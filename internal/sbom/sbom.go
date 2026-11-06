// Package sbom builds a CycloneDX SBOM from a compiled binary.
//
// Sources of truth, in order:
//   - Go binaries: embedded build info (debug/buildinfo) -> exact module versions.
//   - Rust binaries built with cargo-auditable: the .dep-v0 section.
//   - Any ELF: DT_NEEDED shared libraries, resolved transitively and mapped to
//     the owning dpkg package when available.
package sbom

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const ToolName = "secwrap"

var ToolVersion = "0.1.0"

// Generate statically analyses the binary at path and returns a CycloneDX BOM.
func Generate(path string) (*BOM, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	sha256sum, sha1sum, err := hashFile(abs)
	if err != nil {
		return nil, err
	}

	b := newBuilder()
	root := Component{
		BOMRef:   "root",
		Type:     "application",
		Name:     filepath.Base(abs),
		Hashes:   []Hash{{"SHA-256", sha256sum}, {"SHA-1", sha1sum}},
		Evidence: &Evidence{Occurrences: []Occurrence{{Location: abs}}},
	}

	var props []Property
	ef, elfErr := elf.Open(abs)
	if elfErr == nil {
		defer ef.Close()
		props = append(props,
			Property{"secwrap:elf:machine", ef.Machine.String()},
			Property{"secwrap:elf:type", ef.Type.String()},
		)
		if interp := elfInterp(ef); interp != "" {
			props = append(props, Property{"secwrap:elf:interpreter", interp})
		} else {
			props = append(props, Property{"secwrap:elf:linkage", "static"})
		}
	}

	// Go build info.
	if bi, err := buildinfo.ReadFile(abs); err == nil {
		b.addGo(&root, bi)
		props = append(props, Property{"secwrap:language", "go"})
	}

	// Rust cargo-auditable.
	if ef != nil {
		if found, err := b.addCargoAuditable(&root, ef); err != nil {
			props = append(props, Property{"secwrap:warning", "cargo-auditable: " + err.Error()})
		} else if found {
			props = append(props, Property{"secwrap:language", "rust"})
		}
	}

	// Shared libraries (works for C/C++/anything dynamically linked).
	if ef != nil {
		if err := b.addSharedLibs(&root, abs, ef); err != nil {
			props = append(props, Property{"secwrap:warning", "shared libs: " + err.Error()})
		}
	}

	root.Properties = append(root.Properties, props...)

	bom := &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + uuid4(),
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: &Tools{Components: []Component{{
				Type: "application", Name: ToolName, Version: ToolVersion,
			}}},
			Component: &root,
		},
		Components: b.components,
	}
	// Dependency graph: root first, then everything else.
	bom.Dependencies = append(bom.Dependencies, Dependency{Ref: "root", DependsOn: b.deps["root"]})
	for _, c := range b.components {
		bom.Dependencies = append(bom.Dependencies, Dependency{Ref: c.BOMRef, DependsOn: b.deps[c.BOMRef]})
	}
	if bom.Components == nil {
		bom.Components = []Component{}
	}
	return bom, nil
}

type builder struct {
	components []Component
	refs       map[string]bool
	deps       map[string][]string
	libRefs    map[string]string // resolved library path -> bom-ref
	pkgs       *dpkgDB           // nil when not a dpkg system
}

func newBuilder() *builder {
	return &builder{
		refs:    map[string]bool{},
		deps:    map[string][]string{},
		libRefs: map[string]string{},
		pkgs:    dpkg(),
	}
}

// add registers a component once (by bom-ref) and records parent -> ref.
func (b *builder) add(parent string, c Component) {
	if !b.refs[c.BOMRef] {
		b.refs[c.BOMRef] = true
		b.components = append(b.components, c)
	}
	b.link(parent, c.BOMRef)
}

func (b *builder) link(parent, ref string) {
	for _, r := range b.deps[parent] {
		if r == ref {
			return
		}
	}
	b.deps[parent] = append(b.deps[parent], ref)
}

func (b *builder) addGo(root *Component, bi *buildinfo.BuildInfo) {
	if bi.Main.Path != "" {
		root.Name = bi.Main.Path
		root.Version = bi.Main.Version
		root.PURL = goPURL(bi.Main.Path, bi.Main.Version)
	}
	for _, s := range bi.Settings {
		root.Properties = append(root.Properties, Property{"secwrap:go:build:" + s.Key, s.Value})
	}

	// The standard library is the most common source of Go CVEs.
	goVer := strings.TrimPrefix(bi.GoVersion, "go")
	if i := strings.IndexAny(goVer, " "); i >= 0 {
		goVer = goVer[:i]
	}
	b.add("root", Component{
		BOMRef: "pkg:golang/stdlib@v" + goVer, Type: "library",
		Name: "stdlib", Version: "v" + goVer, PURL: "pkg:golang/stdlib@v" + goVer,
		Properties: []Property{{"secwrap:go:toolchain", bi.GoVersion}},
	})

	for _, m := range bi.Deps {
		mod := m
		var props []Property
		if m.Replace != nil {
			props = append(props, Property{"secwrap:go:replaced", m.Path + "@" + m.Version})
			mod = m.Replace
		}
		if mod.Sum != "" {
			props = append(props, Property{"secwrap:go:sum", mod.Sum})
		}
		purl := goPURL(mod.Path, mod.Version)
		b.add("root", Component{
			BOMRef: purl, Type: "library", Name: mod.Path, Version: mod.Version,
			PURL: purl, Properties: props,
		})
	}
}

func goPURL(path, version string) string {
	// purl spec: namespace/name, lowercase not required for golang.
	if version == "" || version == "(devel)" {
		return "pkg:golang/" + path
	}
	return "pkg:golang/" + path + "@" + version
}

func elfInterp(f *elf.File) string {
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			data, err := io.ReadAll(p.Open())
			if err != nil {
				return ""
			}
			return strings.TrimRight(string(data), "\x00")
		}
	}
	return ""
}

func hashFile(path string) (string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	h256, h1 := sha256.New(), sha1.New()
	if _, err := io.Copy(io.MultiWriter(h256, h1), f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(h256.Sum(nil)), hex.EncodeToString(h1.Sum(nil)), nil
}

func uuid4() string {
	var u [16]byte
	_, _ = rand.Read(u[:])
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:])
}
