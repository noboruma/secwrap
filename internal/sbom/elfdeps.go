package sbom

import (
	"bufio"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// addSharedLibs resolves DT_NEEDED transitively, the way ld.so would
// (RPATH/RUNPATH with $ORIGIN, ld.so.cache, default dirs), without executing
// the binary (unlike `ldd`, which can run code).
func (b *builder) addSharedLibs(root *Component, binPath string, f *elf.File) error {
	type item struct {
		ref    string // bom-ref of the component that needs these libs
		path   string
		f      *elf.File
		rpaths []string
	}
	rootRPaths := searchPaths(binPath, f, nil)
	queue := []item{{"root", binPath, f, rootRPaths}}
	seen := b.libRefs

	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		needed, err := it.f.ImportedLibraries()
		if err != nil {
			continue
		}
		for _, soname := range needed {
			libPath := resolveLib(soname, it.rpaths, it.f)
			if libPath == "" {
				ref := "unresolved:" + soname
				b.add(it.ref, Component{
					BOMRef: ref, Type: "library", Name: soname,
					Properties: []Property{{"secwrap:elf:soname", soname}, {"secwrap:resolved", "false"}},
				})
				continue
			}
			if ref, ok := seen[libPath]; ok {
				if ref != it.ref {
					b.link(it.ref, ref)
				}
				continue
			}

			ref := b.libComponent(soname, libPath)
			seen[libPath] = ref
			if ref != it.ref {
				b.link(it.ref, ref)
			}

			lf, err := elf.Open(libPath)
			if err != nil {
				continue
			}
			defer lf.Close()
			// Per ld.so: a library's DT_RPATH also applies to its deps only if
			// it has no RUNPATH; executable RPATH is inherited. Approximate by
			// combining the library's own paths with the root's.
			queue = append(queue, item{ref, libPath, lf, searchPaths(libPath, lf, rootRPaths)})
		}
	}
	return nil
}

// libComponent returns the bom-ref for the library: its owning package if
// known (several .so files may share one package), otherwise the file.
func (b *builder) libComponent(soname, libPath string) string {
	if b.pkgs != nil {
		if p := b.pkgs.owner(libPath); p != nil {
			ref := p.purl()
			if b.refs[ref] {
				// Append this file as another occurrence.
				for i := range b.components {
					if b.components[i].BOMRef == ref {
						b.components[i].Evidence.Occurrences = append(b.components[i].Evidence.Occurrences, Occurrence{libPath})
					}
				}
				return ref
			}
			c := Component{
				BOMRef: ref, Type: "library", Name: p.Name, Version: p.Version, PURL: ref,
				Evidence: &Evidence{Occurrences: []Occurrence{{libPath}}},
				Properties: []Property{
					{"secwrap:dpkg:source", p.Source},
					{"secwrap:elf:soname", soname},
				},
			}
			if p.Maintainer != "" {
				c.Supplier = &Entity{Name: p.Maintainer}
			}
			b.refs[ref] = true
			b.components = append(b.components, c)
			return ref
		}
	}
	ref := "file:" + libPath
	if !b.refs[ref] {
		c := Component{
			BOMRef: ref, Type: "library", Name: soname,
			Evidence:   &Evidence{Occurrences: []Occurrence{{libPath}}},
			Properties: []Property{{"secwrap:elf:soname", soname}},
		}
		if s256, _, err := hashFile(libPath); err == nil {
			c.Hashes = []Hash{{"SHA-256", s256}}
		}
		b.refs[ref] = true
		b.components = append(b.components, c)
	}
	return ref
}

func dynStrings(f *elf.File, tag elf.DynTag) []string {
	v, err := f.DynString(tag)
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range v {
		out = append(out, strings.Split(s, ":")...)
	}
	return out
}

func searchPaths(objPath string, f *elf.File, inherited []string) []string {
	origin := filepath.Dir(objPath)
	expand := func(p string) string {
		p = strings.ReplaceAll(p, "${ORIGIN}", origin)
		return strings.ReplaceAll(p, "$ORIGIN", origin)
	}
	var out []string
	runpath := dynStrings(f, elf.DT_RUNPATH)
	if len(runpath) == 0 {
		for _, p := range dynStrings(f, elf.DT_RPATH) {
			out = append(out, expand(p))
		}
		out = append(out, inherited...)
	}
	for _, p := range runpath {
		out = append(out, expand(p))
	}
	return out
}

func resolveLib(soname string, rpaths []string, from *elf.File) string {
	if strings.Contains(soname, "/") {
		if fileExists(soname) {
			return soname
		}
		return ""
	}
	try := func(dir string) string {
		p := filepath.Join(dir, soname)
		if compatible(p, from) {
			return p
		}
		return ""
	}
	for _, d := range rpaths {
		if p := try(d); p != "" {
			return p
		}
	}
	for _, p := range ldCache()[soname] {
		if compatible(p, from) {
			return p
		}
	}
	dirs := []string{"/lib64", "/usr/lib64", "/lib32", "/usr/lib32", "/lib", "/usr/lib"}
	for _, triplet := range multiarchTriplets { // try only returns a compatible ELF
		dirs = append(dirs, "/lib/"+triplet, "/usr/lib/"+triplet)
	}
	for _, d := range dirs {
		if p := try(d); p != "" {
			return p
		}
	}
	return ""
}

// compatible reports whether path is an ELF of the same class and machine.
func compatible(path string, from *elf.File) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return f.Class == from.Class && f.Machine == from.Machine
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

var (
	ldCacheOnce sync.Once
	ldCacheMap  map[string][]string
)

// ldCache parses `ldconfig -p`. This only reads /etc/ld.so.cache; it does not
// run the target binary.
func ldCache() map[string][]string {
	ldCacheOnce.Do(func() {
		ldCacheMap = map[string][]string{}
		bin := "/sbin/ldconfig"
		if !fileExists(bin) {
			bin = "ldconfig"
		}
		out, err := exec.Command(bin, "-p").Output()
		if err != nil {
			return
		}
		sc := bufio.NewScanner(strings.NewReader(string(out)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			name, rest, ok := strings.Cut(line, " (")
			if !ok {
				continue
			}
			_, path, ok := strings.Cut(rest, "=> ")
			if !ok {
				continue
			}
			ldCacheMap[name] = append(ldCacheMap[name], strings.TrimSpace(path))
		}
	})
	return ldCacheMap
}

// multiarchTriplets are Debian's library directories under /lib and /usr/lib.
var multiarchTriplets = []string{
	"x86_64-linux-gnu", "i386-linux-gnu", "aarch64-linux-gnu",
	"arm-linux-gnueabihf", "arm-linux-gnueabi",
	"mips-linux-gnu", "mipsel-linux-gnu", "mips64el-linux-gnuabi64", "mips64-linux-gnuabi64",
	"riscv64-linux-gnu", "powerpc64le-linux-gnu", "s390x-linux-gnu", "loongarch64-linux-gnu",
}
