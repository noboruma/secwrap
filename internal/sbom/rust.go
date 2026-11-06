package sbom

import (
	"compress/zlib"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
)

// cargo-auditable embeds zlib-compressed JSON in the ".dep-v0" section.
// https://github.com/rust-secure-code/cargo-auditable
type auditableDeps struct {
	Packages []struct {
		Name         string `json:"name"`
		Version      string `json:"version"`
		Source       string `json:"source"`
		Kind         string `json:"kind"`
		Dependencies []int  `json:"dependencies"`
		Root         bool   `json:"root"`
	} `json:"packages"`
}

func (b *builder) addCargoAuditable(root *Component, f *elf.File) (bool, error) {
	sec := f.Section(".dep-v0")
	if sec == nil {
		return false, nil
	}
	zr, err := zlib.NewReader(sec.Open())
	if err != nil {
		return false, err
	}
	defer zr.Close()
	var deps auditableDeps
	if err := json.NewDecoder(io.LimitReader(zr, 64<<20)).Decode(&deps); err != nil {
		return false, err
	}

	refs := make([]string, len(deps.Packages))
	for i, p := range deps.Packages {
		purl := fmt.Sprintf("pkg:cargo/%s@%s", p.Name, p.Version)
		if p.Root {
			refs[i] = "root"
			root.Name, root.Version, root.PURL = p.Name, p.Version, purl
			continue
		}
		refs[i] = purl
	}
	for i, p := range deps.Packages {
		if p.Root {
			continue
		}
		props := []Property{{"secwrap:cargo:source", p.Source}}
		if p.Kind != "" && p.Kind != "runtime" {
			props = append(props, Property{"secwrap:cargo:kind", p.Kind})
		}
		c := Component{BOMRef: refs[i], Type: "library", Name: p.Name, Version: p.Version, PURL: refs[i], Properties: props}
		if !b.refs[c.BOMRef] {
			b.refs[c.BOMRef] = true
			b.components = append(b.components, c)
		}
	}
	for i, p := range deps.Packages {
		for _, d := range p.Dependencies {
			if d >= 0 && d < len(refs) {
				b.link(refs[i], refs[d])
			}
		}
	}
	return true, nil
}
