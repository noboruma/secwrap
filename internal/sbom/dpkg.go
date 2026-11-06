package sbom

import (
	"bufio"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type dpkgPkg struct {
	Name, Version, Arch, Source, Maintainer string
	distro                                  string
}

func (p *dpkgPkg) purl() string {
	q := url.Values{}
	if p.Arch != "" {
		q.Set("arch", p.Arch)
	}
	if p.distro != "" {
		q.Set("distro", p.distro)
	}
	ns := "debian"
	if id := osRelease()["ID"]; id != "" {
		ns = id
	}
	s := "pkg:deb/" + ns + "/" + p.Name + "@" + url.PathEscape(p.Version)
	if len(q) > 0 {
		s += "?" + q.Encode()
	}
	return s
}

type dpkgDB struct {
	pkgs  map[string]*dpkgPkg // "name:arch" and "name" -> pkg
	once  sync.Once
	files map[string]string // path -> "name:arch" or "name"
}

const dpkgDir = "/var/lib/dpkg"

// dpkg is the dpkg database, loaded once per process: secwrap may build
// many SBOMs in one session.
var dpkg = sync.OnceValue(loadDpkg)

func loadDpkg() *dpkgDB {
	f, err := os.Open(filepath.Join(dpkgDir, "status"))
	if err != nil {
		return nil
	}
	defer f.Close()

	osr := osRelease()
	distro := ""
	if osr["ID"] != "" && osr["VERSION_ID"] != "" {
		distro = osr["ID"] + "-" + osr["VERSION_ID"]
	}

	db := &dpkgDB{pkgs: map[string]*dpkgPkg{}}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	cur := &dpkgPkg{distro: distro}
	installed := false
	flush := func() {
		if cur.Name != "" && installed {
			db.pkgs[cur.Name+":"+cur.Arch] = cur
			db.pkgs[cur.Name] = cur
		}
		cur, installed = &dpkgPkg{distro: distro}, false
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch k {
		case "Package":
			cur.Name = v
		case "Version":
			cur.Version = v
		case "Architecture":
			cur.Arch = v
		case "Source":
			cur.Source = strings.Fields(v)[0]
		case "Maintainer":
			cur.Maintainer = v
		case "Status":
			installed = strings.HasSuffix(v, " installed")
		}
	}
	flush()
	return db
}

// owner returns the package owning path, accounting for /usr-merge.
func (db *dpkgDB) owner(path string) *dpkgPkg {
	db.once.Do(db.indexFiles)
	cands := []string{path}
	if real, err := filepath.EvalSymlinks(path); err == nil && real != path {
		cands = append(cands, real)
	}
	for _, c := range append([]string(nil), cands...) {
		if strings.HasPrefix(c, "/usr/") {
			cands = append(cands, strings.TrimPrefix(c, "/usr"))
		} else {
			cands = append(cands, "/usr"+c)
		}
	}
	for _, c := range cands {
		if key, ok := db.files[c]; ok {
			if p := db.pkgs[key]; p != nil {
				if p.Source == "" {
					p.Source = p.Name
				}
				return p
			}
		}
	}
	return nil
}

func (db *dpkgDB) indexFiles() {
	db.files = map[string]string{}
	lists, _ := filepath.Glob(filepath.Join(dpkgDir, "info", "*.list"))
	for _, l := range lists {
		key := strings.TrimSuffix(filepath.Base(l), ".list")
		f, err := os.Open(l)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			p := sc.Text()
			// Only index shared objects to keep memory small.
			if strings.Contains(p, ".so") {
				db.files[p] = key
			}
		}
		f.Close()
	}
}

var (
	osrOnce sync.Once
	osrMap  map[string]string
)

func osRelease() map[string]string {
	osrOnce.Do(func() {
		osrMap = map[string]string{}
		data, err := os.ReadFile("/etc/os-release")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if ok {
				osrMap[k] = strings.Trim(v, `"`)
			}
		}
	})
	return osrMap
}
