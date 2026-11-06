package main

// --sbom DIR: a CycloneDX SBOM for every binary the monitored tree executes,
// built in the background, once per binary, and listed on the web page.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/noboruma/secwrap/internal/monitor"
	"github.com/noboruma/secwrap/internal/sbom"
)

// binary is one executed file. Re-executions of the same path count as one,
// unless the file changed (size, mtime or inode): then it is a new entry.
type binary struct {
	ID         int       `json:"id"`
	Path       string    `json:"path"`
	SHA256     string    `json:"sha256,omitempty"`
	FirstSeen  time.Time `json:"firstSeen"`
	PID        uint32    `json:"pid"`  // first process that ran it
	Comm       string    `json:"comm"` // its name
	Execs      int       `json:"execs"`
	Status     string    `json:"status"`         // pending | done | error
	File       string    `json:"file,omitempty"` // SBOM file name in the directory
	Components int       `json:"components"`
	Language   string    `json:"language,omitempty"`
	Error      string    `json:"error,omitempty"`

	stamp fileStamp
}

type fileStamp struct {
	size  int64
	mtime time.Time
	ino   uint64
}

type sbomStore struct {
	dir  string
	root *os.Root // dir: writes stay inside it whatever is renamed or linked

	mu      sync.Mutex
	list    []*binary
	byPath  map[string]*binary // latest entry for each path
	closing bool               // no new entries: the queue is closed

	queue     chan *binary
	done      chan struct{}
	closeOnce sync.Once
}

func newSBOMStore(dir string) (*sbomStore, error) {
	_, statErr := os.Stat(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("--sbom: %w", err)
	}
	if os.IsNotExist(statErr) { // created by us, under sudo: give it to the user
		chownPathToInvoker(dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("--sbom: %w", err)
	}
	st := &sbomStore{dir: dir, root: root, byPath: map[string]*binary{}, queue: make(chan *binary, 4096), done: make(chan struct{})}
	go st.worker()
	return st, nil
}

// onExec is monitor.Options.OnBinary: it must not block.
func (st *sbomStore) onExec(e monitor.FileEvent) {
	stamp, ok := statStamp(e.Path)
	st.mu.Lock()
	defer st.mu.Unlock()
	if b := st.byPath[e.Path]; b != nil && (!ok || b.stamp == stamp) {
		b.Execs++
		return
	}
	if st.closing {
		return
	}
	b := &binary{ID: len(st.list) + 1, Path: e.Path, FirstSeen: e.Time, PID: e.PID, Comm: e.Comm,
		Execs: 1, Status: "pending", stamp: stamp}
	st.list = append(st.list, b)
	st.byPath[e.Path] = b
	select {
	case st.queue <- b:
	default:
		b.Status, b.Error = "error", "queue full"
	}
}

func (st *sbomStore) worker() {
	defer close(st.done)
	for b := range st.queue {
		st.generate(b)
	}
}

func (st *sbomStore) generate(b *binary) {
	set := func(f func()) {
		st.mu.Lock()
		f()
		st.mu.Unlock()
		st.writeIndex()
	}
	bom, err := sbom.Generate(b.Path)
	if err != nil {
		set(func() { b.Status, b.Error = "error", err.Error() })
		return
	}
	root := bom.Metadata.Component
	sha := ""
	for _, h := range root.Hashes {
		if h.Alg == "SHA-256" {
			sha = h.Content
		}
	}
	lang := ""
	for _, p := range root.Properties {
		if p.Name == "secwrap:language" {
			lang = p.Value
		}
	}

	// Same content seen before (hard link, rebuilt and reverted, ...):
	// reuse its SBOM file.
	st.mu.Lock()
	var same *binary
	for _, o := range st.list {
		if o != b && o.SHA256 == sha && o.File != "" {
			same = o
		}
	}
	st.mu.Unlock()
	name := ""
	if same != nil {
		name = same.File
	} else {
		name = fmt.Sprintf("%s-%s.cdx.json", safeName(filepath.Base(b.Path)), sha[:min(12, len(sha))])
		if err := writeJSONIn(st.root, name, bom); err != nil {
			set(func() { b.Status, b.Error = "error", err.Error() })
			return
		}
	}
	set(func() {
		b.Status, b.File, b.SHA256, b.Components, b.Language = "done", name, sha, len(bom.Components), lang
	})
}

// close waits for the queued SBOMs, then writes the final index. Later
// calls do nothing.
func (st *sbomStore) close() { st.closeOnce.Do(st.drain) }

func (st *sbomStore) drain() {
	st.mu.Lock()
	pending := 0
	for _, b := range st.list {
		if b.Status == "pending" {
			pending++
		}
	}
	st.closing = true
	st.mu.Unlock()
	if pending > 0 {
		fmt.Fprintf(os.Stderr, "secwrap: finishing %d SBOM(s)...\n", pending)
	}
	close(st.queue)
	<-st.done
	st.writeIndex()
}

// snapshot returns a copy of the list, newest first.
func (st *sbomStore) snapshot() []binary {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]binary, len(st.list))
	for i, b := range st.list {
		out[len(out)-1-i] = *b
	}
	return out
}

// get returns the binary with id, if its SBOM is ready.
func (st *sbomStore) get(id int) (binary, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if id < 1 || id > len(st.list) || st.list[id-1].File == "" {
		return binary{}, false
	}
	return *st.list[id-1], true
}

// writeIndex rewrites DIR/index.json (oldest first), atomically.
func (st *sbomStore) writeIndex() {
	list := st.snapshot()
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}
	if err := writeFileAtomic(st.root, "index.json", list, 0o644); err == nil {
		chownInvokerIn(st.root, "index.json")
	}
}

func statStamp(path string) (fileStamp, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, false
	}
	s := fileStamp{size: fi.Size(), mtime: fi.ModTime()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		s.ino = st.Ino
	}
	return s, true
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9._+-]`)

func safeName(s string) string { return unsafeChars.ReplaceAllString(s, "_") }
