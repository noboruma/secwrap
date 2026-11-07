//go:build linux

package monitor

// File access: a BPF LSM file_open program reports every open by the traced
// tree and, in ask mode, enforces the user's answers (see filemon.bpf.c).
// fileScope mirrors the BPF "in scope" rules, so the seccomp supervisor can
// ask about exactly the opens the LSM program would refuse.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	filePathMax = 512 // FPATH_MAX
	maxSens     = 16  // NSENS
	sensMax     = 128 // SENS_MAX

	fileWrite     = 1
	fileCreated   = 2
	fileExec      = 4
	fileSensitive = 8
	fileBlocked   = 16
	fileInScope   = 32
	fileLongPath  = 64
	fileProgram   = 128 // an exec (bprm), not an open

	ruleRead  = 1
	ruleWrite = 2
	ruleExec  = 4
)

// FileEvent is one open(2) of a file by the target.
type FileEvent struct {
	Time      time.Time `json:"time"`
	PID       uint32    `json:"pid"`
	TID       uint32    `json:"tid"`
	UID       uint32    `json:"uid"`
	Comm      string    `json:"comm"`
	Kind      string    `json:"kind"` // open (--filesystem) | exec (--exec)
	Path      string    `json:"path"`
	Write     bool      `json:"write,omitempty"`
	Created   bool      `json:"created,omitempty"`
	Exec      bool      `json:"exec,omitempty"`
	Sensitive bool      `json:"sensitive,omitempty"`
	// InScope: a write or a sensitive read (what ask mode asks about).
	InScope bool `json:"inScope,omitempty"`
	Blocked bool `json:"blocked,omitempty"`
}

// FileAccess aggregates the opens of one path.
type FileAccess struct {
	Path      string    `json:"path"`
	Read      bool      `json:"read,omitempty"`
	Write     bool      `json:"write,omitempty"`
	Created   bool      `json:"created,omitempty"`
	Exec      bool      `json:"exec,omitempty"`
	Sensitive bool      `json:"sensitive,omitempty"`
	InScope   bool      `json:"inScope,omitempty"` // a write or sensitive read (asked about in ask mode)
	Blocked   bool      `json:"blocked,omitempty"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"firstSeen"`
	Comms     []string  `json:"comms"`
}

// fileObjects are the maps shared by the LSM programs (file_open for
// --filesystem/--sbom, bprm_creds_for_exec for --exec).
type fileObjects struct {
	FileEvents  *ebpf.Map `ebpf:"file_events"`
	FileRules   *ebpf.Map `ebpf:"file_rules"`
	DirRules    *ebpf.Map `ebpf:"dir_rules"`
	PathScratch *ebpf.Map `ebpf:"path_scratch"`

	seed1, seed2 uint64 // dir_seed1/2 (secret)
}

func (o *fileObjects) Close() {
	for _, m := range []*ebpf.Map{o.FileEvents, o.FileRules, o.DirRules, o.PathScratch} {
		if m != nil {
			m.Close()
		}
	}
}

func ruleKey(path string) ([filePathMax]byte, error) {
	var k [filePathMax]byte
	if len(path) >= len(k) {
		return k, errors.New("path too long")
	}
	copy(k[:], path)
	return k, nil
}

// allow sets the RULE_* bits of path in the BPF rule map; 0 removes it.
func (o *fileObjects) allow(path string, bits uint8) error {
	k, err := ruleKey(path)
	if err != nil {
		return err
	}
	if bits == 0 {
		if err := o.FileRules.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		return nil
	}
	return o.FileRules.Put(k, bits)
}

// dirHashes mirrors dir_allowed in common.bpf.h.
func (o *fileObjects) dirHashes(dir string) (h1, h2 uint64) {
	const p1, p2 = 0x100000001b3, 0x9e3779b97f4a7c15
	h1, h2 = o.seed1, o.seed2
	for i := 0; i < len(dir); i++ {
		c := uint64(dir[i])
		h1 = (h1 ^ c) * p1
		h2 = (h2 ^ c) * p2
		h2 ^= h2 >> 31
	}
	return h1, h2
}

// allowDir sets the RULE_* bits for everything below dir (and dir itself);
// 0 removes the folder rule.
func (o *fileObjects) allowDir(dir string, bits uint8) error {
	if len(dir) >= filePathMax {
		return errors.New("path too long")
	}
	h1, h2 := o.dirHashes(dir)
	type key struct {
		H1  uint64
		Len uint32
		_   uint32
	}
	type val struct {
		H2   uint64
		Bits uint32
		_    uint32
	}
	k := key{H1: h1, Len: uint32(len(dir))}
	if bits == 0 {
		if err := o.DirRules.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		return nil
	}
	return o.DirRules.Put(k, val{H2: h2, Bits: uint32(bits)})
}

// FolderRule allows reads, writes and/or execs below Dir without asking.
type FolderRule struct {
	Dir  string
	Bits uint8 // ruleRead | ruleWrite | ruleExec
}

// ParseFolderRule parses --allow values: "r:DIR", "w:DIR", "x:DIR" or a
// combination ("rw:DIR"). A leading "~/" is the invoking user's home (the
// shell does not expand it after "r:").
func ParseFolderRule(s, home string) (FolderRule, error) {
	modes, dir, ok := strings.Cut(s, ":")
	if !ok || modes == "" || dir == "" {
		return FolderRule{}, fmt.Errorf("--allow %q: want r|w|x:DIR, e.g. r:~/.oh-my-zsh or rw:./build", s)
	}
	var r FolderRule
	for _, m := range modes {
		switch m {
		case 'r':
			r.Bits |= ruleRead
		case 'w':
			r.Bits |= ruleWrite
		case 'x':
			r.Bits |= ruleExec
		default:
			return FolderRule{}, fmt.Errorf("--allow %q: unknown mode %q (want r, w and/or x)", s, m)
		}
	}
	if rest, ok := strings.CutPrefix(dir, "~/"); ok {
		dir = filepath.Join(home, rest)
	}
	d, err := CleanDir(dir)
	if err != nil {
		return FolderRule{}, err
	}
	r.Dir = d
	return r, nil
}

// presetDirs adds the --allow folder rules.
func (o *fileObjects) presetDirs(rules []FolderRule) (map[string]uint8, error) {
	out := map[string]uint8{}
	for _, r := range rules {
		if err := o.allowDir(r.Dir, out[r.Dir]|r.Bits); err != nil {
			return nil, fmt.Errorf("allow folder %s: %w", r.Dir, err)
		}
		out[r.Dir] |= r.Bits
	}
	return out, nil
}

// BPFLSMEnabled reports whether the BPF LSM is active on this kernel and
// can run on its architecture.
func BPFLSMEnabled() bool {
	return lsmArchSupported() && bpfInLSMList()
}

// lsmArchSupported: BPF LSM programs attach through BPF trampolines, which
// only some architectures' JITs implement (not 32-bit x86, arm or mips).
func lsmArchSupported() bool {
	m, err := unameMachine()
	if err != nil {
		return false
	}
	switch m {
	case "x86_64", "aarch64", "arm64", "riscv64", "s390x", "loongarch64", "ppc64", "ppc64le":
		return true
	}
	return false
}

func bpfInLSMList() bool {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if l == "bpf" {
			return true
		}
	}
	return false
}

// lsmConfig says which LSM programs to attach and what they enforce.
type lsmConfig struct {
	opens        bool // file_open: --filesystem, --sbom
	logAll       bool // report every open (--filesystem), not only execs (--sbom)
	enforceFiles bool // --filesystem with --deny/--ask
	exec         bool // bprm_creds_for_exec: --exec
	enforceExec  bool // --exec with --deny/--ask
}

// setupLSM loads the shared maps, then each LSM program on its own, so a
// program this kernel rejects does not take the others down.
func setupLSM(spec *ebpf.CollectionSpec, tracked *ebpf.Map, scope *fileScope, c lsmConfig, cleanup *closers) (*fileObjects, error) {
	if !lsmArchSupported() {
		m, _ := unameMachine()
		return nil, fmt.Errorf("--filesystem, --exec and --sbom need BPF LSM programs, which %s kernels can't run (no BPF trampolines); only --net works here", m)
	}
	if !bpfInLSMList() {
		return nil, errors.New(`--filesystem, --exec and --sbom need the BPF LSM: "bpf" is not in /sys/kernel/security/lsm (add lsm=...,bpf to the kernel command line)`)
	}
	var (
		count uint32
		lens  [maxSens]uint32
		dirs  [maxSens]uint8
		paths [maxSens][sensMax]byte
	)
	for i, p := range scope.sens {
		count++
		lens[i] = uint32(len(p.path))
		if p.dir {
			dirs[i] = 1
		}
		copy(paths[i][:], p.path)
	}
	var seeds [16]byte
	if _, err := rand.Read(seeds[:]); err != nil {
		return nil, err
	}
	objs := &fileObjects{
		seed1: binary.NativeEndian.Uint64(seeds[:8]),
		seed2: binary.NativeEndian.Uint64(seeds[8:]),
	}
	vars := map[string]any{
		"sens_count": count, "sens_len": lens, "sens_dir": dirs, "sens_path": paths,
		"file_enforce": boolByte(c.enforceFiles), "file_log_all": boolByte(c.logAll),
		"exec_enforce": boolByte(c.enforceExec), "dir_seed1": objs.seed1, "dir_seed2": objs.seed2,
	}
	for name, v := range vars {
		if err := spec.Variables[name].Set(v); err != nil {
			return nil, fmt.Errorf("set %s: %w", name, err)
		}
	}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, fmt.Errorf("load LSM maps: %w", err)
	}
	cleanup.add(objs.Close)

	opts := &ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{
		"tracked": tracked, "file_events": objs.FileEvents, "file_rules": objs.FileRules,
		"dir_rules": objs.DirRules, "path_scratch": objs.PathScratch,
	}}
	attach := func(hook string, prog **ebpf.Program, load func() error) error {
		if err := load(); err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				return fmt.Errorf("lsm/%s rejected by the verifier: %+v", hook, ve)
			}
			return fmt.Errorf("load lsm/%s: %w", hook, err)
		}
		cleanup.add(func() { (*prog).Close() })
		l, err := link.AttachLSM(link.LSMOptions{Program: *prog})
		if err != nil {
			return fmt.Errorf("attach lsm/%s: %w", hook, err)
		}
		cleanup.addLink(l)
		return nil
	}
	if c.opens {
		var p struct {
			P *ebpf.Program `ebpf:"vc_file_open"`
		}
		if err := attach("file_open", &p.P, func() error { return spec.LoadAndAssign(&p, opts) }); err != nil {
			return nil, err
		}
	}
	if c.exec {
		var p struct {
			P *ebpf.Program `ebpf:"vc_bprm_exec"`
		}
		if err := attach("bprm_creds_for_exec", &p.P, func() error { return spec.LoadAndAssign(&p, opts) }); err != nil {
			return nil, err
		}
	}
	return objs, nil
}

func boolByte(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// readFileEvents decodes file_events until the reader is closed.
func readFileEvents(rd *ringbuf.Reader, wallOffset time.Time, emit func(FileEvent)) {
	var raw secwrapFileEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			return
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &raw); err != nil {
			continue
		}
		f := raw.Flags
		emit(FileEvent{
			Time: wallOffset.Add(time.Duration(raw.TsNs)), PID: raw.Tgid, TID: raw.Pid, UID: raw.Uid,
			Comm: cString(raw.Comm[:]), Kind: kind(f), Path: fileEventPath(&raw),
			Write: f&fileWrite != 0, Created: f&fileCreated != 0, Exec: f&fileExec != 0,
			Sensitive: f&fileSensitive != 0, InScope: f&fileInScope != 0, Blocked: f&fileBlocked != 0,
		})
	}
}

func kind(flags uint32) string {
	if flags&fileProgram != 0 {
		return "exec"
	}
	return "open"
}

func fileEventPath(r *secwrapFileEvent) string {
	if r.Flags&fileLongPath != 0 {
		return "(path too long)"
	}
	return cString(r.Path[:])
}

// ---------------------------------------------------------------------------
// Scope (must match path_excluded / path_sensitive in filemon.bpf.c)

type sensPath struct {
	path string
	dir  bool // also everything below
}

type fileScope struct {
	sens []sensPath
}

// newFileScope builds the sensitive path list: the invoking user's home,
// /root, password/sudo/ssh config, plus extra (a trailing "/" or an existing
// directory means "and everything below").
func newFileScope(extra []string, home string) (*fileScope, error) {
	s := &fileScope{}
	add := func(p string, dir bool) error {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r // the kernel reports resolved paths
		}
		p = filepath.Clean(p)
		if !filepath.IsAbs(p) || p == "/" {
			return fmt.Errorf("sensitive path %q must be absolute and not /", p)
		}
		if len(p) >= sensMax {
			return fmt.Errorf("sensitive path %q is too long (max %d)", p, sensMax-1)
		}
		for _, e := range s.sens {
			if e.path == p {
				return nil
			}
		}
		if len(s.sens) == maxSens {
			return fmt.Errorf("at most %d sensitive paths", maxSens)
		}
		s.sens = append(s.sens, sensPath{p, dir})
		return nil
	}
	if home != "" && home != "/" {
		if err := add(home, true); err != nil {
			return nil, err
		}
	}
	defaults := []sensPath{
		{"/root", true}, {"/etc/shadow", false}, {"/etc/gshadow", false},
		{"/etc/sudoers", false}, {"/etc/sudoers.d", true}, {"/etc/ssh", true},
	}
	for _, d := range defaults {
		if err := add(d.path, d.dir); err != nil {
			return nil, err
		}
	}
	for _, p := range extra {
		dir := strings.HasSuffix(p, "/")
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			dir = true
		}
		if err := add(p, dir); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// CleanDir validates a folder for a folder rule: absolute, symlinks
// resolved (the kernel reports resolved paths), and not "/".
func CleanDir(dir string) (string, error) {
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) || dir == "/" {
		return "", fmt.Errorf("folder %q must be absolute and not /", dir)
	}
	if len(dir) >= filePathMax {
		return "", fmt.Errorf("folder %q is too long", dir)
	}
	return dir, nil
}

// Ancestors returns the folders a folder rule for path could use, nearest
// first: its parent up to the top-level directory ("/" is never offered).
func Ancestors(path string) []string {
	var out []string
	for d := filepath.Dir(path); d != "/" && d != "."; d = filepath.Dir(d) {
		out = append(out, d)
	}
	return out
}

// Paths returns the sensitive paths, for display.
func (s *fileScope) Paths() []string {
	out := make([]string, len(s.sens))
	for i, e := range s.sens {
		out[i] = e.path
		if e.dir {
			out[i] += "/"
		}
	}
	return out
}

func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
}

func (s *fileScope) excluded(p string) bool {
	return !strings.HasPrefix(p, "/") || under(p, "/proc") || under(p, "/sys") || under(p, "/dev")
}

func (s *fileScope) sensitive(p string) bool {
	for _, e := range s.sens {
		if p == e.path || (e.dir && strings.HasPrefix(p, e.path+"/")) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Aggregation

type fileAggregator struct {
	mu sync.Mutex
	m  map[string]*FileAccess
}

func newFileAggregator() *fileAggregator { return &fileAggregator{m: map[string]*FileAccess{}} }

func (a *fileAggregator) add(ev FileEvent) {
	key := ev.Path + "|" + strconv.FormatBool(ev.Blocked)
	a.mu.Lock()
	defer a.mu.Unlock()
	fa, ok := a.m[key]
	if !ok {
		fa = &FileAccess{Path: ev.Path, Blocked: ev.Blocked, FirstSeen: ev.Time}
		a.m[key] = fa
	}
	fa.Count++
	fa.Read = fa.Read || (!ev.Write && !ev.Exec)
	fa.Write = fa.Write || ev.Write
	fa.Created = fa.Created || ev.Created
	fa.Exec = fa.Exec || ev.Exec
	fa.Sensitive = fa.Sensitive || ev.Sensitive
	fa.InScope = fa.InScope || ev.InScope
	if !contains(fa.Comms, ev.Comm) {
		fa.Comms = append(fa.Comms, ev.Comm)
	}
}

func (a *fileAggregator) files() []FileAccess {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]FileAccess, 0, len(a.m))
	for _, fa := range a.m {
		out = append(out, *fa)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstSeen.Before(out[j].FirstSeen) })
	return out
}
