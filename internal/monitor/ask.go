//go:build linux

package monitor

// Ask mode: deny mode plus an interactive "breakpoint" on outbound network
// syscalls. The target gets a seccomp filter that turns connect, sendto,
// sendmsg and sendmmsg into SECCOMP_RET_USER_NOTIF. The calling thread stays
// blocked in the kernel until we answer, so we can ask the user first:
//
//   - allow: the peer goes into the BPF allow map, and the syscall continues
//   - deny:  the syscall fails with EPERM
//
// seccomp only pauses the call. The cgroup BPF hooks (deny.go) still enforce
// the decision on the address the kernel copied. A thread that rewrites the
// sockaddr after we read it (TOCTOU), io_uring, or 32-bit/x32 syscalls get no
// prompt, but they still cannot reach a peer that was not allowed.
//
// With files enabled, open/openat/openat2/creat are trapped too. We resolve
// the path like the kernel will and ask about writes and sensitive reads
// (fileScope). The answer goes into the BPF file_rules map, and the LSM
// file_open program (files.go) enforces it on the file actually opened.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// AskRequest describes a paused syscall waiting for a decision: a network
// request (Remote set) or a file open (Path set).
type AskRequest struct {
	PID, TID int
	Comm     string
	Kind     string // connect | udp_send | send | open | exec
	Proto    string // tcp | udp | "" if unknown (network only)
	Remote   netip.AddrPort

	Path      string   // open, exec: resolved absolute path
	Write     bool     // open: for write/create/truncate
	Sensitive bool     // open: under a sensitive path
	Args      []string // exec: the command line (argv), possibly truncated

	// Forget, set by the supervisor, undoes the answer to this request once
	// given (a deny, an allow, or the folder rule it created), so the next
	// such call asks again. Calls and files already let through stay so.
	Forget func() error
}

// IsFile reports whether r is about a file (an open or an exec).
func (r AskRequest) IsFile() bool { return r.Path != "" }

// IsExec reports whether r is about a program about to be executed.
func (r AskRequest) IsExec() bool { return r.Kind == "exec" }

// AskDecision is the user's answer. It is remembered for the rest of the
// session, so the same peer or file is not asked about twice. For files,
// the Host variants mean the same as the Endpoint ones.
type AskDecision int

const (
	DenyEndpoint  AskDecision = iota // deny this ip:port
	DenyHost                         // deny every port on this ip
	AllowEndpoint                    // allow this ip:port
	AllowHost                        // allow every port on this ip
)

// AskAnswer is returned by the Ask callback.
type AskAnswer struct {
	Decision AskDecision
	// Dir, for an allowed file request: allow the same access (read, or
	// write) for everything under Dir instead of just this file. It must be
	// an ancestor of the path, and not "/". See Ancestors.
	Dir string
}

// Answer is an AskAnswer without a folder.
func Answer(d AskDecision) AskAnswer { return AskAnswer{Decision: d} }

// ErrCoveredByRule is the context cause given to an Ask call whose question
// was answered meanwhile by a folder rule from another answer. The Ask
// callback should withdraw the question; its return value is ignored.
var ErrCoveredByRule = errors.New("answered by a folder rule")

type peerRule struct {
	addr netip.Addr
	port uint16 // 0 = any port
}

// pendingAnswer lets concurrent calls to the same peer share one question.
type pendingAnswer struct {
	done      chan struct{}
	allowed   bool
	cancelled bool // the asking task went away: waiters must ask again
}

// askConfig is what the supervisor needs from the monitoring session.
type askConfig struct {
	ask       func(context.Context, AskRequest) AskAnswer
	emit      func(Event)
	emitFile  func(FileEvent)
	deny      *denyCgroup
	files     fileRuleSink // nil: no LSM rules (no --filesystem/--exec)
	scope     *fileScope
	dirAllow  map[string]uint8 // preset folder rules (already in BPF)
	fileAllow map[string]uint8 // preset file rules (the launched command)

	net, opens, execs bool // which categories are asked about
}

// fileRuleSink stores file decisions where the LSM program enforces them
// (*fileObjects).
type fileRuleSink interface {
	allow(path string, bits uint8) error   // exact bits; 0 removes
	allowDir(dir string, bits uint8) error // exact bits; 0 removes
}

// pendingQ is a question being asked, so a new folder rule can answer it.
type pendingQ struct {
	lookup func() (allowed, known bool)
	cancel context.CancelCauseFunc
}

type supervisor struct {
	askConfig
	lfd int

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu        sync.Mutex
	rules     map[peerRule]bool // true = allowed
	fileAllow map[string]uint8  // path -> ruleRead|ruleWrite allowed
	fileDeny  map[string]uint8  // path -> ruleRead|ruleWrite denied
	dirAllow  map[string]uint8  // folder -> ruleRead|ruleWrite allowed below it
	inflight  map[string]*pendingAnswer
	asking    map[*pendingQ]struct{}
}

// superviseAsk answers seccomp notifications until the target tree is gone
// or stop is called. Each notification is handled in its own goroutine, so
// several paused calls can wait for an answer at once. It owns lfd.
func superviseAsk(lfd int, cfg askConfig) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &supervisor{
		askConfig: cfg, lfd: lfd, ctx: ctx, cancel: cancel,
		rules: map[peerRule]bool{}, fileAllow: map[string]uint8{}, fileDeny: map[string]uint8{},
		dirAllow: map[string]uint8{}, inflight: map[string]*pendingAnswer{}, asking: map[*pendingQ]struct{}{},
	}
	for d, b := range cfg.dirAllow {
		s.dirAllow[d] = b
	}
	for p, b := range cfg.fileAllow {
		s.fileAllow[p] = b
	}
	go s.loop()
	return cancel
}

func (s *supervisor) loop() {
	defer func() {
		s.cancel()  // pending questions are void now
		s.wg.Wait() // handlers still use lfd
		unix.Close(s.lfd)
	}()
	for s.ctx.Err() == nil {
		pfd := []unix.PollFd{{Fd: int32(s.lfd), Events: unix.POLLIN}}
		n, err := unix.Poll(pfd, 250)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		if n == 0 {
			continue
		}
		if pfd[0].Revents&unix.POLLIN == 0 && pfd[0].Revents&(unix.POLLHUP|unix.POLLERR) != 0 {
			return // no task uses the filter any more
		}
		req := new(seccompNotif) // must be zeroed for RECV
		if err := ioctlPtr(s.lfd, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(req)); err != nil {
			continue // ENOENT: the task died before we got it
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			resp := s.handle(req)
			_ = ioctlPtr(s.lfd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&resp))
		}()
	}
}

func (s *supervisor) idValid(id uint64) bool {
	return ioctlPtr(s.lfd, unix.SECCOMP_IOCTL_NOTIF_ID_VALID, unsafe.Pointer(&id)) == nil
}

// taskContext is cancelled when the paused task is gone (killed, timed out)
// or the session ends, so its question can be withdrawn.
func (s *supervisor) taskContext(id uint64) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(s.ctx)
	go func() {
		t := time.NewTicker(300 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if !s.idValid(id) {
					cancel()
					return
				}
			}
		}
	}()
	return ctx, cancel
}

func (s *supervisor) handle(req *seccompNotif) seccompNotifResp {
	switch int(req.Data.Nr) {
	case unix.SYS_OPEN, unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_CREAT:
		return s.handleOpen(req)
	case unix.SYS_EXECVE, unix.SYS_EXECVEAT:
		return s.handleExec(req)
	}
	return s.handleNet(req)
}

func (s *supervisor) handleNet(req *seccompNotif) seccompNotifResp {
	cont := seccompNotifResp{ID: req.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
	tid := int(req.PID)
	a := req.Data.Args

	var kind string
	var peers []netip.AddrPort
	switch int(req.Data.Nr) {
	case unix.SYS_CONNECT: // connect(fd, addr, len)
		kind = "connect"
		peers = appendPeer(peers, tid, a[1], a[2])
	case unix.SYS_SENDTO: // sendto(fd, buf, len, flags, addr, alen)
		kind = "send"
		peers = appendPeer(peers, tid, a[4], a[5])
	case unix.SYS_SENDMSG: // sendmsg(fd, msghdr*, flags)
		kind = "send"
		peers = appendMsgPeer(peers, tid, a[1])
	case unix.SYS_SENDMMSG: // sendmmsg(fd, mmsghdr*, vlen, flags)
		kind = "send"
		const mmsghdrSize = 64 // struct msghdr (56) + msg_len + padding
		for i := uint64(0); i < min(a[2], 64); i++ {
			peers = appendMsgPeer(peers, tid, a[1]+i*mmsghdrSize)
		}
	}
	// No inet destination (unix/netlink socket, connected UDP, bad pointer):
	// nothing to ask. The cgroup hooks still apply.
	if len(peers) == 0 {
		return cont
	}
	// The memory we read is only meaningful if the task is still waiting.
	if !s.idValid(req.ID) {
		return cont
	}

	proto := sockProto(tid, int(a[0]))
	if kind == "send" && proto == "udp" {
		kind = "udp_send"
	}
	comm := readComm(tid)
	tgid := tgidOf(tid)

	ctx, cancel := s.taskContext(req.ID)
	defer cancel()
	denied := false
	for _, p := range peers {
		r := AskRequest{PID: tgid, TID: tid, Comm: comm, Kind: kind, Proto: proto, Remote: p}
		lookup := func() (bool, bool) { return s.lookupLocked(p) }
		var rule peerRule
		var allowed, done bool
		record := func(a AskAnswer) bool {
			rule, allowed = s.recordLocked(p, a.Decision)
			done = true
			return allowed
		}
		r.Forget = func() error {
			s.mu.Lock()
			defer s.mu.Unlock()
			if !done {
				return nil
			}
			done = false
			delete(s.rules, rule)
			if allowed {
				return s.deny.disallow(rule.addr, rule.port)
			}
			return nil
		}
		if !s.decide(ctx, "net|"+p.String(), r, lookup, record) {
			denied = true
			if ctx.Err() != nil {
				break // task gone or session over: the answer no longer matters
			}
			s.emit(Event{
				Time: time.Now(), PID: uint32(tgid), TID: uint32(tid), Comm: comm,
				Kind: kind, Proto: proto, Direction: Outbound, Remote: p, Blocked: true,
			})
		}
	}
	if denied {
		return seccompNotifResp{ID: req.ID, Error: -int32(unix.EPERM)}
	}
	return cont
}

// decide returns whether the request is allowed, asking the user unless
// lookup (called with s.mu held) already knows, or the same question (key)
// is already open. record (also under s.mu) stores the answer.
func (s *supervisor) decide(ctx context.Context, key string, r AskRequest,
	lookup func() (allowed, known bool), record func(AskAnswer) bool) bool {
	for {
		s.mu.Lock()
		if v, ok := lookup(); ok {
			s.mu.Unlock()
			return v
		}
		if pa, ok := s.inflight[key]; ok {
			s.mu.Unlock()
			select {
			case <-pa.done:
				if pa.cancelled {
					continue // its asker went away; ask on our own behalf
				}
				return pa.allowed
			case <-ctx.Done():
				return false
			}
		}
		pa := &pendingAnswer{done: make(chan struct{})}
		s.inflight[key] = pa
		askCtx, cancelAsk := context.WithCancelCause(ctx)
		q := &pendingQ{lookup: lookup, cancel: cancelAsk}
		s.asking[q] = struct{}{}
		s.mu.Unlock()

		d := s.ask(askCtx, r)

		s.mu.Lock()
		delete(s.asking, q)
		cancelAsk(nil)
		switch {
		case ctx.Err() != nil:
			pa.cancelled = true
		case context.Cause(askCtx) == ErrCoveredByRule:
			pa.allowed, _ = lookup()
		default:
			pa.allowed = record(d)
		}
		delete(s.inflight, key)
		close(pa.done)
		s.mu.Unlock()
		return pa.allowed
	}
}

func (s *supervisor) lookupLocked(p netip.AddrPort) (allowed, known bool) {
	if v, ok := s.rules[peerRule{p.Addr(), p.Port()}]; ok {
		return v, true
	}
	v, ok := s.rules[peerRule{p.Addr(), 0}]
	return v, ok
}

func (s *supervisor) recordLocked(p netip.AddrPort, d AskDecision) (rule peerRule, allowed bool) {
	rule = peerRule{p.Addr(), p.Port()}
	if d == AllowHost || d == DenyHost {
		rule.port = 0
	}
	allowed = d == AllowHost || d == AllowEndpoint
	if allowed {
		if err := s.deny.allow(rule.addr, rule.port); err != nil {
			fmt.Fprintf(os.Stderr, "secwrap: allow %s: %v (it stays blocked)\n", p, err)
			return rule, false
		}
	}
	s.rules[rule] = allowed
	return rule, allowed
}

// handleOpen asks about writes and sensitive reads. Anything we cannot
// resolve or classify continues: the LSM program refuses in-scope opens that
// have no allow rule, so a wrong guess here fails closed.
func (s *supervisor) handleOpen(req *seccompNotif) seccompNotifResp {
	cont := seccompNotifResp{ID: req.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
	if s.files == nil || !s.opens {
		return cont
	}
	tid := int(req.PID)
	a := req.Data.Args

	dirfd := int32(unix.AT_FDCWD)
	var pathPtr, flags uint64
	switch int(req.Data.Nr) {
	case unix.SYS_OPEN: // open(path, flags, mode)
		pathPtr, flags = a[0], a[1]
	case unix.SYS_CREAT: // creat(path, mode)
		pathPtr, flags = a[0], unix.O_CREAT|unix.O_WRONLY|unix.O_TRUNC
	case unix.SYS_OPENAT: // openat(dirfd, path, flags, mode)
		dirfd, pathPtr, flags = int32(a[0]), a[1], a[2]
	case unix.SYS_OPENAT2: // openat2(dirfd, path, struct open_how *, size)
		var how [8]byte // __u64 flags is the first field
		if a[3] < 8 || !readMem(tid, a[2], how[:]) {
			return cont
		}
		dirfd, pathPtr, flags = int32(a[0]), a[1], binary.NativeEndian.Uint64(how[:])
	}
	// O_PATH never reaches file_open; O_TMPFILE files have no name yet.
	if flags&unix.O_PATH != 0 || flags&unix.O_TMPFILE == unix.O_TMPFILE {
		return cont
	}
	write := flags&unix.O_ACCMODE != unix.O_RDONLY || flags&(unix.O_CREAT|unix.O_TRUNC) != 0

	raw, ok := readCString(tid, pathPtr, 4096)
	if !ok {
		return cont
	}
	tgid := tgidOf(tid)
	path, err := resolveOpenPath(tgid, tid, dirfd, raw, flags&unix.O_CREAT != 0)
	if err != nil || len(path) >= filePathMax || s.scope.excluded(path) {
		return cont
	}
	sens := s.scope.sensitive(path)
	if !write && !sens {
		return cont
	}
	if !s.idValid(req.ID) {
		return cont
	}

	need := uint8(ruleRead)
	if write {
		need = ruleWrite
	}
	r := AskRequest{PID: tgid, TID: tid, Comm: readComm(tid), Kind: "open", Path: path, Write: write, Sensitive: sens}
	return s.askFile(req.ID, r, need)
}

// handleExec asks before every program the target executes. The launched
// command is pre-allowed. What can't be resolved continues: the LSM
// bprm_creds_for_exec program refuses it unless an exec rule allows it.
func (s *supervisor) handleExec(req *seccompNotif) seccompNotifResp {
	cont := seccompNotifResp{ID: req.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
	if s.files == nil || !s.execs {
		return cont
	}
	tid := int(req.PID)
	a := req.Data.Args
	dirfd, pathPtr, argvPtr := int32(unix.AT_FDCWD), a[0], a[1] // execve(path, argv, envp)
	if int(req.Data.Nr) == unix.SYS_EXECVEAT {                  // execveat(dirfd, path, argv, envp, flags)
		dirfd, pathPtr, argvPtr = int32(a[0]), a[1], a[2]
	}
	raw, ok := readCString(tid, pathPtr, 4096)
	if !ok {
		return cont
	}
	tgid := tgidOf(tid)
	var path string
	var err error
	if raw == "" && int(req.Data.Nr) == unix.SYS_EXECVEAT && a[4]&unix.AT_EMPTY_PATH != 0 {
		path, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", tgid, dirfd)) // fexecve
	} else {
		path, err = resolveOpenPath(tgid, tid, dirfd, raw, false)
	}
	if err != nil || len(path) >= filePathMax || !s.idValid(req.ID) {
		return cont
	}
	r := AskRequest{PID: tgid, TID: tid, Comm: readComm(tid), Kind: "exec", Path: path, Args: readArgv(tid, argvPtr)}
	return s.askFile(req.ID, r, ruleExec)
}

// askFile decides an open or an exec (need: ruleRead, ruleWrite or
// ruleExec), asking unless a file or folder rule already answers it.
func (s *supervisor) askFile(id uint64, r AskRequest, need uint8) seccompNotifResp {
	path := r.Path
	lookup := func() (bool, bool) {
		if s.fileAllow[path]&need != 0 || s.dirCoversLocked(path, need) {
			return true, true
		}
		return false, s.fileDeny[path]&need != 0
	}
	// What the answer changed, so that Forget can undo it.
	var added uint8 // bits added: to fileAllow[path], to dirAllow[dir], or to fileDeny[path]
	var dir string
	var allowed, done bool
	record := func(a AskAnswer) bool {
		done = true
		if a.Decision != AllowEndpoint && a.Decision != AllowHost {
			added = need
			if need == ruleRead {
				added |= ruleWrite // no read: no write either
			}
			added &^= s.fileDeny[path]
			s.fileDeny[path] |= added
			return false
		}
		if d := filepath.Clean(a.Dir); a.Dir != "" && d != "/" && under(path, d) {
			added = need &^ s.dirAllow[d]
			dir, allowed = d, s.allowDirLocked(d, need)
			return allowed
		}
		added = need
		if need == ruleWrite {
			added |= ruleRead // opened for writing: reading it too
		}
		added &^= s.fileAllow[path]
		if err := s.files.allow(path, s.fileAllow[path]|added); err != nil {
			fmt.Fprintf(os.Stderr, "secwrap: allow %s: %v (it stays blocked)\n", path, err)
			return false
		}
		s.fileAllow[path] |= added
		allowed = true
		return true
	}
	r.Forget = func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !done {
			return nil
		}
		done = false
		switch {
		case !allowed:
			s.fileDeny[path] &^= added
		case dir != "":
			s.dirAllow[dir] &^= added
			return s.files.allowDir(dir, s.dirAllow[dir])
		default:
			s.fileAllow[path] &^= added
			return s.files.allow(path, s.fileAllow[path])
		}
		return nil
	}

	ctx, cancel := s.taskContext(id)
	defer cancel()
	if s.decide(ctx, fmt.Sprintf("file|%d|%s", need, path), r, lookup, record) {
		return seccompNotifResp{ID: id, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
	}
	if ctx.Err() == nil && s.emitFile != nil {
		s.emitFile(FileEvent{
			Time: time.Now(), PID: uint32(r.PID), TID: uint32(r.TID), Comm: r.Comm, Kind: r.Kind, Path: path,
			Write: r.Write, Exec: r.IsExec(), Sensitive: r.Sensitive, InScope: true, Blocked: true,
		})
	}
	return seccompNotifResp{ID: id, Error: -int32(unix.EPERM)}
}

func (s *supervisor) dirCoversLocked(path string, need uint8) bool {
	for d, bits := range s.dirAllow {
		if bits&need != 0 && under(path, d) {
			return true
		}
	}
	return false
}

// allowDirLocked adds a folder rule (only the access in bits: reads and
// writes stay separate) and answers the open questions it covers.
func (s *supervisor) allowDirLocked(dir string, bits uint8) bool {
	if err := s.files.allowDir(dir, s.dirAllow[dir]|bits); err != nil {
		fmt.Fprintf(os.Stderr, "secwrap: allow folder %s: %v\n", dir, err)
		return false
	}
	s.dirAllow[dir] |= bits
	for q := range s.asking {
		if ok, known := q.lookup(); ok && known {
			q.cancel(ErrCoveredByRule)
		}
	}
	return true
}
