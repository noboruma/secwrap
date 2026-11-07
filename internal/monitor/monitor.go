//go:build linux

// Package monitor observes the network activity of a process tree with eBPF.
package monitor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Direction of a connection relative to the monitored process.
type Direction string

const (
	Outbound Direction = "outbound"
	Inbound  Direction = "inbound"
)

// Event is one observed network operation.
type Event struct {
	Time      time.Time      `json:"time"`
	PID       uint32         `json:"pid"`
	TID       uint32         `json:"tid"`
	UID       uint32         `json:"uid"`
	Comm      string         `json:"comm"`
	Kind      string         `json:"kind"` // connect | accept | udp_send
	Proto     string         `json:"proto"`
	Direction Direction      `json:"direction"`
	Local     netip.AddrPort `json:"local"`
	Remote    netip.AddrPort `json:"remote"`
	Blocked   bool           `json:"blocked,omitempty"` // refused by deny mode
}

// Endpoint aggregates events to the same remote peer.
type Endpoint struct {
	Proto     string    `json:"proto"`
	Direction Direction `json:"direction"`
	Remote    string    `json:"remote"`              // ip:port (outbound) or ip (inbound, ephemeral peer port dropped)
	LocalPort uint16    `json:"localPort,omitempty"` // for inbound: the listening port
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	Comms     []string  `json:"comms"`
	Blocked   bool      `json:"blocked,omitempty"`
}

// Report is the result of a monitoring session.
type Report struct {
	Target    string     `json:"target"`
	Started   time.Time  `json:"started"`
	Ended     time.Time  `json:"ended"`
	ExitCode  *int       `json:"exitCode,omitempty"`
	Attached  []int      `json:"attachedPids,omitempty"`
	Endpoints []Endpoint `json:"endpoints,omitempty"` // with Net
	// Network blocked (--net with --deny/--ask).
	Denied         bool   `json:"denied,omitempty"`
	DroppedEgress  uint64 `json:"droppedEgressPackets,omitempty"`
	DroppedIngress uint64 `json:"droppedIngressPackets,omitempty"`
	// --filesystem: every path opened, and the sensitive paths used.
	Files          []FileAccess `json:"files,omitempty"`
	SensitivePaths []string     `json:"sensitivePaths,omitempty"`
	// --exec: every program executed.
	Execs []FileAccess `json:"execs,omitempty"`
}

// Options control a monitoring session. Exactly one of Command, PIDs or All
// must be set, and at least one of Net, Files, Exec and OnBinary.
type Options struct {
	// PIDs attaches to running processes. Their future children are always
	// followed; already-running descendants too when FollowExisting is set.
	// The session ends when every tracked process has exited (or ctx ends).
	PIDs           []int
	FollowExisting bool
	Command        []string
	All            bool

	// What to watch.
	Net   bool // TCP connect/accept, UDP sends
	Files bool // file opens (BPF LSM), --filesystem
	Exec  bool // programs executed (BPF LSM)
	// OnBinary is called for every file the target executes, interpreters
	// and the dynamic loader included (BPF LSM; used for --sbom). It must
	// not block.
	OnBinary func(FileEvent)

	// What to do with each category watched (Net, Files, Exec above):
	// ActionLog records it, ActionDeny refuses it in the kernel (Net all
	// network access, Files writes and sensitive reads, Exec every program
	// but the launched command), ActionAsk pauses those calls until Ask
	// returns a decision (only with Command); what is not allowed yet is
	// refused, as with ActionDeny. Ask may be called concurrently, once per
	// distinct question; ctx is cancelled when the paused task goes away.
	NetAction, FilesAction, ExecAction Action
	Ask                                func(ctx context.Context, r AskRequest) AskAnswer
	// FreezeOnAsk runs the command in a cgroup that AskRequest.Freeze can
	// freeze, for questions asked on the terminal (cgroup v2, Linux 5.19+;
	// without them Freeze stays nil).
	FreezeOnAsk bool
	// Allow are folder rules: reads, writes or execs that need no answer.
	Allow []FolderRule
	// SensitivePaths are added to the default sensitive paths (home, /root,
	// /etc/shadow, ...). A directory covers everything below.
	SensitivePaths []string

	// RunAsInvoker drops the child's privileges to SUDO_UID/SUDO_GID.
	RunAsInvoker bool
	// RunAs, if set, is the user the command runs as instead (its uid,
	// group and supplementary groups, HOME, USER and LOGNAME). Its home is
	// the one marked sensitive.
	RunAs *user.User
	// Callbacks (optional): network events, file opens and execs (Kind
	// "open" / "exec"), and the launched command exiting (its children may
	// still run and be monitored).
	OnEvent       func(Event)
	OnFileEvent   func(FileEvent)
	OnCommandExit func()
	// WaitLeftovers keeps monitoring the command's background processes
	// after it exits, until they exit too (or ctx ends). Without it they
	// are stopped (SIGTERM, then SIGKILL) and the session ends with the
	// command.
	WaitLeftovers bool
	// Stdin/Stdout/Stderr for the launched command.
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

// Action is what to do with a watched category.
type Action uint8

const (
	ActionLog  Action = iota // record only
	ActionDeny               // refuse in the kernel
	ActionAsk                // pause until Options.Ask answers
)

func (a Action) String() string {
	switch a {
	case ActionDeny:
		return "deny"
	case ActionAsk:
		return "ask"
	}
	return "log"
}

// enforcesNet, enforcesFiles and enforcesExec: the category is watched and
// denied or asked about.
func (o *Options) enforcesNet() bool   { return o.Net && o.NetAction != ActionLog }
func (o *Options) enforcesFiles() bool { return o.Files && o.FilesAction != ActionLog }
func (o *Options) enforcesExec() bool  { return o.Exec && o.ExecAction != ActionLog }

// enforcing: some watched category is denied or asked about.
func (o *Options) enforcing() bool { return o.enforcesNet() || o.enforcesFiles() || o.enforcesExec() }

// Asks reports whether some watched category is asked about.
func (o *Options) Asks() bool {
	return o.Net && o.NetAction == ActionAsk || o.Files && o.FilesAction == ActionAsk || o.Exec && o.ExecAction == ActionAsk
}

// Run attaches the probes and collects events until ctx is cancelled or the
// target is gone.
func Run(ctx context.Context, opts Options) (*Report, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	blockNet := opts.enforcesNet()
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("eBPF needs root (or CAP_BPF+CAP_PERFMON+CAP_SYS_RESOURCE); try: sudo %s: %w", os.Args[0], err)
	}

	var cleanup closers
	defer cleanup.close()

	spec, objs, err := loadTrace(opts, blockNet, &cleanup)
	if err != nil {
		return nil, err
	}
	var deny *denyCgroup
	if blockNet {
		if deny, err = setupDeny(spec, objs.Events); err != nil {
			return nil, err
		}
		cleanup.add(deny.Close)
	}
	var (
		scope    *fileScope
		files    *fileObjects
		dirAllow map[string]uint8
	)
	if opts.Files || opts.Exec || opts.OnBinary != nil {
		if scope, err = newFileScope(opts.SensitivePaths, opts.Home()); err != nil {
			return nil, err
		}
		c := lsmConfig{
			opens: opts.Files || opts.OnBinary != nil, logAll: opts.Files, enforceFiles: opts.enforcesFiles(),
			exec: opts.Exec, enforceExec: opts.enforcesExec(),
		}
		if files, err = setupLSM(spec, objs.Tracked, scope, c, &cleanup); err != nil {
			return nil, err
		}
		if dirAllow, err = files.presetDirs(opts.Allow); err != nil {
			return nil, err
		}
	}

	report := &Report{Started: time.Now(), Denied: blockNet}
	if opts.Files {
		report.SensitivePaths = scope.Paths()
	}
	agg, fileAgg, execAgg := newAggregator(), newFileAggregator(), newFileAggregator()
	var emitMu sync.Mutex // OnEvent/OnFileEvent are called from several goroutines
	emit := func(ev Event) {
		agg.add(ev)
		if opts.OnEvent != nil {
			emitMu.Lock()
			opts.OnEvent(ev)
			emitMu.Unlock()
		}
	}
	emitFile := func(ev FileEvent) {
		switch {
		case ev.Kind == "exec": // bprm_creds_for_exec (--exec)
			execAgg.add(ev)
		case ev.Exec && opts.OnBinary != nil:
			opts.OnBinary(ev)
			fallthrough
		default:
			if !opts.Files {
				return // file_open loaded for --sbom only
			}
			fileAgg.add(ev)
		}
		if opts.OnFileEvent != nil {
			emitMu.Lock()
			opts.OnFileEvent(ev)
			emitMu.Unlock()
		}
	}

	stopReaders, err := startReaders(objs, files, emit, emitFile)
	if err != nil {
		return nil, err
	}

	switch {
	case len(opts.Command) > 0:
		report.Target = fmt.Sprint(opts.Command)
		cfg := askConfig{ask: opts.Ask, emit: emit, emitFile: emitFile, deny: deny, scope: scope, dirAllow: dirAllow,
			net:   opts.Net && opts.NetAction == ActionAsk,
			opens: opts.Files && opts.FilesAction == ActionAsk,
			execs: opts.Exec && opts.ExecAction == ActionAsk}
		if files != nil {
			cfg.files = files // not a nil *fileObjects in a non-nil interface
		}
		code, err := runCommand(ctx, opts, objs.Tracked, cfg)
		if err != nil {
			stopReaders()
			return nil, err
		}
		report.ExitCode = &code
		time.Sleep(200 * time.Millisecond) // let in-flight ring buffer records drain
	case len(opts.PIDs) > 0:
		pids, err := attachPIDs(opts, objs.Tracked, deny)
		if err != nil {
			stopReaders()
			return nil, err
		}
		strs := make([]string, len(opts.PIDs))
		for i, p := range opts.PIDs {
			strs[i] = strconv.Itoa(p)
		}
		report.Target, report.Attached = "pid "+strings.Join(strs, ","), pids
		waitTreeExit(ctx, objs.Tracked)
	default: // All
		report.Target = "system-wide"
		<-ctx.Done()
	}

	stopReaders()
	report.Ended = time.Now()
	if opts.Net {
		report.Endpoints = agg.endpoints()
	}
	if opts.Files {
		report.Files = fileAgg.files()
	}
	if opts.Exec {
		report.Execs = execAgg.files()
	}
	if deny != nil {
		report.DroppedEgress, report.DroppedIngress = deny.dropped()
	}
	return report, nil
}

// Validate reports an invalid combination of options (Run calls it too).
func (o *Options) Validate() error {
	switch {
	case !o.Net && !o.Files && !o.Exec && o.OnBinary == nil:
		return errors.New("choose what to monitor: --net, --filesystem, --exec and/or --sbom")
	case len(o.Command) == 0 && len(o.PIDs) == 0 && !o.All:
		return errors.New("nothing to monitor: give a command, PIDs or --all")
	case o.Asks() && len(o.Command) == 0:
		return errors.New("asking only works with a launched command (not --all or attach)")
	case o.Asks() && o.Ask == nil:
		return errors.New("a category is asked about but Options.Ask is nil")
	case len(o.Allow) > 0 && !o.enforcesFiles() && !o.enforcesExec():
		return errors.New("--allow needs --filesystem or --exec set to deny or ask")
	case o.enforcing() && o.All:
		return errors.New("--deny/--ask cannot be combined with --all (it would apply to the whole host)")
	}
	return nil
}

// closers closes what a session opened, last opened first.
type closers []func()

func (c *closers) add(f func()) { *c = append(*c, f) }

func (c *closers) addLink(l link.Link) { c.add(func() { l.Close() }) }

func (c closers) close() {
	for i := len(c) - 1; i >= 0; i-- {
		c[i]()
	}
}

// loadTrace loads the BPF spec and the tracing programs, and attaches them.
func loadTrace(opts Options, blockNet bool, cleanup *closers) (*ebpf.CollectionSpec, *traceObjects, error) {
	spec, err := loadSecwrap()
	if err != nil {
		return nil, nil, fmt.Errorf("load BPF spec: %w", err)
	}
	if err := spec.Variables["self_tgid"].Set(uint32(os.Getpid())); err != nil {
		return nil, nil, err
	}
	if err := spec.Variables["trace_all"].Set(boolByte(opts.All)); err != nil {
		return nil, nil, err
	}
	if err := setKernelRegs(spec); err != nil {
		return nil, nil, err
	}
	if blockNet {
		if err := probeDenyHelpers(spec); err != nil {
			return nil, nil, fmt.Errorf("probe helpers: %w", err)
		}
	}
	objs := &traceObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, nil, fmt.Errorf("BPF verifier: %+v", ve)
		}
		return nil, nil, fmt.Errorf("load BPF objects: %w", err)
	}
	cleanup.add(objs.Close)
	links, err := attach(objs, opts.Net, blockNet)
	for _, l := range links {
		cleanup.addLink(l)
	}
	return spec, objs, err
}

// startReaders decodes both ring buffers in the background. stop closes
// them and waits until every record read so far has been emitted.
func startReaders(objs *traceObjects, files *fileObjects, emit func(Event), emitFile func(FileEvent)) (stop func(), err error) {
	// Boot time offset to convert bpf_ktime_get_ns (CLOCK_MONOTONIC) to wall time.
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return nil, fmt.Errorf("clock_gettime: %w", err)
	}
	wallOffset := time.Now().Add(-time.Duration(ts.Nano()))

	var readers []*ringbuf.Reader
	var wg sync.WaitGroup
	stop = func() {
		for _, r := range readers {
			r.Close()
		}
		wg.Wait()
	}
	start := func(m *ebpf.Map, loop func(*ringbuf.Reader)) error {
		rd, err := ringbuf.NewReader(m)
		if err != nil {
			stop()
			return fmt.Errorf("ringbuf reader: %w", err)
		}
		readers = append(readers, rd)
		wg.Add(1)
		go func() {
			defer wg.Done()
			loop(rd)
		}()
		return nil
	}
	if err := start(objs.Events, func(rd *ringbuf.Reader) {
		var raw secwrapEvent
		for {
			rec, err := rd.Read()
			if err != nil {
				return // closed
			}
			if binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &raw) == nil {
				emit(decode(&raw, wallOffset))
			}
		}
	}); err != nil {
		return nil, err
	}
	if files != nil {
		if err := start(files.FileEvents, func(rd *ringbuf.Reader) { readFileEvents(rd, wallOffset, emitFile) }); err != nil {
			return nil, err
		}
	}
	return stop, nil
}

// attachPIDs tracks running processes (and their descendants with
// FollowExisting), moving them into the deny cgroup in deny mode.
func attachPIDs(opts Options, tracked *ebpf.Map, deny *denyCgroup) ([]int, error) {
	pids := opts.PIDs
	if opts.FollowExisting {
		pids = WithDescendants(pids)
	}
	for _, p := range pids {
		if err := tracked.Put(uint32(p), uint8(1)); err != nil {
			return nil, fmt.Errorf("track pid %d: %w", p, err)
		}
		if deny != nil {
			if err := deny.addPID(p); err != nil {
				return nil, err
			}
		}
	}
	return pids, nil
}

// waitTreeExit blocks until ctx is done or the tracked map is empty (the
// exit tracepoint removes processes as they die, fork adds new children).
func waitTreeExit(ctx context.Context, tracked *ebpf.Map) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			var k uint32
			var v uint8
			if !tracked.Iterate().Next(&k, &v) {
				time.Sleep(200 * time.Millisecond) // drain in-flight events
				return
			}
		}
	}
}

// attach links the tracing programs: process tracking always, network
// probes with net. In deny mode the UDP send kprobes are skipped: they fire
// before the cgroup hook would refuse the send, so they would report
// blocked sends as if they had happened.
func attach(objs *traceObjects, net, deny bool) ([]link.Link, error) {
	type probe struct {
		name     string
		optional bool // tolerate attach failure
		skip     bool
		open     func() (link.Link, error)
	}
	probes := []probe{
		{"tp_btf sched_process_fork", false, false, func() (link.Link, error) {
			return link.AttachTracing(link.TracingOptions{Program: objs.HandleFork})
		}},
		{"tp_btf sched_process_exit", false, false, func() (link.Link, error) {
			return link.AttachTracing(link.TracingOptions{Program: objs.HandleExit})
		}},
		{"kprobe tcp_connect", false, !net, func() (link.Link, error) {
			return link.Kprobe("tcp_connect", objs.KpTcpConnect, nil)
		}},
		{"kretprobe inet_csk_accept", false, !net, func() (link.Link, error) {
			return link.Kretprobe("inet_csk_accept", objs.KrpInetCskAccept, nil)
		}},
		{"kprobe udp_sendmsg", false, !net || deny, func() (link.Link, error) {
			return link.Kprobe("udp_sendmsg", objs.KpUdpSendmsg, nil)
		}},
		// IPv6 may be a module or disabled.
		{"kprobe udpv6_sendmsg", true, !net || deny, func() (link.Link, error) {
			return link.Kprobe("udpv6_sendmsg", objs.KpUdpv6Sendmsg, nil)
		}},
	}
	var links []link.Link
	for _, p := range probes {
		if p.skip {
			continue
		}
		l, err := p.open()
		if err != nil {
			if p.optional {
				continue
			}
			return links, fmt.Errorf("attach %s: %w", p.name, err)
		}
		links = append(links, l)
	}
	return links, nil
}

// runCommand starts the command so that the fork is already tracked by the
// time the child execs: we track our own tgid, the fork tracepoint adds the
// child, then we untrack ourselves. No race with early connections.
// With deny set, the child is created directly inside the deny cgroup
// (clone3 CLONE_INTO_CGROUP): it never has network access, not even briefly.
// With Ask set, the child first runs secwrap's ask helper, which installs
// the seccomp notify filter and then execs the target.
// With files enabled too, the filter also traps the open syscalls.
func runCommand(ctx context.Context, opts Options, tracked *ebpf.Map, cfg askConfig) (int, error) {
	deny := cfg.deny
	track := func(pid int) error { return tracked.Put(uint32(pid), uint8(1)) }
	cmd := exec.CommandContext(ctx, opts.Command[0], opts.Command[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = opts.Stdin, opts.Stdout, opts.Stderr
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	attr := &syscall.SysProcAttr{}
	u := opts.RunAs
	if u == nil && opts.RunAsInvoker {
		u = SudoUser()
	}
	if u != nil {
		cred, err := userCredential(u)
		if err != nil {
			return 0, err
		}
		attr.Credential, cmd.Env = cred, userEnv(u)
	}
	freezePath := ""
	switch {
	case deny != nil:
		attr.UseCgroupFD, attr.CgroupFD = true, deny.FD()
		freezePath = deny.path
	case opts.FreezeOnAsk && opts.Asks():
		pc, err := newPlainCgroup()
		if err != nil {
			return 0, err
		}
		defer pc.Close()
		attr.UseCgroupFD, attr.CgroupFD = true, pc.FD()
		freezePath = pc.path
	}
	cmd.SysProcAttr = attr

	// --exec with --deny/--ask: the launched command may run, and so may
	// secwrap's own ask helper, until it has exec'd the target.
	helperRule := ""
	if opts.enforcesExec() && cfg.files != nil {
		target, err := exec.LookPath(opts.Command[0])
		if err == nil {
			target, err = filepath.EvalSymlinks(target)
		}
		if err == nil {
			target, err = filepath.Abs(target)
		}
		if err != nil {
			return 0, fmt.Errorf("--exec: %w", err)
		}
		if err := cfg.files.allow(target, ruleExec); err != nil {
			return 0, fmt.Errorf("--exec: allow %s: %w", target, err)
		}
		cfg.fileAllow = map[string]uint8{target: ruleExec}
		if self, err := os.Executable(); opts.Asks() && err == nil {
			if self, err = filepath.EvalSymlinks(self); err == nil && self != target {
				if cfg.files.allow(self, ruleExec) == nil {
					helperRule = self
				}
			}
		}
	}

	var finishAsk func() (int, bool, error)
	if opts.Asks() {
		var err error
		if finishAsk, err = askCommand(cmd, opts.Command, cfg.net, cfg.opens, cfg.execs); err != nil {
			return 0, fmt.Errorf("ask mode: %w", err)
		}
	}

	self := os.Getpid()
	if err := track(self); err != nil {
		return 0, fmt.Errorf("track self: %w", err)
	}
	err := cmd.Start()
	_ = tracked.Delete(uint32(self))
	if err != nil {
		return 0, fmt.Errorf("start %s: %w", opts.Command[0], err)
	}
	// Belt and braces in case the fork hook missed it.
	_ = track(cmd.Process.Pid)

	if finishAsk != nil {
		lfd, killable, err := finishAsk()
		if helperRule != "" {
			cfg.files.allow(helperRule, 0) // the helper is running: no more secwrap execs
		}
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return 0, fmt.Errorf("ask mode: %w", err)
		}
		if opts.FreezeOnAsk && killable && freezePath != "" {
			cfg.freeze = freezer(freezePath)
		}
		stop := superviseAsk(lfd, cfg)
		defer stop()
	}

	err = cmd.Wait()
	code := 0
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		return -1, err
	}
	if opts.OnCommandExit != nil {
		opts.OnCommandExit()
	}

	// Children that outlive the command (background jobs, daemons) stay
	// monitored: keep going until the whole tree has exited.
	if n := countTracked(tracked); n > 0 && ctx.Err() == nil {
		if opts.WaitLeftovers {
			what := "they keep running, unmonitored"
			if deny != nil {
				what = "they are killed"
			}
			fmt.Fprintf(os.Stderr, "secwrap: %s exited; %d background process(es) still running and monitored (Ctrl-C to stop: %s)\n",
				opts.Command[0], n, what)
			waitTreeExit(ctx, tracked)
		} else {
			fmt.Fprintf(os.Stderr, "secwrap: %s exited; stopping its %d background process(es): %s (--wait to keep monitoring them)\n",
				opts.Command[0], n, strings.Join(trackedNames(tracked), ", "))
			stopTracked(tracked, deny)
		}
	}
	// Stopped early: in deny/ask mode, leftovers would get their network
	// back once the cgroup goes away, so kill them instead.
	if ctx.Err() != nil && deny != nil {
		deny.kill()
	}
	return code, nil
}

// trackedPIDs lists the processes still in the tracked map.
func trackedPIDs(tracked *ebpf.Map) []int {
	var pids []int
	var k uint32
	var v uint8
	for it := tracked.Iterate(); it.Next(&k, &v); {
		pids = append(pids, int(k))
	}
	return pids
}

// trackedNames is "comm(pid)" for each tracked process.
func trackedNames(tracked *ebpf.Map) []string {
	var names []string
	for _, pid := range trackedPIDs(tracked) {
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		names = append(names, fmt.Sprintf("%s(%d)", strings.TrimSpace(string(comm)), pid))
	}
	return names
}

// stopTracked ends the processes left after the command: the whole deny
// cgroup when there is one, otherwise SIGTERM, then SIGKILL after 2s.
func stopTracked(tracked *ebpf.Map, deny *denyCgroup) {
	if deny != nil {
		deny.kill()
	} else {
		for _, pid := range trackedPIDs(tracked) {
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	waitTreeExit(ctx, tracked)
	for _, pid := range trackedPIDs(tracked) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		_ = tracked.Delete(uint32(pid))
	}
}

func countTracked(tracked *ebpf.Map) int { return len(trackedPIDs(tracked)) }

// LookupUser finds a user by name or uid.
func LookupUser(s string) (*user.User, error) {
	if _, err := strconv.Atoi(s); err == nil {
		if u, err := user.LookupId(s); err == nil {
			return u, nil
		}
	}
	u, err := user.Lookup(s)
	if err != nil {
		return nil, fmt.Errorf("--user %q: %w", s, err)
	}
	return u, nil
}

// SudoUser is the user who ran sudo, or nil (not under sudo, or root).
func SudoUser() *user.User {
	uid, err := strconv.Atoi(os.Getenv("SUDO_UID"))
	if err != nil || uid == 0 {
		return nil
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		// No passwd entry: the ids alone, as before.
		return &user.User{Uid: strconv.Itoa(uid), Gid: os.Getenv("SUDO_GID"), Username: os.Getenv("SUDO_USER")}
	}
	return u
}

// Home is the home whose files are sensitive and that ~/ means: the one of
// the user the command runs as.
func (o *Options) Home() string {
	u := o.RunAs
	if u == nil {
		u = SudoUser() // the sudo invoker's, even with --as-root, attach or --all
	}
	if u != nil && u.HomeDir != "" {
		return u.HomeDir
	}
	h, _ := os.UserHomeDir()
	return h
}

// userCredential is u's uid, primary group and supplementary groups, as a
// login (or sudo -u) gives them.
func userCredential(u *user.User) (*syscall.Credential, error) {
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("user %s: bad uid/gid %q/%q", u.Username, u.Uid, u.Gid)
	}
	cred := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	if ids, err := u.GroupIds(); err == nil {
		for _, g := range ids {
			if n, err := strconv.Atoi(g); err == nil {
				cred.Groups = append(cred.Groups, uint32(n))
			}
		}
	}
	return cred, nil
}

// userEnv is our environment with HOME, USER and LOGNAME set for u, as
// sudo -u would: under sudo they still describe root.
func userEnv(u *user.User) []string {
	if u.HomeDir == "" {
		return nil // nil: inherit ours
	}
	set := map[string]string{"HOME": u.HomeDir, "USER": u.Username, "LOGNAME": u.Username}
	var env []string
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); set[k] == "" {
			env = append(env, kv)
		}
	}
	for k, v := range set {
		env = append(env, k+"="+v)
	}
	return env
}

const (
	afInet  = 2
	afInet6 = 10
)

func decode(r *secwrapEvent, wallOffset time.Time) Event {
	ev := Event{
		Time: wallOffset.Add(time.Duration(r.TsNs)),
		PID:  r.Tgid,
		TID:  r.Pid,
		UID:  r.Uid,
		Comm: cString(r.Comm[:]),
	}
	switch r.Proto {
	case 6:
		ev.Proto = "tcp"
	case 17:
		ev.Proto = "udp"
	}
	switch r.Kind {
	case 1:
		ev.Kind, ev.Direction = "connect", Outbound
	case 2:
		ev.Kind, ev.Direction = "accept", Inbound
	case 3:
		ev.Kind, ev.Direction = "udp_send", Outbound
	case 4:
		ev.Kind, ev.Direction, ev.Blocked = "connect", Outbound, true
	case 5:
		ev.Kind, ev.Direction, ev.Blocked = "udp_send", Outbound, true
	}
	var src, dst netip.Addr
	switch r.Family {
	case afInet:
		src = netip.AddrFrom4([4]byte(r.Saddr[:4]))
		dst = netip.AddrFrom4([4]byte(r.Daddr[:4]))
	case afInet6:
		src = netip.AddrFrom16(r.Saddr).Unmap()
		dst = netip.AddrFrom16(r.Daddr).Unmap()
	}
	ev.Local = netip.AddrPortFrom(src, r.Sport)
	ev.Remote = netip.AddrPortFrom(dst, r.Dport)
	return ev
}

func cString(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

type aggregator struct {
	mu sync.Mutex
	m  map[string]*Endpoint
}

func newAggregator() *aggregator { return &aggregator{m: map[string]*Endpoint{}} }

func (a *aggregator) add(ev Event) {
	var key, remote string
	var lport uint16
	if ev.Direction == Inbound {
		// Peer port is ephemeral; group by peer IP + our listening port.
		remote = ev.Remote.Addr().String()
		lport = ev.Local.Port()
		key = fmt.Sprintf("%s|in|%s|%d", ev.Proto, remote, lport)
	} else {
		remote = ev.Remote.String()
		key = fmt.Sprintf("%s|out|%s|%v", ev.Proto, remote, ev.Blocked)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	ep, ok := a.m[key]
	if !ok {
		ep = &Endpoint{Proto: ev.Proto, Direction: ev.Direction, Remote: remote, LocalPort: lport, FirstSeen: ev.Time, Blocked: ev.Blocked}
		a.m[key] = ep
	}
	ep.Count++
	ep.LastSeen = ev.Time
	if !contains(ep.Comms, ev.Comm) {
		ep.Comms = append(ep.Comms, ev.Comm)
	}
}

func (a *aggregator) endpoints() []Endpoint {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Endpoint, 0, len(a.m))
	for _, ep := range a.m {
		out = append(out, *ep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstSeen.Before(out[j].FirstSeen) })
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
