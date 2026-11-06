package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/noboruma/secwrap/internal/monitor"
)

// session holds what monitor, run, attach and shell share: the common
// flags, the live event log, the asker and the summary.
type session struct {
	// what to watch
	net, files, exec bool
	sbomDir          string
	sbomTemp         bool // bare --sbom: in the history folder (or /tmp)
	// what to do with it
	deny  bool
	ask   string // "" | off | session | tty | stdout
	allow stringList
	sens  stringList
	// how
	asRoot  bool
	user    string // --user: run the command as this user
	runAs   *user.User
	log     string // "" (stderr) | off | FILE
	wait    bool   // keep monitoring background processes after the command
	summ    bool   // print the summary at the end
	histDir string // "" (~/.local/state/secwrap) | off | DIR
	hist    *history
	sess    *liveSession
	web     string // --web: serve every session's page at this address (off: "")
	webHost *webHost

	sboms   *sbomStore
	logW    io.Writer // live events
	summary io.Writer // human summary
	logF    *os.File
	asker   func(context.Context, monitor.AskRequest) monitor.AskAnswer
	stopAsk func()
}

// newSession registers the common flags. withAsk adds --ask and --as-root,
// which only make sense for a launched command (not attach).
func newSession(fs *flag.FlagSet, withAsk bool) *session {
	s := &session{}
	fs.BoolVar(&s.net, "net", false, "watch the network: TCP connect/accept, UDP sends")
	fs.BoolVar(&s.files, "filesystem", false, "watch file opens (BPF LSM)")
	fs.BoolVar(&s.exec, "exec", false, "watch programs executed (BPF LSM)")
	fs.Var(sbomFlag{s}, "sbom", "write a CycloneDX SBOM to DIR for every binary executed (listed on the --ask web page);\n"+
		"bare --sbom: sboms/ in the session's history folder (/tmp with --history off)")
	fs.BoolVar(&s.deny, "deny", false, "block what is watched: --net all network access, --filesystem writes and sensitive reads,\n"+
		"--exec every program but the launched command")
	if withAsk {
		fs.Var(askFlag{s}, "ask", "like --deny, but pause each call until answered: session (from secwrap session attach\n"+
			"or the --web page), tty (or stdout) on the terminal, or off; ADDR is short for session --web ADDR.\n"+
			"Every session can also be answered with secwrap session attach")
		fs.BoolVar(&s.asRoot, "as-root", false, "under sudo, run the command as root instead of SUDO_USER")
		fs.StringVar(&s.user, "user", "", "run the command as this user (name or uid), with its groups and HOME,\n"+
			"instead of SUDO_USER (needs root)")
		fs.BoolVar(&s.wait, "wait", false, "when the command exits, keep monitoring its background processes until they exit\n"+
			"(default: stop them and end the session)")
	}
	fs.Var(&s.allow, "allow", "with --deny/--ask: allow r(ead), w(rite) and/or (e)x(ec) under DIR, e.g. r:~/.oh-my-zsh, rwx:./build (repeatable)")
	fs.Var(&s.sens, "sensitive", "with --filesystem: extra sensitive PATH (repeatable; a directory covers everything below)")
	fs.Var(optAddr{&s.web}, "web", "serve the web page of every session at ADDR (bare --web: "+defaultWebAddr+"),\n"+
		"unless another secwrap serves it already; takes over when that one exits. off: don't")
	fs.BoolVar(&s.summ, "summary", false, "print the summary at the end (it is always in the history folder)")
	fs.StringVar(&s.histDir, "history", "", "keep every session in a folder under DIR (default ~/.local/state/secwrap), or off")
	fs.StringVar(&s.log, "log", "", "live events to FILE instead of stderr (JSON lines if it ends in .json/.jsonl), or off")
	return s
}

func (s *session) options(cmd []string) monitor.Options {
	return monitor.Options{
		Command: cmd, RunAsInvoker: !s.asRoot, RunAs: s.runAs, Net: s.net, Files: s.files, Exec: s.exec,
		Deny: s.deny, SensitivePaths: s.sens, WaitLeftovers: s.wait,
	}
}

// run monitors o, printing live events and the summary.
func (s *session) run(ctx context.Context, o monitor.Options) (*monitor.Report, error) {
	if s.asking() { // s.asker is set by start, after the session exists
		o.Ask = func(ctx context.Context, r monitor.AskRequest) monitor.AskAnswer { return s.asker(ctx, r) }
	}
	onBinary := func(e monitor.FileEvent) { s.sboms.onExec(e) }
	if s.sbomDir != "" || s.sbomTemp {
		o.OnBinary = onBinary
	}
	sess, err := createSession(sessionName(o), s.info(o))
	if err != nil {
		return nil, err
	}
	s.sess = sess
	var rep *monitor.Report
	defer func() { s.sess.end(rep) }()
	if s.histDir != "off" { // named after the session
		if s.hist, err = openHistory(s.histDir, sess.info.ID); err != nil {
			return nil, err
		}
	}
	for _, a := range s.allow {
		r, err := monitor.ParseFolderRule(a, o.Home())
		if err != nil {
			return nil, err
		}
		o.Allow = append(o.Allow, r)
	}
	if err := o.Validate(); err != nil {
		return nil, err
	}
	// Bare --sbom, or --ask session (the web page lists the binaries run, with
	// their SBOMs, when the BPF LSM is there): in the history folder, or /tmp.
	if s.sbomDir == "" && (s.sbomTemp || s.ask == "session" && monitor.BPFLSMEnabled()) {
		if err := s.tempSBOMDir(); err != nil {
			return nil, err
		}
		o.OnBinary = onBinary
	}
	s.sess.update(func(i *sessionInfo) {
		i.SBOMs = s.sbomDir
		if s.hist != nil {
			i.History = s.hist.dir
		}
	})
	if err := s.start(o.Command); err != nil {
		return nil, err
	}
	s.announce()
	defer s.stop()
	s.liveOutput(&o)
	if s.hist != nil {
		s.hist.wrap(&o)
	}
	rep, err = monitor.Run(ctx, o)
	if err != nil {
		if s.hist != nil {
			s.hist.finish(nil, func(w io.Writer) { fmt.Fprintf(w, "secwrap: %v\n", err) })
		}
		return nil, err
	}
	if len(rep.Attached) > 0 {
		fmt.Fprintf(os.Stderr, "secwrap: followed %d process(es)\n", len(rep.Attached))
	}
	s.closeSBOMs() // before the summary: it lists them
	summary := func(w io.Writer) {
		printSummary(w, rep)
		s.printSBOMSummary(w)
	}
	if s.summ {
		summary(s.summary)
	}
	if s.hist != nil {
		s.hist.finish(rep, summary)
		fmt.Fprintf(os.Stderr, "secwrap: session recorded in %s\n", s.hist.dir)
	}
	return rep, nil
}

// tempSBOMDir points --sbom at a new, unpredictable directory under $TMPDIR
// (/tmp), owned by the invoking user under sudo.
func (s *session) tempSBOMDir() error {
	if s.hist != nil { // with the rest of the session
		dir, err := s.hist.sbomDir()
		if err != nil {
			return fmt.Errorf("--sbom: %w", err)
		}
		s.sbomDir = dir
		return nil
	}
	dir, err := os.MkdirTemp("", "secwrap-sboms-*")
	if err != nil {
		return fmt.Errorf("--sbom: %w", err)
	}
	chownPathToInvoker(dir) // under sudo: the user's
	s.sbomDir = dir
	fmt.Fprintf(os.Stderr, "secwrap: SBOMs of the binaries run go to %s (--sbom DIR to choose)\n", dir)
	return nil
}

// optionalValue is a flag whose value is optional: "--web" alone or
// "--web ADDR" (see parseFlags). To the flag package it is a bool flag, so
// a bare one gets Set("true").
type optionalValue interface {
	flag.Value
	IsBoolFlag() bool
	optionalValue()
}

// optAddr is --web [ADDR]: bare, the default address; off or false, none.
type optAddr struct{ p *string }

func (f optAddr) IsBoolFlag() bool { return true }
func (f optAddr) optionalValue()   {}

func (f optAddr) String() string {
	if f.p == nil {
		return ""
	}
	return *f.p
}

func (f optAddr) Set(v string) error {
	switch v {
	case "true":
		*f.p = defaultWebAddr
	case "false", "off", "":
		*f.p = ""
	default:
		if !looksLikeAddr(v) {
			return fmt.Errorf("want an address (9000, :9000, 127.0.0.1:9000) or off, not %q", v)
		}
		*f.p = normalizeAddr(v)
	}
	return nil
}

// sbomFlag is --sbom [DIR].
type sbomFlag struct{ s *session }

func (f sbomFlag) IsBoolFlag() bool { return true }
func (f sbomFlag) optionalValue()   {}

func (f sbomFlag) String() string {
	if f.s == nil {
		return ""
	}
	return f.s.sbomDir
}

func (f sbomFlag) Set(v string) error {
	switch v {
	case "true":
		f.s.sbomDir, f.s.sbomTemp = "", true
	case "false", "":
		f.s.sbomDir, f.s.sbomTemp = "", false
	default:
		f.s.sbomDir, f.s.sbomTemp = v, false
	}
	return nil
}

// askFlag is --ask; an address means --ask session --web ADDR.
type askFlag struct{ s *session }

func (f askFlag) String() string {
	if f.s == nil {
		return ""
	}
	return f.s.ask
}

func (f askFlag) Set(v string) error {
	switch {
	case v == "session" || v == "tty" || v == "stdout" || v == "off" || v == "":
		f.s.ask = v
	case looksLikeAddr(v):
		f.s.ask, f.s.web = "session", normalizeAddr(v)
	default:
		return fmt.Errorf("want session, tty, off or an address (9000, :9000, 127.0.0.1:9000), not %q", v)
	}
	return nil
}

// parse parses args into fs (see parseFlags), then checks --user.
func (s *session) parse(fs *flag.FlagSet, args []string) {
	parseFlags(fs, args)
	if err := s.resolveUser(); err != nil {
		fmt.Fprintln(os.Stderr, "secwrap:", err)
		os.Exit(2)
	}
}

// parseFlags parses args into fs. Flags with an optionalValue take a value
// only when one follows ("--sbom DIR", "--web 9000"); bare ("--sbom --net",
// "--web --", last) they get their default. The command after the flags is
// left untouched.
func parseFlags(fs *flag.FlagSet, args []string) {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		out = append(out, a)
		if a == "--" || !strings.HasPrefix(a, "-") || a == "-" {
			out = append(out, args[i+1:]...) // the command and its args: untouched
			break
		}
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue
		}
		f := fs.Lookup(name)
		if f == nil || i+1 >= len(args) {
			continue
		}
		next := args[i+1]
		if _, ok := f.Value.(optionalValue); ok {
			if !strings.HasPrefix(next, "-") {
				out[len(out)-1] = a + "=" + next
				i++
			}
			continue
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !b.IsBoolFlag() {
			out = append(out, next) // this flag's value
			i++
		}
	}
	fs.Parse(out)
}

// resolveUser checks --user against --as-root and looks it up. It runs
// before the command is built (shell picks that user's login shell).
func (s *session) resolveUser() error {
	if s.user == "" {
		return nil
	}
	if s.asRoot {
		return errors.New("--user and --as-root: pick one")
	}
	if os.Geteuid() != 0 {
		return errors.New("--user needs root (sudo)")
	}
	u, err := monitor.LookupUser(s.user)
	if err != nil {
		return err
	}
	s.runAs = u
	return nil
}

// info describes the session for session.json.
func (s *session) info(o monitor.Options) sessionInfo {
	i := sessionInfo{Target: sessionName(o)}
	if len(o.Command) > 0 {
		i.Target = strings.Join(o.Command, " ")
	}
	for _, w := range []struct {
		on   bool
		name string
	}{{s.net, "net"}, {s.files, "filesystem"}, {s.exec, "exec"}} {
		if w.on {
			i.Watch = append(i.Watch, w.name)
		}
	}
	switch {
	case s.asking():
		i.Ask = s.ask
	case s.deny:
		i.Ask = "deny"
	}
	if s.runAs != nil {
		i.RunAs = s.runAs.Username
	}
	return i
}

// announce says where the session is, and how to answer it.
func (s *session) announce() {
	id := s.sess.info.ID
	page := ""
	if base, _ := currentWeb(); base != "" {
		page = base + "s/" + id + "/"
	}
	switch {
	case s.asking() && page != "":
		fmt.Fprintf(os.Stderr, "secwrap: session %s: answer at %s or with sudo secwrap session attach %s\n", id, page, id)
	case s.asking():
		fmt.Fprintf(os.Stderr, "secwrap: session %s: answer with sudo secwrap session attach %s (or sudo secwrap session --web)\n", id, id)
	case page != "":
		fmt.Fprintf(os.Stderr, "secwrap: session %s: %s\n", id, page)
	default:
		fmt.Fprintf(os.Stderr, "secwrap: session %s\n", id)
	}
	if s.hist != nil {
		fmt.Fprintf(os.Stderr, "secwrap: recording it in %s\n", s.hist.dir)
	}
}

// sessionName names the session: the command, attach-PID or all.
func sessionName(o monitor.Options) string {
	switch {
	case len(o.Command) > 0:
		return filepath.Base(o.Command[0])
	case o.All:
		return "all"
	case len(o.PIDs) > 0:
		return "attach-" + strconv.Itoa(o.PIDs[0])
	}
	return "session"
}

// start opens the log and the asker. A bad command fails here, before the
// web page is served or anything is forked.
func (s *session) start(cmd []string) error {
	s.logW, s.summary, s.stopAsk = os.Stderr, os.Stderr, func() {}
	if s.sbomDir != "" {
		st, err := newSBOMStore(s.sbomDir)
		if err != nil {
			return err
		}
		s.sboms = st
	}
	asking := s.asking()
	if asking && len(cmd) > 0 {
		if _, err := exec.LookPath(cmd[0]); err != nil {
			return fmt.Errorf("command not found: %w", err)
		}
	}
	if asking { // every question goes to the session files; tty races them
		var tty func(context.Context, monitor.AskRequest) monitor.AskAnswer
		if s.ask == "tty" || s.ask == "stdout" {
			tty = newTTYAsker().ask
		}
		sa := newSessionAsker(s.sess, tty)
		s.asker, s.stopAsk = sa.ask, sa.close
	}
	if s.web != "" {
		s.webHost = startWebHost(s.web)
	}

	switch s.log {
	case "", "-", "off":
	default:
		f, err := os.OpenFile(s.log, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			s.stopAsk()
			return fmt.Errorf("open log: %w", err)
		}
		chownToInvoker(f)
		s.logF, s.logW = f, f
		if !s.jsonLog() {
			s.summary = f // JSON logs stay machine-readable: summary on stderr
		}
	}
	return nil
}

func (s *session) asking() bool { return s.ask != "" && s.ask != "off" }

func (s *session) closeSBOMs() {
	if s.sboms != nil {
		s.sboms.close()
	}
}

// printSBOMSummary lists the executed binaries and where their SBOMs are.
func (s *session) printSBOMSummary(w io.Writer) {
	if s.sboms == nil {
		return
	}
	list := s.sboms.snapshot()
	fmt.Fprintf(w, "\n== binaries executed: %d, SBOMs in %s ==\n", len(list), s.sbomDir)
	for i := len(list) - 1; i >= 0; i-- { // oldest first
		b := list[i]
		what := fmt.Sprintf("%d components -> %s", b.Components, b.File)
		if b.Status != "done" {
			what = b.Status + ": " + b.Error
		}
		fmt.Fprintf(w, "  %-50s x%-4d %s\n", b.Path, b.Execs, what)
	}
}

func (s *session) stop() {
	s.closeSBOMs() // no-op if already closed by run
	s.stopAsk()
	if s.webHost != nil {
		s.webHost.close() // another --web secwrap takes the page over
	}
	if s.logF != nil {
		s.logF.Close()
		fmt.Fprintf(os.Stderr, "secwrap: event log written to %s\n", s.log)
	}
}

func (s *session) jsonLog() bool {
	return strings.HasSuffix(s.log, ".json") || strings.HasSuffix(s.log, ".jsonl")
}

// liveOutput sets the event callbacks. JSON logs get every event; text
// shows file opens only when they matter (writes, sensitive reads,
// blocked): plain reads are counted in hundreds.
func (s *session) liveOutput(o *monitor.Options) {
	if s.log == "off" {
		return
	}
	w := s.logW
	if s.jsonLog() {
		enc := json.NewEncoder(w)
		o.OnEvent = func(e monitor.Event) { enc.Encode(e) }
		o.OnFileEvent = func(e monitor.FileEvent) { enc.Encode(e) }
		return
	}
	const ts = "15:04:05.000"
	o.OnEvent = func(e monitor.Event) {
		if e.Blocked {
			fmt.Fprintf(w, "[deny] %s pid=%d %-8s %s %s -> %s BLOCKED\n", e.Time.Format(ts), e.PID, e.Comm, e.Proto, e.Kind, e.Remote)
			return
		}
		arrow := "->"
		if e.Direction == monitor.Inbound {
			arrow = "<-"
		}
		fmt.Fprintf(w, "[net] %s pid=%d %-8s %s %s %s %s\n", e.Time.Format(ts), e.PID, e.Comm, e.Proto, e.Local, arrow, e.Remote)
	}
	o.OnFileEvent = func(e monitor.FileEvent) {
		if e.Kind == "exec" {
			fmt.Fprintf(w, "[exec] %s pid=%d %-8s %s%s\n", e.Time.Format(ts), e.PID, e.Comm, e.Path, blocked(e.Blocked, " BLOCKED"))
			return
		}
		if e.InScope || e.Blocked {
			fmt.Fprintf(w, "[file] %s pid=%d %-8s %-6s %s%s\n", e.Time.Format(ts), e.PID, e.Comm,
				fileMode(e.Write, e.Created, e.Sensitive), e.Path, blocked(e.Blocked, " BLOCKED"))
		}
	}
}

func printSummary(w io.Writer, rep *monitor.Report) {
	if rep.Endpoints != nil {
		printNetSummary(w, rep)
	}
	if rep.Files != nil {
		printFileSummary(w, rep)
	}
	if rep.Execs != nil {
		fmt.Fprintf(w, "\n== exec summary: %d programs ==\n", len(rep.Execs))
		for _, f := range rep.Execs {
			fmt.Fprintf(w, "  %-60s x%-5d %s%s\n", f.Path, f.Count, strings.Join(f.Comms, ","), blocked(f.Blocked, "  BLOCKED"))
		}
	}
}

func printNetSummary(w io.Writer, rep *monitor.Report) {
	eps := append([]monitor.Endpoint(nil), rep.Endpoints...)
	sort.SliceStable(eps, func(i, j int) bool { return eps[i].Count > eps[j].Count })
	fmt.Fprintf(w, "\n== network summary: %s (%d endpoints) ==\n", rep.Target, len(eps))
	nBlocked := 0
	for _, ep := range eps {
		peer := ep.Remote
		if ep.Direction == monitor.Inbound {
			peer = fmt.Sprintf("%s -> :%d", ep.Remote, ep.LocalPort)
		}
		if ep.Blocked {
			nBlocked += ep.Count
		}
		fmt.Fprintf(w, "  %-8s %-3s %-45s x%-5d %s%s\n", ep.Direction, ep.Proto, peer, ep.Count,
			strings.Join(ep.Comms, ","), blocked(ep.Blocked, "  BLOCKED"))
	}
	if rep.Denied {
		fmt.Fprintf(w, "  deny mode: %d connection/send attempts blocked; other packets dropped: %d out, %d in\n",
			nBlocked, rep.DroppedEgress, rep.DroppedIngress)
	}
}

func printFileSummary(w io.Writer, rep *monitor.Report) {
	var shown []monitor.FileAccess
	for _, f := range rep.Files {
		if f.InScope || f.Blocked {
			shown = append(shown, f)
		}
	}
	fmt.Fprintf(w, "\n== file summary: %d paths opened, %d writes/sensitive ==\n", len(rep.Files), len(shown))
	for _, f := range shown {
		fmt.Fprintf(w, "  %-6s %-60s x%-5d %s%s\n", fileMode(f.Write, f.Created, f.Sensitive), f.Path, f.Count,
			strings.Join(f.Comms, ","), blocked(f.Blocked, "  BLOCKED"))
	}
	if n := len(rep.Files) - len(shown); n > 0 {
		fmt.Fprintf(w, "  (+%d paths only read; listed in the JSON report, -o FILE)\n", n)
	}
}

func blocked(b bool, label string) string {
	if b {
		return label
	}
	return ""
}

// fileMode is a short label: create, write, read* (sensitive read) or read.
func fileMode(write, created, sensitive bool) string {
	switch {
	case created:
		return "create"
	case write:
		return "write"
	case sensitive:
		return "read*"
	}
	return "read"
}

// looksLikeAddr reports whether s is PORT, :PORT or HOST:PORT.
func looksLikeAddr(s string) bool {
	if _, err := strconv.Atoi(s); err == nil {
		return true
	}
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	_, err = strconv.Atoi(port)
	return err == nil
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }
