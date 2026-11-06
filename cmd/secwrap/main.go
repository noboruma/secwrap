// Command secwrap wraps a command or a shell and watches, with eBPF, what it
// does on the network and the file system: record, block, or ask first. It
// also generates CycloneDX SBOMs.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/noboruma/secwrap/internal/monitor"
	"github.com/noboruma/secwrap/internal/sbom"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == monitor.AskHelperArg {
		monitor.RunAskHelper(os.Args[2:]) // never returns
	}
	cmds := map[string]func([]string) error{
		"sbom": cmdSBOM, "monitor": cmdMonitor, "run": cmdRun, "attach": cmdAttach, "shell": cmdShell,
		"session": cmdSession,
	}
	name := ""
	if len(os.Args) > 1 {
		name = os.Args[1]
	}
	cmd := cmds[name]
	if cmd == nil {
		usage()
		if name == "-h" || name == "--help" || name == "help" {
			return
		}
		os.Exit(2)
	}
	if err := cmd(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "secwrap:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `secwrap: run a command or a shell under eBPF watch: record, block, or ask before network and file access

  secwrap sbom    [-o FILE] BINARY              CycloneDX SBOM (Go, Rust, ELF shared libs + dpkg)
  secwrap monitor [flags] (--all | -- CMD ...)  record what CMD does (root)
  secwrap run     [flags] -- CMD ...            SBOM + monitor; endpoints become CycloneDX services
  secwrap attach  [flags] (PID... | --name N)   monitor running processes and their children
  secwrap shell   [flags] [-- SHELL ...]        shell where everything you run is monitored
  secwrap session                              sessions alive and dead in a terminal UI: attach, delete
  secwrap session list | attach [ID] | delete ID  list; answer one's questions here (root); delete dead ones

What to watch, and what to do with each: off, log, ask or deny (shell: --net --filesystem --ask):
  --net [MODE]          network: TCP connect/accept, UDP sends
  --filesystem [MODE]   file opens (BPF LSM); deny/ask: writes and sensitive reads
  --exec [MODE]         programs executed (BPF LSM); deny/ask: every exec but CMD
  --sbom [DIR]          a CycloneDX SBOM in DIR (default: the history folder) for every binary executed
  --deny, --ask         the mode of categories given bare (default: log)
  --answer inline|detached  ask here in the terminal too (default), or only from secwrap session (attach, web page)
  --web-addr ADDR       serve every session's web page at ADDR (default 127.0.0.1:9000; 9000, :9000, 0.0.0.0:9100)
                        unless a secwrap already serves that address; one host per address, all show every session
  --no-web              don't serve it
  --allow rwx:DIR       with deny/ask: allow reads/writes/execs under DIR (repeatable)
  --log FILE|off        live events to FILE (JSON lines if *.json/*.jsonl) instead of stderr
Run "secwrap CMD -h" for all flags.
`)
}

// writeJSONIn writes v as indented JSON to name inside root (no symlink
// can lead it out), owned by the invoking user under sudo.
func writeJSONIn(root *os.Root, name string, v any) error {
	f, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	chownToInvoker(f)
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func writeJSON(path string, v any) error {
	var w io.Writer = os.Stdout
	if path != "" && path != "-" {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		chownToInvoker(f)
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func cmdSBOM(args []string) error {
	fs := flag.NewFlagSet("sbom", flag.ExitOnError)
	out := fs.String("o", "-", "output file (default stdout)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: secwrap sbom [-o FILE] BINARY")
	}
	bom, err := sbom.Generate(fs.Arg(0))
	if err != nil {
		return err
	}
	return writeJSON(*out, bom)
}

func cmdMonitor(args []string) error {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	s := newSession(fs, true)
	all := fs.Bool("all", false, "monitor every process on the host")
	out := fs.String("o", "", "write the JSON report to FILE ('-' for stdout)")
	s.parse(fs, args)

	o := s.options(fs.Args())
	o.All = *all
	rep, err := s.run(signalContext(), o)
	if err != nil {
		return err
	}
	if *out != "" {
		if err := writeJSON(*out, rep); err != nil {
			return err
		}
	}
	return exitWith(rep)
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	s := newSession(fs, true)
	out := fs.String("o", "-", "SBOM output file (default stdout)")
	s.parse(fs, args)
	if fs.NArg() == 0 {
		return errors.New("usage: secwrap run [flags] -- CMD [ARGS...]")
	}
	bin, err := exec.LookPath(fs.Arg(0))
	if err != nil {
		return err
	}
	bom, err := sbom.Generate(bin)
	if err != nil {
		return err
	}
	rep, err := s.run(signalContext(), s.options(fs.Args()))
	if err != nil {
		return err
	}
	bom.Services = toServices(rep)
	if err := writeJSON(*out, bom); err != nil {
		return err
	}
	return exitWith(rep)
}

func cmdAttach(args []string) error {
	fs := flag.NewFlagSet("attach", flag.ExitOnError)
	s := newSession(fs, false)
	name := fs.String("name", "", "attach to every process with this name (comm or executable basename)")
	children := fs.Bool("children", true, "also follow child processes that are already running")
	duration := fs.Duration("duration", 0, "stop after this long, e.g. 30s, 5m (default: until the processes exit or Ctrl-C)")
	out := fs.String("o", "", "write the JSON report to FILE ('-' for stdout)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: secwrap attach [flags] (PID[,PID...]... | --name NAME)")
		fs.PrintDefaults()
	}
	s.parse(fs, args)

	var pids []int
	for _, a := range fs.Args() {
		for _, f := range strings.Split(a, ",") {
			pid, err := strconv.Atoi(strings.TrimSpace(f))
			if err != nil || pid <= 0 {
				return fmt.Errorf("invalid pid %q", f)
			}
			pids = append(pids, pid)
		}
	}
	if *name != "" {
		found := monitor.FindByName(*name)
		if len(found) == 0 {
			return fmt.Errorf("no process named %q", *name)
		}
		pids = append(pids, found...)
	}
	if len(pids) == 0 {
		fs.Usage()
		return errors.New("give at least one PID or --name")
	}
	if err := monitor.CheckAlive(pids); err != nil {
		return err
	}

	ctx := signalContext()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}
	o := s.options(nil)
	o.PIDs, o.FollowExisting = pids, *children
	if err := o.Validate(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "secwrap: attaching to %v (children=%v); Ctrl-C to stop\n", pids, *children)
	rep, err := s.run(ctx, o)
	if err != nil {
		return err
	}
	if *out != "" {
		return writeJSON(*out, rep)
	}
	return nil
}

// signalContext is cancelled by Ctrl-C or SIGTERM. The process exits soon
// after, so the stop function is not needed.
func signalContext() context.Context {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	return ctx
}

func exitWith(rep *monitor.Report) error {
	if rep.ExitCode != nil && *rep.ExitCode != 0 {
		os.Exit(*rep.ExitCode)
	}
	return nil
}

// chownToInvoker hands files created under sudo back to the real user.
// invoker is the user who ran sudo, while we run as root; nil otherwise.
// Files secwrap writes for them (history, SBOMs, logs) are given to them.
func invoker() *user.User {
	if os.Geteuid() != 0 {
		return nil
	}
	return monitor.SudoUser()
}

func invokerIDs() (uid, gid int, ok bool) {
	u := invoker()
	if u == nil {
		return 0, 0, false
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	return uid, gid, err1 == nil && err2 == nil
}

func chownToInvoker(f *os.File) {
	if uid, gid, ok := invokerIDs(); ok {
		_ = f.Chown(uid, gid)
	}
}

// chownPathToInvoker gives a directory secwrap just created to the invoker.
func chownPathToInvoker(dir string) {
	if uid, gid, ok := invokerIDs(); ok {
		_ = os.Lchown(dir, uid, gid)
	}
}

// chownInvokerIn gives name inside root to the invoker.
func chownInvokerIn(root *os.Root, name string) {
	if uid, gid, ok := invokerIDs(); ok {
		_ = root.Lchown(name, uid, gid)
	}
}

// toServices maps observed endpoints to CycloneDX services, one per peer.
func toServices(rep *monitor.Report) []sbom.Service {
	var svcs []sbom.Service
	for i, ep := range rep.Endpoints {
		endpoint := fmt.Sprintf("%s://%s", ep.Proto, ep.Remote)
		if ep.Direction == monitor.Inbound {
			endpoint = fmt.Sprintf("%s://0.0.0.0:%d", ep.Proto, ep.LocalPort)
		}
		svcs = append(svcs, sbom.Service{
			BOMRef:    "service-" + strconv.Itoa(i),
			Name:      fmt.Sprintf("%s %s %s", ep.Direction, ep.Proto, ep.Remote),
			Endpoints: []string{endpoint},
			Properties: []sbom.Property{
				{Name: "secwrap:net:direction", Value: string(ep.Direction)},
				{Name: "secwrap:net:peer", Value: ep.Remote},
				{Name: "secwrap:net:count", Value: strconv.Itoa(ep.Count)},
				{Name: "secwrap:net:firstSeen", Value: ep.FirstSeen.UTC().Format("2006-01-02T15:04:05.000Z")},
				{Name: "secwrap:net:processes", Value: strings.Join(ep.Comms, ",")},
				{Name: "secwrap:net:blocked", Value: strconv.FormatBool(ep.Blocked)},
			},
		})
	}
	return svcs
}
