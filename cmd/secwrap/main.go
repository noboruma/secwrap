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
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/noboruma/secwrap/internal/monitor"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == monitor.AskHelperArg {
		monitor.RunAskHelper(os.Args[2:]) // never returns
	}
	if len(os.Args) > 1 && os.Args[1] == envCleanupArg {
		runEnvCleaner(os.Args[2:]) // never returns
	}
	if len(os.Args) > 1 && os.Args[1] == invokerEnvArg { // re-run through sudo by elevate
		rest, err := takeInvokerEnv(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, "secwrap:", err)
			os.Exit(1)
		}
		os.Args = append(os.Args[:1], rest...)
	}
	cmds := map[string]func([]string) error{
		"attach": cmdAttach, "shell": cmdShell, "sessions": cmdSession, "vacuum": cmdVacuum, "cap": cmdCap,
	}
	name := ""
	if len(os.Args) > 1 {
		name = os.Args[1]
	}
	cmd, args := cmds[name], os.Args[min(2, len(os.Args)):]
	switch {
	case name == "-h" || name == "-help" || name == "--help" || name == "help":
		fmt.Fprint(os.Stderr, usageCommands+"\n")
		cmdRun([]string{"-h"}) // every flag; exits
		return
	case cmd == nil && strings.HasPrefix(name, "-"): // secwrap [flags] -- CMD
		cmd, args = cmdRun, os.Args[1:]
	case cmd == nil:
		usage()
		os.Exit(2)
	}
	if err := elevate(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "secwrap:", err)
		os.Exit(1)
	}
	if err := cmd(args); err != nil {
		fmt.Fprintln(os.Stderr, "secwrap:", err)
		os.Exit(1)
	}
}

func usage() { fmt.Fprint(os.Stderr, usageCommands+usageFlags) }

const usageCommands = `secwrap: run a command or a shell under eBPF watch: record, block, or ask before network and file access

  secwrap [flags] -- CMD ...                    run CMD and watch it and its children
  secwrap attach  [flags] (PID... | --name N)   monitor running processes and their children
  secwrap shell   [flags] [-- SHELL ...]        shell where everything you run is monitored
  secwrap sessions                              sessions alive and dead in a terminal UI: attach, delete
  secwrap vacuum  [--older-than 30d]            delete dead sessions' records and history older than 30 days
  secwrap cap                                   what this kernel supports: network, filesystem, exec, sbom
  secwrap sessions list | attach [ID] | delete ID
                                               list; answer one's questions here (root); delete dead ones
`

const usageFlags = `
What to watch, and what to do with each: off, log, ask or deny; bare, ask (shell: --net --fs):
  --net [MODE]          network: TCP connect/accept, UDP sends
  --fs [MODE]           file opens (BPF LSM); deny/ask: writes and sensitive reads
  --exec [MODE]         programs executed (BPF LSM); deny/ask: every exec but CMD
  --sbom [DIR]          a CycloneDX SBOM in DIR (default: the history folder) for every binary executed
  --deny-all            categories without a mode are denied (default: ask; attach: log)
  --log-only            categories without a mode are logged, nothing is asked (scripts, CI)
  --no-inline           don't ask in the terminal (the web page and secwrap sessions attach always can)
  --web-addr ADDR       serve every session's web page at ADDR (default 127.0.0.1:9000; 9000, :9000, 0.0.0.0:9100)
                        unless a secwrap already serves that address; one host per address, all show every session
  --no-web              don't serve it
  --allow rwx:DIR       with deny/ask: allow reads/writes/execs under DIR (repeatable)
  --log FILE|off        live events to FILE (JSON lines if *.json/*.jsonl) instead of stderr
Every flag: secwrap --help; for attach and shell: secwrap attach -h, secwrap shell -h.
`

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

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("secwrap", flag.ExitOnError)
	s := newSession(fs, true)
	out := fs.String("o", "", "write the JSON report to FILE ('-' for stdout)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: secwrap [flags] -- CMD [ARGS...]")
		fs.PrintDefaults()
	}
	s.parse(fs, args)
	if fs.NArg() == 0 {
		fs.Usage()
		return errors.New("no command given: secwrap [flags] -- CMD")
	}
	rep, err := s.run(signalContext(), s.options(fs.Args()))
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

func cmdAttach(args []string) error {
	fs := flag.NewFlagSet("attach", flag.ExitOnError)
	s := newSession(fs, false)
	name := fs.String("name", "", "attach to every process with this name (comm or executable basename)")
	allowAsk := fs.Bool("allow-ask", false, "allow ask mode (--net/--fs/--exec ask) on attach; the attached\n"+
		"processes are left unable to gain privileges afterwards (sudo, setuid)")
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
	o.PIDs, o.AllowAsk = pids, *allowAsk
	if err := o.Validate(); err != nil {
		return err
	}
	if o.Asks() {
		// Ask on attach needs a seccomp listener per running process
		// (Options.AskListeners), and nothing supplies them yet.
		return errors.New("secwrap attach: ask mode on attach is not available in this build (--allow-ask is accepted, but pausing a running process's syscalls is not yet implemented)")
	}
	fmt.Fprintf(os.Stderr, "secwrap: attaching to %v and their children; Ctrl-C to stop\n", pids)
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
