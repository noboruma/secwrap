package main

// secwrap shell: an interactive shell whose whole process tree is
// monitored. Everything typed in it runs as a child of the shell, so it is
// followed by the fork hook, stays in the deny cgroup and inherits the
// seccomp filter. Questions are asked inline: the shell owns the terminal
// (it reads the keyboard and takes the foreground for job control), so for
// each question secwrap freezes the tree and borrows the terminal (see
// ttyAsker); they can also be answered from the web page or attach.

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
)

func cmdShell(args []string) error {
	fs := flag.NewFlagSet("shell", flag.ExitOnError)
	s := newSession(fs, true)
	out := fs.String("o", "", "write the JSON report to FILE when the shell exits ('-' for stdout)")
	// Shell defaults: network and files, asked about inline (and on the web
	// page), no live output (it would scribble over the shell; use --log
	// FILE and tail -f it). --deny alone turns asking off.
	for name, v := range map[string]string{"net": "true", "filesystem": "true", "log": "off"} {
		fs.Lookup(name).DefValue = v
		fs.Set(name, v)
	}
	s.askOn, s.defAnswer, s.shell = true, "inline", true
	fs.Lookup("ask").DefValue, fs.Lookup("answer").DefValue = "on", "inline"
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: secwrap shell [flags] [-- SHELL [ARGS...]]")
		fs.PrintDefaults()
	}
	s.parse(fs, args)

	argv, cleanup, err := shellCommand(fs.Args(), s.shellUID())
	if err != nil {
		return err
	}
	defer cleanup()

	// Ctrl-C belongs to the shell and its jobs. secwrap only stops on
	// SIGTERM/SIGHUP, or on Ctrl-C once the shell itself has exited (while
	// waiting for leftover background processes).
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	var shellDone atomic.Bool
	intr := make(chan os.Signal, 1)
	signal.Notify(intr, os.Interrupt, syscall.SIGQUIT)
	defer signal.Stop(intr)
	go func() {
		for range intr {
			if shellDone.Load() {
				cancel()
			}
		}
	}()

	o := s.options(argv)
	o.OnCommandExit = func() { shellDone.Store(true) }
	rep, err := s.run(ctx, o)
	if err != nil {
		return err
	}
	if *out != "" {
		return writeJSON(*out, rep)
	}
	return nil
}

// shellCommand returns the shell to run: the given command, or the user's
// login shell. bash and zsh load their usual startup files and then get a
// "(secwrap)" prompt prefix, re-applied before each prompt so themes that
// rebuild the prompt don't drop it; sh/dash get PS1.
func shellCommand(args []string, uid int) (argv []string, cleanup func(), err error) {
	cleanup = func() {}
	if len(args) > 0 {
		return args, cleanup, nil
	}
	sh := loginShell(uid)
	if isSecwrapWrapper(sh) {
		return nil, nil, fmt.Errorf("the login shell %s is a secwrap wrapper: name the real shell, e.g. secwrap shell -- /bin/zsh", sh)
	}
	os.Setenv("SECWRAP_SHELL", "1")

	// Startup files go in a temp dir read by the shell (the invoking user).
	tmpDir := func(files map[string]string) (string, error) {
		dir, err := os.MkdirTemp("", "secwrap-shell-*")
		if err != nil {
			return "", err
		}
		os.Chmod(dir, 0o755)
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				os.RemoveAll(dir)
				return "", err
			}
		}
		cleanup = func() { os.RemoveAll(dir) }
		return dir, nil
	}

	switch filepath.Base(sh) {
	case "bash":
		dir, err := tmpDir(map[string]string{"bashrc": bashRC})
		if err != nil {
			return nil, nil, err
		}
		return []string{sh, "--rcfile", filepath.Join(dir, "bashrc"), "-i"}, cleanup, nil
	case "zsh":
		dir, err := tmpDir(map[string]string{".zshenv": zshEnv, ".zshrc": zshRC})
		if err != nil {
			return nil, nil, err
		}
		os.Setenv("SECWRAP_ZDOTDIR", os.Getenv("ZDOTDIR")) // the user's own, if any
		os.Setenv("ZDOTDIR", dir)
		return []string{sh, "-i"}, cleanup, nil
	case "sh", "dash":
		os.Setenv("PS1", "(secwrap) $ ")
	}
	return []string{sh, "-i"}, cleanup, nil
}

const bashRC = `[ -f /etc/bash.bashrc ] && . /etc/bash.bashrc
[ -f ~/.bashrc ] && . ~/.bashrc
__secwrap_ps1() { case "$PS1" in "(secwrap) "*) ;; *) PS1="(secwrap) $PS1" ;; esac; }
PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND;}__secwrap_ps1"
`

// zsh reads $ZDOTDIR/.zshenv then $ZDOTDIR/.zshrc. Ours load the user's
// (from their own ZDOTDIR or $HOME) and leave ZDOTDIR pointing there, so
// history and later startup files behave as usual.
const zshEnv = `__vc_dir="$ZDOTDIR"
ZDOTDIR="${SECWRAP_ZDOTDIR:-$HOME}"
[ -f "$ZDOTDIR/.zshenv" ] && . "$ZDOTDIR/.zshenv"
__vc_user_dir="$ZDOTDIR"
ZDOTDIR="$__vc_dir"
`

const zshRC = `ZDOTDIR="$__vc_user_dir"
unset __vc_dir __vc_user_dir SECWRAP_ZDOTDIR
[ -f "$ZDOTDIR/.zshrc" ] && . "$ZDOTDIR/.zshrc"
__secwrap_prompt() { [[ "$PROMPT" == "(secwrap) "* ]] || PROMPT="(secwrap) $PROMPT"; }
precmd_functions+=(__secwrap_prompt)
__secwrap_prompt
`

// isSecwrapWrapper reports whether sh is a script that runs secwrap
// (a chsh wrapper): starting it would start secwrap again, forever.
func isSecwrapWrapper(sh string) bool {
	f, err := os.Open(sh)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 4096)
	n, _ := f.Read(head)
	return strings.HasPrefix(string(head[:n]), "#!") && strings.Contains(string(head[:n]), "secwrap")
}

// loginShell reads uid's shell from /etc/passwd ($SHELL is root's under sudo).
var loginShellOverride string

func loginShell(uid int) string {
	if loginShellOverride != "" {
		return loginShellOverride
	}
	f, err := os.Open("/etc/passwd")
	if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fl := strings.Split(sc.Text(), ":")
			if len(fl) == 7 && fl[2] == strconv.Itoa(uid) && fl[6] != "" {
				if _, err := os.Stat(fl[6]); err == nil {
					return fl[6]
				}
			}
		}
	}
	if sh := os.Getenv("SHELL"); sh != "" && uid == os.Getuid() {
		return sh
	}
	return "/bin/sh"
}

// shellUID is the user whose login shell to start: --user, else the sudo
// invoker unless --as-root, else us.
func (s *session) shellUID() int {
	if s.runAs != nil {
		if v, err := strconv.Atoi(s.runAs.Uid); err == nil {
			return v
		}
	}
	if uid, _, ok := invokerIDs(); ok && !s.asRoot {
		return uid
	}
	return os.Getuid()
}
