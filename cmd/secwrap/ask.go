package main

// A question (--ask) as the session files, the web page and the prompts
// show it, the prompt that both --ask tty and secwrap session attach use,
// and the terminal asker.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/noboruma/secwrap/internal/monitor"
)

// Question statuses (asks/<n>.json, the web page's badges).
const (
	stPending   = "pending"
	stAllowed   = "allowed"
	stDenied    = "denied"
	stGone      = "gone"      // the asking process went away (or the session ended)
	stCovered   = "covered"   // allowed meanwhile by a folder rule
	stForgotten = "forgotten" // its answer was undone: the next such call asks again
)

type webItem struct {
	ID        int       `json:"id"`
	Time      time.Time `json:"time"`
	PID       int       `json:"pid"`
	Comm      string    `json:"comm"`
	Kind      string    `json:"kind"`
	Proto     string    `json:"proto"`
	Remote    string    `json:"remote,omitempty"`
	Path      string    `json:"path,omitempty"`
	Access    string    `json:"access,omitempty"` // file: read (sensitive) | write | exec
	Sensitive bool      `json:"sensitive,omitempty"`
	Dirs      []string  `json:"dirs,omitempty"`   // file: folders a folder rule may use
	Args      []string  `json:"args,omitempty"`   // exec: command line
	Folder    string    `json:"folder,omitempty"` // allowed through this folder rule
	Status    string    `json:"status"`           // st*
}

func newItem(id int, r monitor.AskRequest) *webItem {
	it := &webItem{ID: id, Time: time.Now(), PID: r.PID, Comm: r.Comm, Kind: r.Kind, Proto: r.Proto, Status: stPending}
	if r.IsFile() {
		it.Path, it.Dirs, it.Args, it.Sensitive = r.Path, monitor.Ancestors(r.Path), r.Args, r.Sensitive
		switch {
		case r.IsExec():
			it.Access = "exec"
		case r.Write:
			it.Access = "write"
		default:
			it.Access = "read"
		}
	} else {
		it.Remote = r.Remote.String()
	}
	return it
}

func (it webItem) isFile() bool { return it.Path != "" }

// verb and what make "WRITE /path", "EXEC /usr/bin/curl (curl -s …)".
func (it webItem) verb() string {
	switch it.Access {
	case "exec":
		return "EXEC"
	case "write":
		return "WRITE"
	}
	return "READ (sensitive)"
}

func (it webItem) what() string {
	if len(it.Args) == 0 {
		return it.Path
	}
	cmd := strings.Join(it.Args, " ")
	if len(cmd) > 160 {
		cmd = cmd[:160] + "…"
	}
	return fmt.Sprintf("%s (%s)", it.Path, cmd)
}

// describe is the question on one line, for logs.
func (it webItem) describe() string {
	if it.isFile() {
		return it.verb() + " " + it.what()
	}
	return fmt.Sprintf("%s %s -> %s", orQ(it.Proto), it.Kind, it.Remote)
}

func orQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

// decision turns an answer into what the monitor applies. ok=false: not an
// answer to this question (a folder that is not one of its folders).
func (it webItem) decision(af answerFile) (a monitor.AskAnswer, ok bool) {
	allow := af.Allow != nil && *af.Allow
	switch {
	case allow && af.Dir != "":
		if !it.isFile() || !slices.Contains(it.Dirs, af.Dir) {
			return a, false
		}
		return monitor.AskAnswer{Decision: monitor.AllowEndpoint, Dir: af.Dir}, true
	case af.Host && !it.isFile() && allow:
		return monitor.Answer(monitor.AllowHost), true
	case af.Host && !it.isFile():
		return monitor.Answer(monitor.DenyHost), true
	case allow:
		return monitor.Answer(monitor.AllowEndpoint), true
	}
	return monitor.Answer(monitor.DenyEndpoint), true
}

// ---------------------------------------------------------------------------
// The prompt

// readResult is what reading an answer line gave.
type readResult int

const (
	gotLine readResult = iota
	gotVoid            // the question stopped waiting meanwhile
	gotQuit            // q or EOF (detach)
)

// prompt asks it on w until a valid answer, reading lines with read.
// quitHint adds "q = detach" to the help (secwrap session attach).
func prompt(w io.Writer, it webItem, read func() (string, readResult), quitHint bool) (*answerFile, readResult) {
	yes, no := true, false
	help := "Enter = no"
	if quitHint {
		help += ", q = detach"
	}
	num := ""
	if it.ID > 0 {
		num = fmt.Sprintf(" #%d", it.ID)
	}
	for {
		if it.isFile() {
			fmt.Fprintf(w, "\n[ask%s] Allow %s (pid %d) to %s %s? [y/N/f]  (f = every %s under a folder) ",
				num, it.Comm, it.PID, it.verb(), it.what(), it.Access)
		} else {
			fmt.Fprintf(w, "\n[ask%s] Allow %s (pid %d) %s %s to %s? [y/N]  (Y = any port on this IP, D = never this IP) ",
				num, it.Comm, it.PID, orQ(it.Proto), it.Kind, it.Remote)
		}
		line, r := read()
		if r != gotLine {
			return nil, r
		}
		switch {
		case line == "y" || line == "yes":
			return &answerFile{Allow: &yes}, gotLine
		case line == "" || line == "n" || line == "N" || line == "no":
			return &answerFile{Allow: &no}, gotLine
		case it.isFile() && line == "f":
			dir, r := pickFolder(w, it, read)
			if r != gotLine {
				return nil, r
			}
			if dir != "" {
				return &answerFile{Allow: &yes, Dir: dir}, gotLine
			}
			continue // asked again
		case !it.isFile() && line == "Y":
			return &answerFile{Allow: &yes, Host: true}, gotLine
		case !it.isFile() && line == "D":
			return &answerFile{Allow: &no, Host: true}, gotLine
		}
		if it.isFile() {
			fmt.Fprintf(w, "      answer y, n or f (%s)\n", help)
		} else {
			fmt.Fprintf(w, "      answer y, n, Y or D (%s)\n", help)
		}
	}
}

// pickFolder lists the folders of it.Path and reads a number (Enter = the
// parent) or a folder path. "" goes back to the main question.
func pickFolder(w io.Writer, it webItem, read func() (string, readResult)) (string, readResult) {
	if len(it.Dirs) == 0 {
		fmt.Fprintln(w, "      no folder to offer (files directly under / need a per-file answer)")
		return "", gotLine
	}
	fmt.Fprintf(w, "      allow every %s under:\n", it.Access)
	for i, d := range it.Dirs {
		fmt.Fprintf(w, "        %d) %s\n", i+1, d)
	}
	fmt.Fprint(w, "      folder [1, or a path, b = back]: ")
	line, r := read()
	switch {
	case r != gotLine || line == "b":
		return "", r
	case line == "":
		return it.Dirs[0], gotLine
	}
	if n, err := strconv.Atoi(line); err == nil && n >= 1 && n <= len(it.Dirs) {
		return it.Dirs[n-1], gotLine
	}
	if i := slices.Index(it.Dirs, filepath.Clean(line)); i >= 0 {
		return it.Dirs[i], gotLine
	}
	fmt.Fprintln(w, "      not one of the folders above")
	return "", gotLine
}

// ---------------------------------------------------------------------------
// --answer inline

// ttyAsker asks on the controlling terminal (not stdin, which belongs to the
// target), one question at a time. Anything but yes, or no terminal, denies.
//
// The terminal is shared with the target (and in secwrap shell, owned by
// the shell), so for each question it is borrowed: the target's tree is
// frozen (AskRequest.Freeze) so nothing else reads the keyboard, secwrap's
// process group takes the foreground, the line discipline is set to cooked
// mode (the target may have left it raw), and all of it is put back after.
// The keyboard is read only while a question is up.
type ttyAsker struct {
	sem  chan struct{} // one question at a time
	once sync.Once
	tty  *os.File
	fd   int // tty's (not tty.Fd(), which would make reads blocking: no deadlines)
	br   *bufio.Reader
	err  error

	// needFreeze: without AskRequest.Freeze, don't touch the terminal and
	// leave the question to the web page and attach. secwrap shell sets it:
	// taking the terminal from a shell reading its prompt, unfrozen, could
	// hand it the answer, or make its next read fail and the shell exit.
	needFreeze bool
	warnOnce   sync.Once
}

func newTTYAsker() *ttyAsker { return &ttyAsker{sem: make(chan struct{}, 1)} }

func (t *ttyAsker) open() {
	t.tty, t.err = os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if t.err != nil {
		return
	}
	t.br = bufio.NewReader(t.tty)
	rc, err := t.tty.SyscallConn()
	if err == nil {
		err = rc.Control(func(fd uintptr) { t.fd = int(fd) })
	}
	if err != nil {
		t.tty.Close()
		t.err = err
	}
}

// borrow takes the terminal for one question; give it back with the
// returned function.
func (t *ttyAsker) borrow(r monitor.AskRequest) (giveBack func()) {
	thaw := func() {}
	if r.Freeze != nil {
		thaw = r.Freeze()
	}
	fd := t.fd
	oldFg, fgErr := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	me := unix.Getpgrp()
	tookFg := false
	if fgErr == nil && oldFg != me {
		// From the background, TIOCSPGRP raises SIGTTOU unless it is ignored.
		signal.Ignore(syscall.SIGTTOU)
		tookFg = unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, me) == nil
		signal.Reset(syscall.SIGTTOU)
	}
	// Drop typed-ahead input: it was not typed for this question, and the
	// tree may have pushed it in (TIOCSTI) before asking; frozen, it can't now.
	unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
	t.br.Reset(t.tty)
	saved, termErr := unix.IoctlGetTermios(fd, unix.TCGETS)
	if termErr == nil {
		cooked := *saved
		cooked.Iflag |= unix.ICRNL
		cooked.Oflag |= unix.OPOST | unix.ONLCR
		cooked.Lflag |= unix.ICANON | unix.ECHO | unix.ECHOE | unix.ISIG
		unix.IoctlSetTermios(fd, unix.TCSETSW, &cooked)
	}
	return func() {
		if termErr == nil {
			unix.IoctlSetTermios(fd, unix.TCSETSW, saved)
		}
		// Hand the foreground back unless someone else took it meanwhile,
		// and have its owner redraw (a shell prompt, a full-screen program).
		if cur, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP); tookFg && err == nil && cur == me {
			if unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, oldFg) == nil {
				defer unix.Kill(-oldFg, unix.SIGWINCH)
			}
		}
		thaw()
	}
}

// ask is the inner asker of sessionAsker: ctx ends when the question is
// answered elsewhere, covered by a folder rule, or its process is gone.
func (t *ttyAsker) ask(ctx context.Context, r monitor.AskRequest) monitor.AskAnswer {
	deny := monitor.Answer(monitor.DenyEndpoint)
	select {
	case t.sem <- struct{}{}:
	case <-ctx.Done():
		return deny
	}
	defer func() { <-t.sem }()

	t.once.Do(t.open)
	if t.err != nil {
		fmt.Fprintf(os.Stderr, "secwrap: --answer inline: no terminal (%v), denying\n", t.err)
		return deny
	}
	if t.needFreeze && r.Freeze == nil {
		t.warnOnce.Do(func() {
			fmt.Fprintln(os.Stderr, "secwrap: inline questions need Linux 5.19+ and cgroup v2 here; answer on the web page or with secwrap session attach")
		})
		<-ctx.Done()
		return deny
	}
	defer t.borrow(r)()

	// Read lines only while this question is up; a deadline interrupts the
	// read when it ends (answered elsewhere, or answered here).
	lines := make(chan string)
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		defer close(lines)
		for {
			line, err := t.br.ReadString('\n')
			if err != nil {
				return
			}
			select {
			case lines <- strings.TrimSpace(line):
			case <-stop:
				return
			}
		}
	}()
	defer func() {
		close(stop)
		if t.tty.SetReadDeadline(time.Now()) == nil {
			<-readerDone
			t.tty.SetReadDeadline(time.Time{})
		}
	}()

	read := func() (string, readResult) {
		select {
		case <-ctx.Done():
			switch context.Cause(ctx) {
			case monitor.ErrCoveredByRule:
				fmt.Fprintln(t.tty, "\n      (allowed by a folder rule)")
			case errAnsweredElsewhere:
				fmt.Fprintln(t.tty, "\n      (answered from secwrap session or its web page)")
			default:
				fmt.Fprintln(t.tty, "\n      (process gone, question dropped)")
			}
			return "", gotVoid
		case line, ok := <-lines:
			if !ok {
				return "", gotVoid
			}
			return line, gotLine
		}
	}
	it := newItem(0, r)
	af, res := prompt(t.tty, *it, read, false)
	if res != gotLine {
		return deny
	}
	a, _ := it.decision(*af) // the prompt only offers it.Dirs
	return a
}
