package main

// Sessions: every monitoring session registers itself in a folder, and its
// questions (--ask) are answered through files there, so another secwrap
// (session attach, the --web page) can answer them without a connection to it:
//
//	/var/lib/secwrap/sessions/<id>/   root:invoker 0750
//	  session.json     what it is: command, user, ask mode, folders, end
//	  lock             flock-ed by the session while it runs
//	  asks/<n>.json    every question and its status (the web page's items)
//	  answers/         root only 0700: {"allow":..} or {"forget":true} as <n>.json
//	  hidden           present: not on the web page
//
// answers/ is root's alone on purpose: the monitored command runs as the
// invoking user, and must not be able to answer its own questions.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/noboruma/secwrap/internal/monitor"
)

// errAnsweredElsewhere cancels a terminal question answered through the
// session files.
var errAnsweredElsewhere = errors.New("answered through the session files")

func sessionsDir() string {
	if d := os.Getenv("SECWRAP_SESSIONS"); d != "" {
		return d
	}
	return "/var/lib/secwrap/sessions" // kept across reboots: dead sessions stay viewable
}

type sessionInfo struct {
	ID       string     `json:"id"`
	PID      int        `json:"pid"`
	User     string     `json:"user"`            // who started it
	RunAs    string     `json:"runAs,omitempty"` // --user: who the command runs as
	Target   string     `json:"target"`          // what is watched: the command, attach PIDs, all
	Watch    []string   `json:"watch"`           // net, filesystem, exec
	Ask      string     `json:"ask"`             // "" (record), deny, ask (older: session, tty, inline, detached)
	Started  time.Time  `json:"started"`
	Ended    *time.Time `json:"ended,omitempty"`
	ExitCode *int       `json:"exitCode,omitempty"`
	History  string     `json:"history,omitempty"` // the history folder
	SBOMs    string     `json:"sboms,omitempty"`   // the SBOM folder
}

// answerFile is what a client writes to answers/<n>.json.
type answerFile struct {
	Allow  *bool  `json:"allow,omitempty"`
	Host   bool   `json:"host,omitempty"` // network: any port of this IP (allow), or never this IP (deny)
	Dir    string `json:"dir,omitempty"`  // file: everything under it
	Forget bool   `json:"forget,omitempty"`
}

// stampedName is <date>-<time>-<name>: how sessions are named.
func stampedName(name string) string {
	return time.Now().Format("20060102-150405") + "-" + safeName(name)
}

// mkUniqueDir creates base in root (else base-2, base-3...) and returns its
// name.
func mkUniqueDir(root *os.Root, base string, perm os.FileMode) (string, error) {
	dir := base
	for i := 2; ; i++ {
		err := root.Mkdir(dir, perm)
		if err == nil {
			return dir, nil
		}
		if !os.IsExist(err) || i > 100 {
			return "", err
		}
		dir = fmt.Sprintf("%s-%d", base, i)
	}
}

// writeFileAtomic replaces name in root with v as JSON.
func writeFileAtomic(root *os.Root, name string, v any, perm os.FileMode) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(name), "."+filepath.Base(name)+".tmp")
	if err := root.WriteFile(tmp, append(b, '\n'), perm); err != nil {
		return err
	}
	return root.Rename(tmp, name)
}

// lockHeld reports whether someone holds a flock on path.
func lockHeld(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
	if err == nil {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return false
	}
	return errors.Is(err, syscall.EWOULDBLOCK)
}

// ---------------------------------------------------------------------------
// The session side

type liveSession struct {
	dir  string
	root *os.Root
	lock *os.File

	mu   sync.Mutex
	info sessionInfo
}

// chownGroup gives name to root:<the invoker's group>, which may read it.
func (ls *liveSession) chownGroup(name string) {
	if _, gid, ok := invokerIDs(); ok {
		_ = ls.root.Chown(name, 0, gid)
	}
}

// createSession registers a new session named after name.
func createSession(name string, info sessionInfo) (*liveSession, error) {
	base := sessionsDir()
	if err := os.MkdirAll(base, 0o755); err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	parent, err := os.OpenRoot(base)
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	defer parent.Close()
	id, err := mkUniqueDir(parent, stampedName(name), 0o750)
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	if _, gid, ok := invokerIDs(); ok {
		_ = parent.Chown(id, 0, gid)
	}
	root, err := parent.OpenRoot(id)
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	ls := &liveSession{dir: filepath.Join(base, id), root: root}
	if err := root.Mkdir("asks", 0o750); err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	ls.chownGroup("asks")
	if err := root.Mkdir("answers", 0o700); err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	ls.lock, err = root.OpenFile("lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	if err := syscall.Flock(int(ls.lock.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("session: lock: %w", err)
	}
	info.ID, info.PID, info.Started, info.User = id, os.Getpid(), time.Now(), os.Getenv("USER")
	if u := invoker(); u != nil {
		info.User = u.Username
	}
	ls.info = info
	if err := ls.writeInfo(); err != nil {
		return nil, err
	}
	return ls, nil
}

func (ls *liveSession) update(f func(*sessionInfo)) {
	ls.mu.Lock()
	f(&ls.info)
	ls.mu.Unlock()
	if err := ls.writeInfo(); err != nil {
		fmt.Fprintf(os.Stderr, "secwrap: session: %v\n", err)
	}
}

func (ls *liveSession) writeInfo() error {
	ls.mu.Lock()
	info := ls.info
	ls.mu.Unlock()
	if err := writeFileAtomic(ls.root, "session.json", info, 0o640); err != nil {
		return fmt.Errorf("session: %w", err)
	}
	ls.chownGroup("session.json")
	return nil
}

// end records the end of the session and releases its lock.
func (ls *liveSession) end(rep *monitor.Report) {
	now := time.Now()
	ls.update(func(i *sessionInfo) {
		i.Ended = &now
		if rep != nil {
			i.ExitCode = rep.ExitCode
		}
	})
	ls.lock.Close() // releases the flock
	ls.root.Close()
}

// pendingAsk is a published question and what only the session holds.
type pendingAsk struct {
	*webItem
	answer chan monitor.AskAnswer // the answer from the files (or close's deny)
	forget func() error           // undoes the answer (Forget)
}

// sessionAsker publishes every question to asks/ and takes answers from
// answers/, racing the terminal asker when there is one (inner).
type sessionAsker struct {
	ls    *liveSession
	inner func(context.Context, monitor.AskRequest) monitor.AskAnswer

	mu     sync.Mutex
	nextID int
	items  map[int]*pendingAsk

	stop chan struct{}
	done chan struct{}
}

func newSessionAsker(ls *liveSession, inner func(context.Context, monitor.AskRequest) monitor.AskAnswer) *sessionAsker {
	a := &sessionAsker{ls: ls, inner: inner, items: map[int]*pendingAsk{}, stop: make(chan struct{}), done: make(chan struct{})}
	go a.poll()
	return a
}

func (a *sessionAsker) publish(p *pendingAsk) {
	a.mu.Lock()
	cp := *p.webItem
	a.mu.Unlock()
	name := fmt.Sprintf("asks/%d.json", cp.ID)
	if err := writeFileAtomic(a.ls.root, name, cp, 0o640); err != nil {
		fmt.Fprintf(os.Stderr, "secwrap: session: %v\n", err)
		return
	}
	a.ls.chownGroup(name)
}

// settle sets the status of a question still pending; false if it was
// answered from the files meanwhile.
func (a *sessionAsker) settle(p *pendingAsk, status, folder string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if p.Status != stPending {
		return false
	}
	p.Status, p.Folder = status, folder
	return true
}

func (a *sessionAsker) ask(ctx context.Context, r monitor.AskRequest) monitor.AskAnswer {
	a.mu.Lock()
	a.nextID++
	p := &pendingAsk{webItem: newItem(a.nextID, r), answer: make(chan monitor.AskAnswer, 1), forget: r.Forget}
	a.items[p.ID] = p
	a.mu.Unlock()
	a.publish(p)

	ictx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	innerCh := make(chan monitor.AskAnswer, 1)
	if a.inner != nil {
		go func() {
			ans := a.inner(ictx, r)
			if ictx.Err() == nil {
				innerCh <- ans
			}
		}()
	} else {
		fmt.Fprintf(os.Stderr, "[ask] #%d pid=%d %s %s: waiting (secwrap session attach %s)\n",
			p.ID, r.PID, r.Comm, p.describe(), a.ls.info.ID)
	}

	select {
	case ans := <-p.answer: // from the files; status already set
		cancel(errAnsweredElsewhere)
		return ans
	case ans := <-innerCh:
		status := stDenied
		if ans.Decision == monitor.AllowEndpoint || ans.Decision == monitor.AllowHost {
			status = stAllowed
		}
		if !a.settle(p, status, ans.Dir) {
			return <-p.answer
		}
		a.publish(p)
		return ans
	case <-ctx.Done():
		status := stGone
		if context.Cause(ctx) == monitor.ErrCoveredByRule {
			status = stCovered
		}
		if !a.settle(p, status, "") {
			return <-p.answer
		}
		a.publish(p)
		return monitor.Answer(monitor.DenyEndpoint)
	}
}

// poll applies the answers clients drop in answers/.
func (a *sessionAsker) poll() {
	defer close(a.done)
	t := time.NewTicker(150 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-t.C:
		}
		d, err := a.ls.root.Open("answers")
		if err != nil {
			continue
		}
		names, _ := d.Readdirnames(-1)
		d.Close()
		for _, n := range names {
			if strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".json") {
				continue
			}
			b, err := a.ls.root.ReadFile("answers/" + n)
			_ = a.ls.root.Remove("answers/" + n)
			id, err2 := strconv.Atoi(strings.TrimSuffix(n, ".json"))
			var af answerFile
			if err != nil || err2 != nil || json.Unmarshal(b, &af) != nil {
				continue
			}
			a.apply(id, af)
		}
	}
}

func (a *sessionAsker) apply(id int, af answerFile) {
	a.mu.Lock()
	p := a.items[id]
	if p == nil {
		a.mu.Unlock()
		return
	}
	if af.Forget {
		if (p.Status != stAllowed && p.Status != stDenied) || p.forget == nil {
			a.mu.Unlock()
			return
		}
		p.Status = stForgotten
		forget := p.forget
		a.mu.Unlock()
		if err := forget(); err != nil {
			fmt.Fprintf(os.Stderr, "secwrap: forget #%d: %v\n", id, err)
		}
		a.publish(p)
		return
	}
	ans, ok := p.decision(af)
	if p.Status != stPending || af.Allow == nil || !ok {
		a.mu.Unlock()
		return
	}
	p.Status, p.Folder = stDenied, ans.Dir
	if *af.Allow {
		p.Status = stAllowed
	}
	p.answer <- ans
	a.mu.Unlock()
	a.publish(p)
}

// close stops taking answers; questions still pending are marked gone and
// denied (their ask returns at once).
func (a *sessionAsker) close() {
	close(a.stop)
	<-a.done
	a.mu.Lock()
	var left []*pendingAsk
	for _, p := range a.items {
		if p.Status == stPending {
			p.Status = stGone
			p.answer <- monitor.Answer(monitor.DenyEndpoint)
			left = append(left, p)
		}
	}
	a.mu.Unlock()
	for _, p := range left {
		a.publish(p)
	}
}

// ---------------------------------------------------------------------------
// The client side: session list, attach, the web page

type sessionView struct {
	sessionInfo
	Dir     string
	Running bool
	Pending int // questions waiting (0 when dead)
	Hidden  bool
}

// listSessions reads every session this user may see, oldest first.
func listSessions() ([]sessionView, error) {
	base := sessionsDir()
	ents, err := os.ReadDir(base)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []sessionView
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		v, err := readSession(filepath.Join(base, e.Name()), true)
		if err != nil {
			continue // another user's, or being created
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out, nil
}

// readSession reads a session record; countPending also counts the
// questions waiting (a read of every asks/ file of an alive session).
func readSession(dir string, countPending bool) (sessionView, error) {
	var v sessionView
	b, err := os.ReadFile(filepath.Join(dir, "session.json"))
	if err != nil {
		return v, err
	}
	if err := json.Unmarshal(b, &v.sessionInfo); err != nil {
		return v, err
	}
	v.Dir = dir
	v.Running = lockHeld(filepath.Join(dir, "lock"))
	_, err = os.Lstat(filepath.Join(dir, "hidden"))
	v.Hidden = err == nil
	if countPending && v.Running {
		items, _ := v.asks()
		for _, it := range items {
			if it.Status == stPending {
				v.Pending++
			}
		}
	}
	return v, nil
}

// asks returns the session's questions, newest first. In a dead session
// nothing waits any more: pending ones are reported gone.
func (v sessionView) asks() ([]webItem, error) {
	root, err := os.OpenRoot(filepath.Join(v.Dir, "asks"))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	d, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return nil, err
	}
	var out []webItem
	for _, n := range names {
		if strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".json") {
			continue
		}
		if it, err := readItem(root, n); err == nil {
			out = append(out, v.normalize(it))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// ask returns one question of the session.
func (v sessionView) ask(id int) (webItem, error) {
	root, err := os.OpenRoot(filepath.Join(v.Dir, "asks"))
	if err != nil {
		return webItem{}, err
	}
	defer root.Close()
	it, err := readItem(root, strconv.Itoa(id)+".json")
	return v.normalize(it), err
}

func readItem(root *os.Root, name string) (webItem, error) {
	var it webItem
	b, err := root.ReadFile(name)
	if err == nil {
		err = json.Unmarshal(b, &it)
	}
	return it, err
}

func (v sessionView) normalize(it webItem) webItem {
	if !v.Running && it.Status == stPending {
		it.Status = stGone
	}
	return it
}

// writeAnswer drops an answer for question id of the session in dir.
func writeAnswer(dir string, id int, af answerFile) error {
	root, err := os.OpenRoot(filepath.Join(dir, "answers"))
	if err != nil {
		if os.IsPermission(err) {
			return errors.New("answering needs root: run it with sudo")
		}
		return err
	}
	defer root.Close()
	b, _ := json.Marshal(af)
	tmp := fmt.Sprintf(".%d.%d.tmp", id, time.Now().UnixNano())
	if err := root.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return root.Rename(tmp, fmt.Sprintf("%d.json", id))
}

// findSession resolves an ID, a unique part of one, or a number from the
// list (1 = oldest). With no argument: the only alive session that asks.
func findSession(arg string) (sessionView, error) {
	list, err := listSessions()
	if err != nil {
		return sessionView{}, err
	}
	if arg == "" {
		var asking []sessionView
		for _, v := range list {
			if v.Running && v.Ask != "" && v.Ask != "deny" {
				asking = append(asking, v)
			}
		}
		switch len(asking) {
		case 1:
			return asking[0], nil
		case 0:
			return sessionView{}, errors.New("no alive session asks questions (secwrap session list)")
		}
		return sessionView{}, errors.New("several sessions ask questions: name one (secwrap session list)")
	}
	if n, err := strconv.Atoi(arg); err == nil && n >= 1 && n <= len(list) && len(arg) < 6 {
		return list[n-1], nil
	}
	var match []sessionView
	for _, v := range list {
		if v.ID == arg {
			return v, nil
		}
		if strings.Contains(v.ID, arg) {
			match = append(match, v)
		}
	}
	switch len(match) {
	case 1:
		return match[0], nil
	case 0:
		return sessionView{}, fmt.Errorf("no session %q (secwrap session list)", arg)
	}
	return sessionView{}, fmt.Errorf("%q matches %d sessions: be more precise", arg, len(match))
}

// state is "alive" (its command runs) or "dead".
func (v sessionView) state() string {
	if v.Running {
		return "alive"
	}
	return "dead"
}

// stateDetail says since when an alive session runs, or how a dead one ended.
func (v sessionView) stateDetail() string {
	switch {
	case v.Running:
		return "since " + v.Started.Format("15:04")
	case v.Ended != nil:
		d := ""
		if v.ExitCode != nil {
			d = fmt.Sprintf("exit %d, ", *v.ExitCode)
		}
		return d + ago(*v.Ended)
	}
	return "crashed (no end recorded)"
}

func ago(t time.Time) string {
	d := time.Since(t).Round(time.Minute)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return t.Format("2006-01-02")
}

func (v sessionView) askLabel() string {
	if v.Ask == "" {
		return "record"
	}
	return v.Ask
}

// userLabel is who started the session, and who its command runs as when
// that is someone else (--user).
func (v sessionView) userLabel() string {
	if v.RunAs != "" && v.RunAs != v.User {
		return v.User + "→" + v.RunAs
	}
	return v.User
}

// setHidden takes the session off the web page, or puts it back.
func setHidden(v sessionView, hide bool) error {
	p := filepath.Join(v.Dir, "hidden")
	var err error
	if hide {
		err = os.WriteFile(p, nil, 0o644)
	} else if err = os.Remove(p); os.IsNotExist(err) {
		err = nil
	}
	if os.IsPermission(err) {
		return errors.New("changing the web page needs root")
	}
	return err
}

// deleteSession removes the record of a dead session (its history folder
// stays).
func deleteSession(v sessionView) error {
	if v.Running {
		return fmt.Errorf("%s is alive: only dead sessions can be deleted", v.ID)
	}
	if filepath.Dir(v.Dir) != filepath.Clean(sessionsDir()) {
		return fmt.Errorf("%s: not a session folder", v.Dir)
	}
	if err := os.RemoveAll(v.Dir); err != nil {
		if os.IsPermission(err) {
			return errors.New("deleting needs root: run it with sudo")
		}
		return err
	}
	return nil
}
