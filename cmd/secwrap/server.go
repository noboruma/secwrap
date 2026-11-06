package main

// The web page for every session, served from the session files by
// whichever secwrap holds the web lock: a shell (--web, its default), a
// monitor with --web, or secwrap session --web. Every one of them keeps
// trying to take the lock, so as long as one runs the page is up: when the
// host exits (or its listener dies) the next takes over within a second,
// on the same URL (the token is kept). And the terminal UI of secwrap
// session, to see sessions alive or dead, attach, choose which are on the
// web page, and delete dead ones.
//
//	/var/lib/secwrap/web.lock    flock-ed by the host
//	/var/lib/secwrap/web.json    the host's address and pid (root only)
//	/var/lib/secwrap/web.token   the URL token (root only)

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

//go:embed askweb
var askwebFS embed.FS

const (
	defaultWebAddr = "127.0.0.1:9000"
	maxWebItems    = 500 // questions listed per session
)

func stateDir() string { return filepath.Dir(sessionsDir()) }

type webInfo struct {
	Addr string `json:"addr"`
	PID  int    `json:"pid"`
}

// webToken returns the persistent URL token, creating it the first time.
func webToken() (string, error) {
	p := filepath.Join(stateDir(), "web.token")
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) == 32 {
		return strings.TrimSpace(string(b)), nil
	}
	var tok [16]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return "", err
	}
	t := hex.EncodeToString(tok[:])
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) { // created meanwhile
			b, err := os.ReadFile(p)
			return strings.TrimSpace(string(b)), err
		}
		return "", err
	}
	defer f.Close()
	_, err = f.WriteString(t + "\n")
	return t, err
}

// shownAddr is addr as a browser on this machine reaches it.
func shownAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func normalizeAddr(addr string) string {
	if _, err := strconv.Atoi(addr); err == nil {
		return "127.0.0.1:" + addr
	}
	return addr
}

// currentWeb is the base URL of the running web host ("" if none, or if
// we may not read its token) and its pid.
func currentWeb() (base string, pid int) {
	if !lockHeld(filepath.Join(stateDir(), "web.lock")) {
		return "", 0
	}
	b, err := os.ReadFile(filepath.Join(stateDir(), "web.json"))
	if err != nil {
		return "", 0
	}
	var wi webInfo
	if json.Unmarshal(b, &wi) != nil {
		return "", 0
	}
	tok, err := os.ReadFile(filepath.Join(stateDir(), "web.token"))
	if err != nil {
		return "", wi.PID
	}
	return fmt.Sprintf("http://%s/%s/", shownAddr(wi.Addr), strings.TrimSpace(string(tok))), wi.PID
}

// webHost serves the page while it holds the web lock, and keeps trying
// to take it over while another secwrap does.
type webHost struct {
	addr string

	mu      sync.Mutex
	hosting bool
	srv     *http.Server
	lock    *os.File
	warned  bool
	stop    chan struct{}
	done    chan struct{}
}

func startWebHost(addr string) *webHost {
	h := &webHost{addr: normalizeAddr(addr), stop: make(chan struct{}), done: make(chan struct{})}
	h.try() // now, so the URL can be announced
	go h.loop()
	return h
}

func (h *webHost) loop() {
	defer close(h.done)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-h.stop:
			h.release()
			return
		case <-t.C:
			h.try()
		}
	}
}

func (h *webHost) try() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.hosting || os.MkdirAll(stateDir(), 0o755) != nil {
		return
	}
	lock, err := os.OpenFile(filepath.Join(stateDir(), "web.lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close() // someone else hosts
		return
	}
	tok, err := webToken()
	if err != nil {
		lock.Close()
		return
	}
	ln, err := net.Listen("tcp", h.addr)
	if err != nil {
		if !h.warned {
			fmt.Fprintf(os.Stderr, "secwrap: web page: %v (secwrap session attach still answers)\n", err)
			h.warned = true
		}
		lock.Close()
		return
	}
	wi, _ := json.Marshal(webInfo{Addr: h.addr, PID: os.Getpid()})
	_ = os.WriteFile(filepath.Join(stateDir(), "web.json"), wi, 0o600)
	srv := &http.Server{Handler: webHandler(tok), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		// The listener failed while we live: hand the page over.
		if err := srv.Serve(ln); err != http.ErrServerClosed {
			h.mu.Lock()
			if h.srv == srv {
				h.lock.Close()
				h.hosting, h.srv = false, nil
			}
			h.mu.Unlock()
		}
	}()
	h.srv, h.lock, h.hosting = srv, lock, true
	if host, _, _ := net.SplitHostPort(h.addr); host == "" || net.ParseIP(host).IsUnspecified() {
		fmt.Fprintln(os.Stderr, "secwrap: warning: the web page listens on all interfaces over plain HTTP; anyone who sees the URL can approve requests")
	}
}

func (h *webHost) release() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.hosting {
		return
	}
	srv := h.srv
	h.srv = nil
	srv.Close()
	h.lock.Close() // the next secwrap takes over
	h.hosting = false
}

func (h *webHost) isHosting() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hosting
}

func (h *webHost) close() {
	close(h.stop)
	<-h.done
}

// ---------------------------------------------------------------------------
// Web

var sbomFileRe = regexp.MustCompile(`^[A-Za-z0-9._+-]+\.cdx\.json$`)

func webHandler(token string) http.Handler {
	mux := http.NewServeMux()
	p := "/" + token
	mux.HandleFunc("GET "+p+"/{$}", serveIndex)
	mux.HandleFunc("GET "+p+"/s/{id}/{$}", withSession(func(rw http.ResponseWriter, r *http.Request, v sessionView) {
		serveEmbedded(rw, "askweb/index.html", "text/html; charset=utf-8")
	}))
	mux.HandleFunc("GET "+p+"/s/{id}/app.js", withSession(func(rw http.ResponseWriter, r *http.Request, v sessionView) {
		serveEmbedded(rw, "askweb/app.js", "text/javascript; charset=utf-8")
	}))
	mux.HandleFunc("GET "+p+"/s/{id}/api/session", withSession(serveSessionInfo))
	mux.HandleFunc("GET "+p+"/s/{id}/api/requests", withSession(serveRequests))
	mux.HandleFunc("POST "+p+"/s/{id}/api/requests/{n}", withSession(serveDecide))
	mux.HandleFunc("POST "+p+"/s/{id}/api/requests/{n}/forget", withSession(serveForget))
	mux.HandleFunc("GET "+p+"/s/{id}/api/binaries", withSession(serveBinaries))
	mux.HandleFunc("GET "+p+"/s/{id}/api/binaries/{n}/sbom", withSession(serveSBOM))
	return secure(mux)
}

func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hd := rw.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		h.ServeHTTP(rw, r)
	})
}

func serveEmbedded(rw http.ResponseWriter, name, ctype string) {
	b, err := askwebFS.ReadFile(name)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", ctype)
	rw.Write(b)
}

// withSession resolves {id} to a session on the page (its record only).
func withSession(h func(http.ResponseWriter, *http.Request, sessionView)) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" || id == "." || id == ".." || strings.ContainsAny(id, "/\\") {
			http.NotFound(rw, r)
			return
		}
		v, err := readSession(filepath.Join(sessionsDir(), id), false)
		if err != nil || v.Hidden {
			http.NotFound(rw, r)
			return
		}
		h(rw, r, v)
	}
}

var indexTmpl = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="2"><title>secwrap · sessions</title>
<style>
:root{color-scheme:light dark;--fg:#1d1d1f;--bg:#fafafa;--mut:#6e6e73;--line:#e3e3e6;--acc:#0a62c9;--warn:#b25000;
--ok:#1a7f37;--ok-bg:#e6f4ea;--dead:#6e6e73;--dead-bg:#ececef}
@media (prefers-color-scheme:dark){:root{--fg:#f2f2f4;--bg:#161618;--mut:#9a9aa0;--line:#2e2e33;--acc:#5aa7ff;--warn:#ffa24d;
--ok:#4cc26b;--ok-bg:#16301f;--dead:#9a9aa0;--dead-bg:#26262a}}
body{font:15px/1.45 system-ui,sans-serif;color:var(--fg);background:var(--bg);margin:0 auto;padding:24px 16px;max-width:1000px}
h1{font-size:20px;margin:0 0 4px}p{color:var(--mut);margin:0 0 18px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut)}a{color:var(--acc)}
.wait{color:var(--warn);font-weight:600}.mut{color:var(--mut)}code{font-size:13px}
.st{display:inline-block;font-size:12px;font-weight:600;padding:1px 8px;border-radius:999px}
.alive{color:var(--ok);background:var(--ok-bg)}.dead{color:var(--dead);background:var(--dead-bg)}
@media (max-width:640px){.hide-sm{display:none}}
</style></head><body>
<h1>secwrap: sessions</h1><p>{{.Alive}} alive, {{.Dead}} dead. Served by secwrap pid {{.PID}}; <code>secwrap session</code> chooses what is shown.</p>
{{if .Rows}}<table><tr><th>Session</th><th>State</th><th>Waiting</th><th class="hide-sm">User</th><th class="hide-sm">Target</th></tr>
{{range .Rows}}<tr><td><a href="s/{{.ID}}/">{{.ID}}</a></td>
<td><span class="st {{.State}}">{{.State}}</span> <span class="mut">{{.Detail}}</span></td>
<td>{{if .Pending}}<span class="wait">{{.Pending}}</span>{{else}}<span class="mut">–</span>{{end}}</td>
<td class="hide-sm">{{.User}}</td><td class="hide-sm"><code>{{.Target}}</code></td></tr>
{{end}}</table>{{else}}<p>No sessions yet.</p>{{end}}
</body></html>`))

func serveIndex(rw http.ResponseWriter, r *http.Request) {
	list, _ := listSessions()
	type row struct {
		ID, State, Detail, User, Target string
		Pending                         int
	}
	data := struct {
		Rows        []row
		Alive, Dead int
		PID         int
	}{PID: os.Getpid()}
	for i := len(list) - 1; i >= 0; i-- { // newest first
		v := list[i]
		if v.Hidden {
			continue
		}
		if v.Running {
			data.Alive++
		} else {
			data.Dead++
		}
		data.Rows = append(data.Rows, row{v.ID, v.state(), v.stateDetail(), v.userLabel(), trunc(v.Target, 60), v.Pending})
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	indexTmpl.Execute(rw, data)
}

// serveSessionInfo is the session itself, for the page's alive/dead banner.
func serveSessionInfo(rw http.ResponseWriter, r *http.Request, v sessionView) {
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(struct {
		ID     string `json:"id"`
		Alive  bool   `json:"alive"`
		Detail string `json:"detail"`
		Target string `json:"target"`
		User   string `json:"user"`
		Ask    string `json:"ask"`
	}{v.ID, v.Running, v.stateDetail(), v.Target, v.userLabel(), v.askLabel()})
}

func serveRequests(rw http.ResponseWriter, r *http.Request, v sessionView) {
	items, err := v.asks()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(items) > maxWebItems {
		items = items[:maxWebItems]
	}
	if items == nil {
		items = []webItem{}
	}
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(items)
}

// postedItem checks a POST (JSON only: a JSON body can't be sent
// cross-site without a CORS preflight) and returns the question {n}.
func postedItem(rw http.ResponseWriter, r *http.Request, v sessionView) (webItem, bool) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(rw, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return webItem{}, false
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil {
		http.Error(rw, "bad id", http.StatusBadRequest)
		return webItem{}, false
	}
	it, err := v.ask(n)
	if err != nil {
		http.Error(rw, "no such request", http.StatusNotFound)
		return webItem{}, false
	}
	if !v.Running {
		http.Error(rw, "the session is dead", http.StatusConflict)
		return webItem{}, false
	}
	return it, true
}

func serveDecide(rw http.ResponseWriter, r *http.Request, v sessionView) {
	it, ok := postedItem(rw, r, v)
	if !ok {
		return
	}
	var af answerFile
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 4096)).Decode(&af); err != nil || af.Allow == nil {
		http.Error(rw, `body must be {"allow": true|false, "dir": "..."}`, http.StatusBadRequest)
		return
	}
	if it.Status != stPending {
		http.Error(rw, "already "+it.Status, http.StatusConflict)
		return
	}
	if _, ok := it.decision(af); !ok {
		http.Error(rw, "dir is not a folder of this file", http.StatusBadRequest)
		return
	}
	if err := writeAnswer(v.Dir, it.ID, answerFile{Allow: af.Allow, Dir: af.Dir}); err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

func serveForget(rw http.ResponseWriter, r *http.Request, v sessionView) {
	it, ok := postedItem(rw, r, v)
	if !ok {
		return
	}
	if it.Status != stAllowed && it.Status != stDenied {
		http.Error(rw, "nothing to forget", http.StatusConflict)
		return
	}
	if err := writeAnswer(v.Dir, it.ID, answerFile{Forget: true}); err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

// sbomIndex opens the session's SBOM folder and reads its index.
func sbomIndex(v sessionView) (*os.Root, []binary, error) {
	if v.SBOMs == "" {
		return nil, nil, nil
	}
	root, err := os.OpenRoot(v.SBOMs)
	if err != nil {
		return nil, nil, err
	}
	var list []binary
	b, err := root.ReadFile("index.json")
	if err == nil {
		err = json.Unmarshal(b, &list)
	}
	if err != nil {
		root.Close()
		return nil, nil, err
	}
	return root, list, nil
}

// serveBinaries lists the session's executed binaries, newest first (null
// without SBOMs).
func serveBinaries(rw http.ResponseWriter, r *http.Request, v sessionView) {
	rw.Header().Set("Content-Type", "application/json")
	root, list, err := sbomIndex(v)
	switch {
	case v.SBOMs == "":
		rw.Write([]byte("null\n"))
	case err != nil: // not written yet
		rw.Write([]byte("[]\n"))
	default:
		root.Close()
		slices.Reverse(list)
		json.NewEncoder(rw).Encode(list)
	}
}

func serveSBOM(rw http.ResponseWriter, r *http.Request, v sessionView) {
	n, err := strconv.Atoi(r.PathValue("n"))
	root, list, err2 := sbomIndex(v)
	if err != nil || err2 != nil || root == nil {
		http.NotFound(rw, r)
		return
	}
	defer root.Close()
	i := slices.IndexFunc(list, func(b binary) bool { return b.ID == n && sbomFileRe.MatchString(b.File) })
	if i < 0 {
		http.NotFound(rw, r)
		return
	}
	data, err := root.ReadFile(list[i].File)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	disp := "inline"
	if r.URL.Query().Get("download") != "" {
		disp = "attachment"
	}
	rw.Header().Set("Content-Disposition", fmt.Sprintf("%s; filename=%q", disp, list[i].File))
	rw.Write(data)
}

// ---------------------------------------------------------------------------
// secwrap session [--web [ADDR]]: the terminal UI

func sessionUI(web string) error {
	var host *webHost
	if web != "" {
		host = startWebHost(web)
		defer host.close()
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "secwrap: warning: not root: the page can show sessions but not answer them")
		}
	}
	if !isTerminal(os.Stdin) {
		return sessionPlain(host)
	}
	return runTUI(host)
}

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// sessionPlain: no terminal (a service): host the page, log the sessions.
func sessionPlain(host *webHost) error {
	if host == nil {
		return sessionList(os.Stdout)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	seen := map[string]bool{}
	announced := ""
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		if base, pid := currentWeb(); base != announced && base != "" {
			fmt.Fprintf(os.Stderr, "secwrap: web page %s (pid %d)\n", base, pid)
			announced = base
		}
		list, _ := listSessions()
		for _, v := range list {
			if key := v.ID + "/" + v.state(); !seen[key] {
				seen[key] = true
				fmt.Fprintf(os.Stderr, "secwrap: %-5s %s  %s\n", v.state(), v.ID, trunc(v.Target, 50))
			}
		}
		select {
		case <-sig:
			return nil
		case <-t.C:
		}
	}
}

type keyReader struct{ ch chan []byte } // nil: EOF (Ctrl-D in cooked mode)

func newKeyReader() *keyReader {
	k := &keyReader{ch: make(chan []byte, 16)}
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				k.ch <- append([]byte(nil), buf[:n]...)
			}
			if err != nil || n == 0 {
				k.ch <- nil
				if err != io.EOF || !isTerminal(os.Stdin) {
					return // a real end: only a terminal reads on after Ctrl-D
				}
			}
		}
	}()
	return k
}

// lines turns the keys into lines until stop is closed (nil: never) or
// EOF.
func (k *keyReader) lines(stop <-chan struct{}) <-chan string {
	out := make(chan string)
	go func() {
		defer close(out)
		var cur []byte
		for {
			select {
			case <-stop:
				return
			case b := <-k.ch:
				if b == nil {
					return // Ctrl-D: detach
				}
				for _, c := range b {
					if c != '\n' {
						cur = append(cur, c)
						continue
					}
					select {
					case out <- strings.TrimSpace(string(cur)):
					case <-stop:
						return
					}
					cur = cur[:0]
				}
			}
		}
	}()
	return out
}

type term struct {
	fd          int
	cooked, raw unix.Termios
}

func newTerm() (*term, error) {
	fd := int(os.Stdin.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	t := &term{fd: fd, cooked: *old, raw: *old}
	t.raw.Lflag &^= unix.ICANON | unix.ECHO | unix.ISIG
	t.raw.Cc[unix.VMIN], t.raw.Cc[unix.VTIME] = 1, 0
	return t, nil
}

func (t *term) setRaw() {
	unix.IoctlSetTermios(t.fd, unix.TCSETS, &t.raw)
	fmt.Print("\x1b[?25l")
}

func (t *term) setCooked() {
	unix.IoctlSetTermios(t.fd, unix.TCSETS, &t.cooked)
	fmt.Print("\x1b[?25h")
}

// tuiState is what one frame shows, reloaded on each tick (not per key).
type tuiState struct {
	list      []sessionView // newest first
	base      string        // web page URL, if any
	pid       int           // its host
	hostsHere bool
}

func loadTUI(host *webHost) tuiState {
	list, _ := listSessions()
	slices.Reverse(list)
	st := tuiState{list: list, hostsHere: host != nil && host.isHosting()}
	st.base, st.pid = currentWeb()
	return st
}

func runTUI(host *webHost) error {
	t, err := newTerm()
	if err != nil {
		return err
	}
	t.setRaw()
	defer t.setCooked()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sig)

	keys := newKeyReader()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	sel, msg := 0, ""
	confirm := "" // session ID awaiting a delete confirmation
	st := loadTUI(host)
	for {
		sel = max(0, min(sel, len(st.list)-1))
		render(host, st, sel, msg, confirm)

		var key []byte
		select {
		case <-sig:
			fmt.Print("\x1b[H\x1b[2J")
			return nil
		case <-tick.C:
			st = loadTUI(host)
			continue
		case key = <-keys.ch:
		}
		if key == nil {
			continue
		}
		msg = ""
		var cur *sessionView
		if len(st.list) > 0 {
			cur = &st.list[sel]
		}
		if confirm != "" {
			msg = "not deleted"
			if string(key) == "y" && cur != nil && cur.ID == confirm {
				msg = "deleted " + confirm
				if err := deleteSession(*cur); err != nil {
					msg = err.Error()
				}
			}
			confirm = ""
			st = loadTUI(host)
			continue
		}
		switch k := string(key); {
		case k == "q" || k == "\x03" || k == "\x04":
			fmt.Print("\x1b[H\x1b[2J")
			return nil
		case k == "\x1b[A" || k == "k":
			sel--
		case k == "\x1b[B" || k == "j":
			sel++
		case cur == nil:
		case k == "w" || k == " ":
			if err := setHidden(*cur, !cur.Hidden); err != nil {
				msg = err.Error()
			}
			st = loadTUI(host)
		case k == "W":
			hide := slices.ContainsFunc(st.list, func(v sessionView) bool { return !v.Hidden })
			for _, v := range st.list {
				if err := setHidden(v, hide); err != nil {
					msg = err.Error()
				}
			}
			st = loadTUI(host)
		case k == "d":
			if cur.Running {
				msg = cur.ID + " is alive: only dead sessions can be deleted"
			} else {
				confirm = cur.ID
			}
		case k == "a" || k == "\r" || k == "\n":
			if !cur.Running {
				msg = cur.ID + " is dead: nothing to answer (its history: " + orDash(cur.History) + ")"
				continue
			}
			t.setCooked()
			fmt.Print("\x1b[H\x1b[2J")
			stop := make(chan struct{})
			if err := attachSession(*cur, keys.lines(stop), os.Stdout); err != nil {
				msg = err.Error()
			}
			close(stop)
			t.setRaw()
			st = loadTUI(host)
		}
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

const (
	ansiBold, ansiDim, ansiRev, ansiReset = "\x1b[1m", "\x1b[2m", "\x1b[7m", "\x1b[0m"
	ansiGreen, ansiYellow, ansiGrey       = "\x1b[32;1m", "\x1b[33;1m", "\x1b[90m"
)

func render(host *webHost, st tuiState, sel int, msg, confirm string) {
	var b strings.Builder
	b.WriteString("\x1b[H\x1b[2J")
	alive := 0
	for _, v := range st.list {
		if v.Running {
			alive++
		}
	}
	fmt.Fprintf(&b, "%ssecwrap sessions%s  %d alive, %d dead\n", ansiBold, ansiReset, alive, len(st.list)-alive)
	switch {
	case st.base != "" && st.hostsHere:
		fmt.Fprintf(&b, "web: %s  (served here)\n", st.base)
	case st.base != "":
		fmt.Fprintf(&b, "web: %s  (served by pid %d)\n", st.base, st.pid)
	case st.pid != 0:
		fmt.Fprintf(&b, "web: served by pid %d (run as root to see its URL)\n", st.pid)
	case host != nil:
		fmt.Fprintf(&b, "web: not served yet (address busy?), retrying\n")
	default:
		fmt.Fprintf(&b, "web: off (secwrap session --web, or a running shell, serves it)\n")
	}
	fmt.Fprintf(&b, "%s↑/↓ select · Enter attach · w on/off the web page (W: all) · d delete (dead) · q quit%s\n\n", ansiDim, ansiReset)
	if len(st.list) == 0 {
		fmt.Fprintf(&b, "  no sessions yet in %s: start one with sudo secwrap shell / monitor\n", sessionsDir())
	}
	fmt.Fprintf(&b, "%s   %-6s %-28s %-6s %-10s %-4s %-24s %s%s\n", ansiDim, "STATE", "SESSION", "WAIT", "ASK", "WEB", "", "TARGET", ansiReset)
	for i, v := range st.list {
		state := ansiGrey + "dead " + ansiReset
		if v.Running {
			state = ansiGreen + "alive" + ansiReset
		}
		wait := fmt.Sprintf("%-6s", pendingLabel(v))
		if v.Pending > 0 {
			wait = ansiYellow + wait + ansiReset
		}
		web := "on"
		if v.Hidden {
			web = "off"
		}
		row := fmt.Sprintf("  %s %-28s %s %-10s %-4s %-24s %s", state, v.ID, wait, trunc(v.askLabel(), 10), web,
			trunc(v.stateDetail(), 24), trunc(v.Target, 40))
		if i == sel { // reverse video, re-applied after each colour reset
			row = ansiRev + ">" + strings.ReplaceAll(row[1:], ansiReset, ansiReset+ansiRev) + ansiReset
		}
		b.WriteString(row + "\n")
	}
	if sel < len(st.list) {
		v := st.list[sel]
		b.WriteString("\n")
		if st.base != "" && !v.Hidden {
			fmt.Fprintf(&b, "  page: %ss/%s/\n", st.base, v.ID)
		}
		if v.History != "" {
			fmt.Fprintf(&b, "  history: %s\n", v.History)
		}
	}
	if confirm != "" {
		fmt.Fprintf(&b, "\n  %sdelete the record of %s? (its history folder stays) [y/N]%s\n", ansiBold, confirm, ansiReset)
	} else if msg != "" {
		fmt.Fprintf(&b, "\n  %s\n", msg)
	}
	fmt.Print(b.String())
}
