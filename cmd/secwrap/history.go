package main

// Session history: every session is kept in its own folder, named after
// the session, ~/.local/state/secwrap/<session id>/ by default (--history
// DIR to choose, --history off for none), with
//
//	events.jsonl  every event, as JSON lines
//	report.json   the JSON report (what -o writes)
//	summary.txt   the summary (printed at the end only with --summary)
//	sboms/        the SBOMs, when collected without --sbom DIR
//
// Under sudo, the folders are created as root inside the invoker's home
// through os.Root, so a symlink there cannot send root's writes elsewhere,
// and are given to the invoker.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/noboruma/secwrap/internal/monitor"
)

type history struct {
	dir  string // the session's folder
	root *os.Root
	mu   sync.Mutex
	evF  *os.File
	evW  *bufio.Writer // events are many (every file open): one write per 64 KiB
	enc  *json.Encoder
}

// openHistory creates the folder of session id under base ("" means
// ~/.local/state/secwrap, or $XDG_STATE_HOME/secwrap when not under sudo).
func openHistory(base, id string) (*history, error) {
	parentDir, rel := base, "."
	if base == "" {
		var err error
		if parentDir, rel, err = defaultHistory(); err != nil {
			return nil, fmt.Errorf("--history: %w", err)
		}
	} else {
		abs, err := filepath.Abs(base)
		if err == nil {
			err = os.MkdirAll(abs, 0o755)
		}
		if err != nil {
			return nil, fmt.Errorf("--history: %w", err)
		}
		parentDir = abs
	}
	parent, err := os.OpenRoot(parentDir)
	if err != nil {
		return nil, fmt.Errorf("--history: %w", err)
	}
	defer parent.Close()
	if err := mkdirAllInvoker(parent, rel); err != nil {
		return nil, fmt.Errorf("--history: %w", err)
	}
	hroot, err := parent.OpenRoot(rel)
	if err != nil {
		return nil, fmt.Errorf("--history: %w", err)
	}
	defer hroot.Close()
	name, err := mkUniqueDir(hroot, id, 0o755)
	if err != nil {
		return nil, fmt.Errorf("--history: %w", err)
	}
	chownInvokerIn(hroot, name)
	root, err := hroot.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("--history: %w", err)
	}
	h := &history{dir: filepath.Join(parentDir, rel, name), root: root}
	h.evF, err = root.OpenFile("events.jsonl", os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("--history: %w", err)
	}
	chownToInvoker(h.evF)
	h.evW = bufio.NewWriterSize(h.evF, 64<<10)
	h.enc = json.NewEncoder(h.evW)
	return h, nil
}

// defaultHistory is where sessions are kept without --history: rel inside
// parent, the invoker's home (or $XDG_STATE_HOME when not under sudo).
func defaultHistory() (parent, rel string, err error) {
	u := invoker()
	home, err := os.UserHomeDir()
	if u != nil {
		home, err = u.HomeDir, nil
	}
	if err != nil {
		return "", "", err
	}
	if x := os.Getenv("XDG_STATE_HOME"); x != "" && u == nil {
		return x, "secwrap", nil
	}
	return home, filepath.Join(".local", "state", "secwrap"), nil
}

// mkdirAllInvoker creates rel and its missing parents inside root, giving
// the ones it creates to the invoker.
func mkdirAllInvoker(root *os.Root, rel string) error {
	if rel == "." {
		return nil
	}
	cur := ""
	for _, part := range strings.Split(filepath.Clean(rel), string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		err := root.Mkdir(cur, 0o755)
		switch {
		case err == nil:
			chownInvokerIn(root, cur)
		case os.IsExist(err):
		default:
			return err
		}
	}
	return nil
}

// wrap makes o's event callbacks also record into events.jsonl.
func (h *history) wrap(o *monitor.Options) {
	record := func(v any) {
		h.mu.Lock()
		h.enc.Encode(v)
		h.mu.Unlock()
	}
	ev, fe := o.OnEvent, o.OnFileEvent
	o.OnEvent = func(e monitor.Event) {
		record(e)
		if ev != nil {
			ev(e)
		}
	}
	o.OnFileEvent = func(e monitor.FileEvent) {
		record(e)
		if fe != nil {
			fe(e)
		}
	}
}

// sbomDir is the session's SBOM folder, created now.
func (h *history) sbomDir() (string, error) {
	if err := h.root.Mkdir("sboms", 0o755); err != nil && !os.IsExist(err) {
		return "", err
	}
	chownInvokerIn(h.root, "sboms")
	return filepath.Join(h.dir, "sboms"), nil
}

// finish writes the report and the summary, and closes the event log.
func (h *history) finish(rep *monitor.Report, summary func(io.Writer)) {
	h.mu.Lock()
	h.evW.Flush()
	h.evF.Close()
	h.mu.Unlock()
	if rep != nil {
		if err := writeJSONIn(h.root, "report.json", rep); err != nil {
			fmt.Fprintf(os.Stderr, "secwrap: history: %v\n", err)
		}
	}
	if f, err := h.root.OpenFile("summary.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644); err == nil {
		chownToInvoker(f)
		summary(f)
		f.Close()
	}
	h.root.Close()
}
