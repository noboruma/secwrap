package main

// secwrap sessions [list | attach [ID] | delete ID...]

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/sys/unix"
)

func cmdSession(args []string) error {
	usage := errors.New("usage: secwrap sessions [list | attach [ID] | delete ID...]")
	if len(args) == 0 {
		return sessionUI()
	}
	switch args[0] {
	case "list", "ls":
		return sessionList(os.Stdout)
	case "attach", "a":
		arg := ""
		if len(args) > 1 {
			arg = args[1]
		}
		v, err := findSession(arg)
		if err != nil {
			return err
		}
		return attachSession(v, newKeyReader().lines(nil), os.Stdout)
	case "delete", "rm":
		if len(args) < 2 {
			return usage
		}
		for _, a := range args[1:] {
			v, err := findSession(a)
			if err != nil {
				return err
			}
			if err := deleteSession(v); err != nil {
				return err
			}
			fmt.Printf("deleted %s\n", v.ID)
		}
		return nil
	}
	return usage
}

func sessionList(w io.Writer) error {
	list, err := listSessions()
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintf(w, "no sessions in %s\n", sessionsDir())
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tID\tSTATE\tUSER\tASK\tWAITING\tWATCH\tTARGET")
	for i, v := range list {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", i+1, v.ID, v.state()+" ("+v.stateDetail()+")", v.userLabel(),
			v.askLabel(), pendingLabel(v), strings.Join(v.Watch, ","), trunc(v.Target, 50))
	}
	return tw.Flush()
}

func pendingLabel(v sessionView) string {
	if v.Pending == 0 {
		return "-"
	}
	return strconv.Itoa(v.Pending)
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// attachSession answers the session's questions one at a time, oldest
// first, until q, the end of lines (Ctrl-D), or the end of the session.
func attachSession(v sessionView, lines <-chan string, w io.Writer) error {
	if !v.Running {
		return fmt.Errorf("%s is dead (%s)", v.ID, v.stateDetail())
	}
	if unix.Access(filepath.Join(v.Dir, "answers"), unix.W_OK) != nil {
		return errors.New("answering needs root: sudo secwrap sessions attach")
	}
	fmt.Fprintf(w, "attached to %s: %s (pid %d, %s, ask: %s)\n", v.ID, v.Target, v.PID, v.userLabel(), v.askLabel())
	if v.History != "" {
		fmt.Fprintf(w, "recorded in %s\n", v.History)
	}
	fmt.Fprintln(w, "answer each request here; q (or Ctrl-D) to detach")

	q := askQueue{v: v, done: map[int]bool{}}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	idle := false
	for {
		if !lockHeld(filepath.Join(v.Dir, "lock")) {
			fmt.Fprintf(w, "\nsession %s ended\n", v.ID)
			return nil
		}
		it, ok := q.next()
		if !ok {
			if !idle {
				fmt.Fprintln(w, "  (no request waiting)")
				idle = true
			}
			select {
			case line, ok := <-lines:
				if !ok || line == "q" {
					fmt.Fprintln(w, "detached")
					return nil
				}
			case <-tick.C:
			}
			continue
		}
		idle = false
		// read waits for a line while the request is still pending.
		read := func() (string, readResult) {
			for {
				select {
				case line, ok := <-lines:
					if !ok || line == "q" {
						return "", gotQuit
					}
					return line, gotLine
				case <-tick.C:
					if now, err := v.ask(it.ID); err != nil || now.Status != stPending {
						fmt.Fprintf(w, "\n      (%s)\n", statusText(now.Status))
						return "", gotVoid
					}
					if !lockHeld(filepath.Join(v.Dir, "lock")) {
						return "", gotVoid
					}
				}
			}
		}
		af, r := prompt(w, it, read, true)
		switch r {
		case gotQuit:
			fmt.Fprintln(w, "detached")
			return nil
		case gotLine:
			if err := writeAnswer(v.Dir, it.ID, *af); err != nil {
				return err
			}
		}
		q.done[it.ID] = true // answered (or void): not asked again
	}
}

// askQueue finds the oldest question still waiting, reading only the
// files it has not yet seen settled.
type askQueue struct {
	v    sessionView
	done map[int]bool // settled, or answered here
}

func (q *askQueue) next() (webItem, bool) {
	d, err := os.Open(filepath.Join(q.v.Dir, "asks"))
	if err != nil {
		return webItem{}, false
	}
	names, _ := d.Readdirnames(-1)
	d.Close()
	var ids []int
	for _, n := range names {
		if id, err := strconv.Atoi(strings.TrimSuffix(n, ".json")); err == nil && !q.done[id] {
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	for _, id := range ids {
		it, err := q.v.ask(id)
		if err != nil {
			continue
		}
		if it.Status == stPending {
			return it, true
		}
		q.done[id] = true
	}
	return webItem{}, false
}

func statusText(st string) string {
	switch st {
	case stAllowed, stDenied:
		return st + " elsewhere"
	case stCovered:
		return "allowed by a folder rule"
	case stPending:
		return "session ended"
	}
	return "process gone, question dropped"
}
