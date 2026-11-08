package main

// secwrap vacuum: deletes what dead sessions left behind once they ended
// longer ago than --older-than: their records in the sessions folder and
// their history folders (events, report, summary, SBOMs). Alive sessions
// are never touched.

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func cmdVacuum(args []string) error {
	fset := flag.NewFlagSet("vacuum", flag.ExitOnError)
	age := ageFlag(30 * 24 * time.Hour)
	fset.Var(&age, "older-than", "delete sessions that ended longer ago than this, e.g. 30d, 12h, 90m")
	dry := fset.Bool("dry-run", false, "list what would be deleted, and delete nothing")
	fset.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: secwrap vacuum [--older-than 30d] [--dry-run]")
		fset.PrintDefaults()
	}
	fset.Parse(args)
	if fset.NArg() > 0 {
		fset.Usage()
		os.Exit(2)
	}
	v := vacuum{cutoff: time.Now().Add(-time.Duration(age)), dry: *dry, done: map[string]bool{}}
	if err := v.sessions(); err != nil {
		return err
	}
	if err := v.orphans(); err != nil {
		return err
	}
	verb := "deleted"
	if v.dry {
		verb = "would delete"
	}
	fmt.Printf("%s %s and %s (%s), older than %s\n", verb, plural(v.records, "session record"),
		plural(v.folders, "history folder"), humanSize(v.freed), age)
	if v.failed > 0 {
		return fmt.Errorf("%s could not be deleted", plural(v.failed, "item"))
	}
	return nil
}

type vacuum struct {
	cutoff           time.Time
	dry              bool
	live             []string        // history folders of alive sessions
	done             map[string]bool // history folders already handled
	records, folders int
	failed           int // printed as they happen; vacuum goes on
	freed            int64
}

// sessions deletes the old dead session records, and their history folders.
func (v *vacuum) sessions() error {
	list, err := listSessions()
	if err != nil {
		return err
	}
	for _, s := range list {
		if s.Running {
			if s.History != "" {
				v.live = append(v.live, filepath.Clean(s.History))
			}
			continue
		}
		end := s.Started
		if s.Ended != nil {
			end = *s.Ended
		}
		if end.After(v.cutoff) {
			continue
		}
		fmt.Printf("session %s (%s)\n", s.ID, s.stateDetail())
		if h := filepath.Clean(s.History); s.History != "" && filepath.IsAbs(h) && isHistoryOf(filepath.Base(h), s.ID) {
			if err := v.removeFolder(filepath.Dir(h), filepath.Base(h), "  "); err != nil {
				fmt.Fprintf(os.Stderr, "secwrap: %s: %v\n", h, err)
				v.failed++
			}
		}
		if v.dry {
			v.records++
		} else if err := deleteSession(s); err != nil {
			fmt.Fprintf(os.Stderr, "secwrap: session %s: %v\n", s.ID, err)
			v.failed++
		} else {
			v.records++
		}
	}
	return nil
}

// orphans deletes old folders in the default history folder that no
// record points to any more (records deleted by hand, or sessions run
// before vacuum existed).
func (v *vacuum) orphans() error {
	parent, rel, err := defaultHistory()
	if err != nil {
		return err
	}
	dir := filepath.Join(parent, rel)
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range ents {
		path := filepath.Join(dir, e.Name())
		if !e.IsDir() || v.done[path] || v.isLive(path) {
			continue
		}
		newest, ok := historyTime(path)
		if !ok || newest.After(v.cutoff) {
			continue
		}
		if err := v.removeFolder(dir, e.Name(), ""); err != nil {
			fmt.Fprintf(os.Stderr, "secwrap: %s: %v\n", path, err)
			v.failed++
		}
	}
	return nil
}

func (v *vacuum) isLive(path string) bool {
	for _, l := range v.live {
		if l == path {
			return true
		}
	}
	return false
}

// removeFolder deletes name inside parent. Under sudo parent is in the
// invoker's home: os.Root keeps a symlink there from leading root's
// deletion anywhere else.
func (v *vacuum) removeFolder(parent, name, indent string) error {
	path := filepath.Join(parent, name)
	v.done[path] = true
	if v.isLive(path) {
		return nil
	}
	size := dirSize(path)
	fmt.Printf("%shistory %s (%s)\n", indent, path, humanSize(size))
	if !v.dry {
		root, err := os.OpenRoot(parent)
		if err != nil {
			return err
		}
		defer root.Close()
		if err := root.RemoveAll(name); err != nil {
			return err
		}
	}
	v.folders++
	v.freed += size
	return nil
}

// isHistoryOf reports whether a history folder name belongs to session id:
// the id itself, or id-2, id-3... when the name was taken.
func isHistoryOf(name, id string) bool {
	if name == id {
		return true
	}
	n, ok := strings.CutPrefix(name, id+"-")
	_, err := strconv.Atoi(n)
	return ok && err == nil
}

// historyTime is when a history folder was last written to, if it is one
// (it has events.jsonl).
func historyTime(path string) (time.Time, bool) {
	ev, err := os.Lstat(filepath.Join(path, "events.jsonl"))
	if err != nil || !ev.Mode().IsRegular() {
		return time.Time{}, false
	}
	newest := ev.ModTime()
	ents, _ := os.ReadDir(path)
	for _, e := range ents {
		if fi, err := e.Info(); err == nil && fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	return newest, true
}

func dirSize(path string) int64 {
	var n int64
	filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return strconv.Itoa(n) + " " + what + "s"
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// ageFlag is a duration that also takes days: 30d, 12h, 90m.
type ageFlag time.Duration

func (a ageFlag) String() string {
	d := time.Duration(a)
	if d > 0 && d%(24*time.Hour) == 0 {
		return strconv.Itoa(int(d/(24*time.Hour))) + "d"
	}
	return d.String()
}

func (a *ageFlag) Set(s string) error {
	var d time.Duration
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil {
			return fmt.Errorf("want a number of days, e.g. 30d, not %q", s)
		}
		d = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return fmt.Errorf("want e.g. 30d, 12h or 90m, not %q", s)
		}
	}
	if d < 0 {
		return fmt.Errorf("%q is negative", s)
	}
	*a = ageFlag(d)
	return nil
}
