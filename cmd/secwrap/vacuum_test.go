package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestVacuum(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the default history folder is the sudo invoker's")
	}
	tmp := t.TempDir()
	sessions, state := filepath.Join(tmp, "sessions"), filepath.Join(tmp, "state")
	t.Setenv("SECWRAP_SESSIONS", sessions)
	t.Setenv("XDG_STATE_HOME", state)
	hist := filepath.Join(state, "secwrap")
	old, recent := time.Now().Add(-40*24*time.Hour), time.Now().Add(-2*24*time.Hour)

	// folder makes a history folder last written at when.
	folder := func(name string, when time.Time, events bool) string {
		dir := filepath.Join(hist, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if events {
			f := filepath.Join(dir, "events.jsonl")
			os.WriteFile(f, []byte("{}\n"), 0o644)
			os.Chtimes(f, when, when)
		}
		os.Chtimes(dir, when, when)
		return dir
	}
	// record makes a session record; alive holds its lock until the test ends.
	record := func(id string, ended time.Time, history string, alive bool) {
		dir := filepath.Join(sessions, id)
		os.MkdirAll(dir, 0o755)
		info := sessionInfo{ID: id, Started: ended.Add(-time.Minute), History: history}
		if !alive {
			info.Ended = &ended
		}
		b, _ := json.Marshal(info)
		os.WriteFile(filepath.Join(dir, "session.json"), b, 0o644)
		f, _ := os.Create(filepath.Join(dir, "lock"))
		if alive {
			syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
			t.Cleanup(func() { f.Close() })
		} else {
			f.Close()
		}
	}
	record("old", old, folder("old", old, true), false)
	record("recent", recent, folder("recent", recent, true), false)
	record("alive", old, folder("alive", old, true), true)
	folder("orphan", old, true)
	folder("orphan-recent", recent, true)
	folder("not-history", old, false)

	exists := func(p string) bool { _, err := os.Lstat(p); return err == nil }
	check := func(want map[string]bool) {
		t.Helper()
		for p, w := range want {
			if exists(p) != w {
				t.Errorf("%s exists = %v, want %v", p, !w, w)
			}
		}
	}

	if err := cmdVacuum([]string{"--older-than", "30d", "--dry-run"}); err != nil {
		t.Fatal(err)
	}
	check(map[string]bool{filepath.Join(sessions, "old"): true, filepath.Join(hist, "old"): true, filepath.Join(hist, "orphan"): true})

	if err := cmdVacuum([]string{"--older-than", "30d"}); err != nil {
		t.Fatal(err)
	}
	check(map[string]bool{
		filepath.Join(sessions, "old"):       false,
		filepath.Join(hist, "old"):           false,
		filepath.Join(hist, "orphan"):        false,
		filepath.Join(sessions, "recent"):    true,
		filepath.Join(hist, "recent"):        true,
		filepath.Join(hist, "orphan-recent"): true,
		filepath.Join(sessions, "alive"):     true,
		filepath.Join(hist, "alive"):         true,
		filepath.Join(hist, "not-history"):   true,
	})

	if err := cmdVacuum([]string{"--older-than", "1d"}); err != nil {
		t.Fatal(err)
	}
	check(map[string]bool{
		filepath.Join(sessions, "recent"):    false,
		filepath.Join(hist, "recent"):        false,
		filepath.Join(hist, "orphan-recent"): false,
		filepath.Join(hist, "alive"):         true,
	})
}

func TestAgeFlag(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"30d": 30 * 24 * time.Hour, "0d": 0, "12h": 12 * time.Hour, "90m": 90 * time.Minute,
	} {
		var a ageFlag
		if err := a.Set(in); err != nil || time.Duration(a) != want {
			t.Errorf("Set(%q) = %v, %v; want %v", in, time.Duration(a), err, want)
		}
	}
	for _, in := range []string{"", "d", "xd", "30", "-1d", "-5h", "soon"} {
		var a ageFlag
		if a.Set(in) == nil {
			t.Errorf("Set(%q) succeeded", in)
		}
	}
	if s := ageFlag(30 * 24 * time.Hour).String(); s != "30d" {
		t.Errorf("String() = %q, want 30d", s)
	}
}

func TestIsHistoryOf(t *testing.T) {
	id := "20261108-120102-make"
	for name, want := range map[string]bool{
		id: true, id + "-2": true, id + "-17": true,
		id + "-x": false, id + "x": false, "20261108-120102-mak": false, "other": false,
	} {
		if got := isHistoryOf(name, id); got != want {
			t.Errorf("isHistoryOf(%q) = %v, want %v", name, got, want)
		}
	}
}
