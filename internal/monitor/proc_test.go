//go:build linux

package monitor

import (
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func TestParseCgroup(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		err      bool
	}{
		{in: "0::/user.slice/session-3.scope\n", want: cgroupRoot + "/user.slice/session-3.scope"},
		{in: "0::/\n", want: cgroupRoot},
		{in: "12:pids:/x\n1:name=systemd:/x\n0::/system.slice/a.service\n", want: cgroupRoot + "/system.slice/a.service"},
		{in: "0::/gone (deleted)\n", want: cgroupRoot + "/gone"},
		{in: "0::/..\n", err: true},
		{in: "0::/../../system.slice/x\n", err: true},
		{in: "0::/..foo\n", want: cgroupRoot + "/..foo"}, // a name, not a parent
		{in: "1:name=systemd:/x\n", err: true},           // cgroup v1 only
		{in: "", err: true},
	} {
		got, err := parseCgroup(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("parseCgroup(%q) = %q, want an error", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("parseCgroup(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestStatusAlive(t *testing.T) {
	for _, tc := range []struct {
		status string
		want   bool
	}{
		{"Name:\tbash\nState:\tS (sleeping)\nThreads:\t1\n", true},
		{"State:\tR (running)\nThreads:\t4\n", true},
		{"State:\tZ (zombie)\nThreads:\t1\n", false},
		{"State:\tZ (zombie)\nThreads:\t3\n", true}, // leader exited, threads run on
		{"State:\tX (dead)\nThreads:\t1\n", false},
		{"", false},
	} {
		if got := statusAlive(tc.status); got != tc.want {
			t.Errorf("statusAlive(%q) = %v, want %v", tc.status, got, tc.want)
		}
	}
}

func TestProcAlive(t *testing.T) {
	if !procAlive(os.Getpid()) {
		t.Error("procAlive(self) = false")
	}
	if procAlive(1 << 30) {
		t.Error("procAlive(nonexistent) = true")
	}
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer cmd.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for procAlive(cmd.Process.Pid) {
		if time.Now().After(deadline) {
			t.Fatal("procAlive(zombie) stays true")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTgidOf(t *testing.T) {
	self := os.Getpid()
	if got := tgidOf(self); got != self {
		t.Errorf("tgidOf(self) = %d, want %d", got, self)
	}
	ents, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Skip(err)
	}
	for _, e := range ents {
		tid, _ := strconv.Atoi(e.Name())
		if tid != self {
			if got := tgidOf(tid); got != self {
				t.Errorf("tgidOf(thread %d) = %d, want %d", tid, got, self)
			}
			return
		}
	}
	t.Skip("no other thread")
}
