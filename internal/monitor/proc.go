package monitor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procInfo is the subset of /proc/PID/stat we need.
type procInfo struct {
	pid, ppid int
	comm      string
}

func listProcs() []procInfo {
	ents, _ := os.ReadDir("/proc")
	out := make([]procInfo, 0, len(ents))
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue // exited meanwhile
		}
		// pid (comm) state ppid ... ; comm may contain spaces/parens.
		s := string(data)
		lp, rp := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if lp < 0 || rp < lp {
			continue
		}
		f := strings.Fields(s[rp+1:])
		if len(f) < 2 {
			continue
		}
		ppid, _ := strconv.Atoi(f[1])
		out = append(out, procInfo{pid: pid, ppid: ppid, comm: s[lp+1 : rp]})
	}
	return out
}

// WithDescendants returns roots plus all their currently running descendants.
func WithDescendants(roots []int) []int {
	children := map[int][]int{}
	for _, p := range listProcs() {
		children[p.ppid] = append(children[p.ppid], p.pid)
	}
	seen := map[int]bool{}
	var out []int
	queue := append([]int(nil), roots...)
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
		queue = append(queue, children[p]...)
	}
	return out
}

// FindByName returns PIDs whose comm or executable basename equals name.
func FindByName(name string) []int {
	self := os.Getpid()
	var out []int
	for _, p := range listProcs() {
		if p.pid == self {
			continue
		}
		match := p.comm == name
		if !match {
			if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", p.pid)); err == nil {
				match = filepath.Base(strings.TrimSuffix(exe, " (deleted)")) == name
			}
		}
		if match {
			out = append(out, p.pid)
		}
	}
	return out
}

// procAlive reports whether pid is a live process: not gone, and not a
// zombie unless other threads of it still run (its leader thread can exit
// first, with pthread_exit).
func procAlive(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	return statusAlive(string(data))
}

// statusAlive is procAlive on the contents of a /proc/PID/status file.
func statusAlive(status string) bool {
	state, threads := "", 0
	for _, line := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(line, "State:"); ok {
			state = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(line, "Threads:"); ok {
			threads, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	switch {
	case state == "":
		return false
	case strings.HasPrefix(state, "Z"):
		return threads > 1
	case strings.HasPrefix(state, "X"):
		return false
	}
	return true
}

// CheckAlive returns an error if any pid does not exist.
func CheckAlive(pids []int) error {
	var errs []error
	for _, p := range pids {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", p)); err != nil {
			errs = append(errs, fmt.Errorf("no such process: %d", p))
		}
	}
	return errors.Join(errs...)
}
