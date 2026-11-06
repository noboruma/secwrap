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
