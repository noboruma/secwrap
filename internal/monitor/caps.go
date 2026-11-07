//go:build linux

package monitor

// What this kernel can do for secwrap: probed from files any user can read,
// so `secwrap cap` needs no root. Each session checks what it was asked for
// against this, and refuses with the reason before loading anything.

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Caps is what the running kernel supports.
type Caps struct {
	Kernel  string // uname -r
	Machine string // uname -m

	BTF          bool   // /sys/kernel/btf/vmlinux: CO-RE needs it for everything
	Kprobes      bool   // the kprobe PMU: network logging
	CgroupV2     bool   // network deny and ask (cgroup hooks), freezing
	SeccompNotif bool   // ask (SECCOMP_RET_USER_NOTIF)
	Freeze       bool   // inline questions freeze the command: cgroup v2, Linux 5.19+
	LSM          bool   // filesystem, exec, sbom
	LSMWhy       string // why not
}

// ProbeCaps probes the running kernel.
func ProbeCaps() Caps {
	c := Caps{Machine: "?", Kernel: "?"}
	if m, err := unameMachine(); err == nil {
		c.Machine = m
	}
	c.Kernel = kernelRelease()
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	c.BTF = exists("/sys/kernel/btf/vmlinux")
	c.Kprobes = exists("/sys/bus/event_source/devices/kprobe/type")
	c.CgroupV2 = exists(filepath.Join(cgroupRoot, "cgroup.controllers"))
	if b, err := os.ReadFile("/proc/sys/kernel/seccomp/actions_avail"); err == nil {
		c.SeccompNotif = slices.Contains(strings.Fields(string(b)), "user_notif")
	}
	c.Freeze = c.CgroupV2 && kernelAtLeast(c.Kernel, 5, 19)
	switch {
	case !lsmArchSupported():
		c.LSMWhy = c.Machine + " kernels can't run BPF LSM programs"
	case !bpfInLSMList():
		c.LSMWhy = `"bpf" not in /sys/kernel/security/lsm (add lsm=...,bpf to the kernel command line)`
	default:
		c.LSM = true
	}
	return c
}

// Modes lists what each category can do here: "log", "ask", "deny", or
// none (and why).
type Modes struct {
	Log, Ask, Deny bool
	Why            string // why not everything
}

func (m Modes) String() string {
	var s []string
	if m.Log {
		s = append(s, "log")
	}
	if m.Ask {
		s = append(s, "ask")
	}
	if m.Deny {
		s = append(s, "deny")
	}
	if len(s) == 0 {
		return "unavailable"
	}
	return strings.Join(s, " ")
}

func (m Modes) allows(a Action) bool {
	switch a {
	case ActionAsk:
		return m.Ask
	case ActionDeny:
		return m.Deny
	}
	return m.Log
}

// Net: logging uses kprobes; deny and ask, the cgroup hooks; ask, seccomp.
func (c Caps) Net() Modes {
	if !c.BTF {
		return Modes{Why: "no kernel BTF (/sys/kernel/btf/vmlinux)"}
	}
	m := Modes{Log: c.Kprobes, Deny: c.CgroupV2, Ask: c.CgroupV2 && c.SeccompNotif}
	switch {
	case !c.Kprobes:
		m.Why = "no kprobes"
	case !c.CgroupV2:
		m.Why = "no cgroup v2 at " + cgroupRoot
	case !c.SeccompNotif:
		m.Why = "no seccomp user notifications"
	}
	return m
}

// Files (and Exec): the BPF LSM; ask also needs seccomp.
func (c Caps) Files() Modes {
	switch {
	case !c.BTF:
		return Modes{Why: "no kernel BTF (/sys/kernel/btf/vmlinux)"}
	case !c.LSM:
		return Modes{Why: c.LSMWhy}
	}
	m := Modes{Log: true, Deny: true, Ask: c.SeccompNotif}
	if !m.Ask {
		m.Why = "no seccomp user notifications"
	}
	return m
}

// Check refuses what o asks for and this kernel can't do, saying why.
func (c Caps) Check(o *Options) error {
	for _, w := range []struct {
		on    bool
		flag  string
		act   Action
		modes Modes
	}{
		{o.Net, "--net", o.NetAction, c.Net()},
		{o.Files, "--filesystem", o.FilesAction, c.Files()},
		{o.Exec, "--exec", o.ExecAction, c.Files()},
	} {
		switch {
		case !w.on || w.modes.allows(w.act):
		case !w.modes.Log: // nothing at all
			return fmt.Errorf("%s is not available on this kernel: %s (see secwrap cap)", w.flag, w.modes.Why)
		default:
			return fmt.Errorf("%s %s is not available on this kernel: %s; %s can %s (see secwrap cap)", w.flag, w.act, w.modes.Why, w.flag, w.modes)
		}
	}
	if o.OnBinary != nil && !c.Files().Log {
		return fmt.Errorf("--sbom is not available on this kernel: %s (see secwrap cap)", c.Files().Why)
	}
	return nil
}

func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(b))
}

// kernelAtLeast compares release ("6.12.113+deb13-amd64") with major.minor.
func kernelAtLeast(release string, major, minor int) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	ma, err1 := strconv.Atoi(parts[0])
	mi, err2 := strconv.Atoi(leadingDigits(parts[1])) // "19-rc1" -> 19
	if err1 != nil || err2 != nil {
		return false
	}
	return ma > major || ma == major && mi >= minor
}

func leadingDigits(s string) string {
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	return s[:n]
}
