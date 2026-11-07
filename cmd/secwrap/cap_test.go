package main

import (
	"strings"
	"testing"

	"github.com/noboruma/secwrap/internal/monitor"
)

func TestPrintCaps(t *testing.T) {
	full := monitor.Caps{Kernel: "6.12.1", Machine: "x86_64", BTF: true, Kprobes: true, CgroupV2: true,
		SeccompNotif: true, Freeze: true, LSM: true}
	noLSM := full
	noLSM.Machine, noLSM.LSM, noLSM.LSMWhy, noLSM.Freeze, noLSM.Kernel = "armv7l", false, "armv7l kernels can't run BPF LSM programs", false, "5.15.0"
	for _, c := range []struct {
		caps monitor.Caps
		want []string
	}{
		{full, []string{"network     log ask deny\n", "filesystem  log ask deny\n"}},
		{noLSM, []string{"network     log deny      (ask needs cgroup v2 and Linux 5.19+ to freeze the command)",
			"filesystem  unavailable   (armv7l kernels can't run BPF LSM programs)\n", "sbom        unavailable"}},
	} {
		var b strings.Builder
		printCaps(&b, c.caps)
		t.Log("\n" + b.String())
		for _, w := range c.want {
			if !strings.Contains(b.String(), w) {
				t.Errorf("missing %q in:\n%s", w, b.String())
			}
		}
	}
}

func TestCapsCheck(t *testing.T) {
	c := monitor.Caps{BTF: true, Kprobes: true, CgroupV2: true, SeccompNotif: true, Freeze: true, LSMWhy: `"bpf" not in /sys/kernel/security/lsm`}
	ok := monitor.Options{Net: true, NetAction: monitor.ActionAsk}
	if err := c.Check(&ok); err != nil {
		t.Errorf("--net ask: %v", err)
	}
	bad := monitor.Options{Net: true, Files: true, FilesAction: monitor.ActionDeny}
	err := c.Check(&bad)
	if err == nil || !strings.Contains(err.Error(), "--filesystem is not available") || !strings.Contains(err.Error(), `"bpf" not in`) {
		t.Errorf("--filesystem deny without the LSM: got %v", err)
	}
	t.Log(err)
	noCgroup := monitor.Caps{BTF: true, Kprobes: true, SeccompNotif: true}
	err = noCgroup.Check(&monitor.Options{Net: true, NetAction: monitor.ActionDeny})
	if err == nil || !strings.Contains(err.Error(), "--net can log") {
		t.Errorf("--net deny without cgroup v2: got %v", err)
	}
	t.Log(err)
	noFreeze := monitor.Caps{BTF: true, Kprobes: true, CgroupV2: true, SeccompNotif: true}
	err = noFreeze.Check(&monitor.Options{Net: true, NetAction: monitor.ActionAsk})
	if err == nil || !strings.Contains(err.Error(), "--net can log deny") {
		t.Errorf("--net ask without freezing: got %v", err)
	}
	t.Log(err)
}
