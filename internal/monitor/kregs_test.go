//go:build linux

package monitor

import (
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestRegOffsetAnonymousUnion(t *testing.T) {
	// arm64: struct pt_regs { union { struct user_pt_regs user_regs;
	// struct { u64 regs[31]; u64 sp; ... }; }; u64 orig_x0; ... }
	u64 := &btf.Int{Name: "u64", Size: 8}
	regs := &btf.Array{Type: u64, Nelems: 31}
	inner := &btf.Struct{Size: 31*8 + 8, Members: []btf.Member{
		{Name: "regs", Type: regs},
		{Name: "sp", Type: u64, Offset: btf.Bits(31 * 64)},
	}}
	union := &btf.Union{Size: inner.Size, Members: []btf.Member{{Name: "", Type: inner}}}
	pt := &btf.Struct{Name: "pt_regs", Size: inner.Size + 8, Members: []btf.Member{
		{Name: "", Type: union},
		{Name: "orig_x0", Type: u64, Offset: btf.Bits(inner.Size * 8)},
	}}
	for _, c := range []struct {
		ref      regRef
		off, len uint32
	}{{regRef{"regs", 0}, 0, 8}, {regRef{"regs", 2}, 16, 8}, {regRef{"sp", -1}, 248, 8}} {
		off, size, err := regOffset(pt, c.ref)
		if err != nil || off != c.off || size != c.len {
			t.Errorf("%v: got %d, %d, %v; want %d, %d", c.ref, off, size, err, c.off, c.len)
		}
	}
	if _, _, err := regOffset(pt, regRef{"regs", 31}); err == nil {
		t.Error("regs[31]: want an error")
	}
}

func TestRegOffsetRunningKernel(t *testing.T) {
	kspec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skip("no kernel BTF:", err)
	}
	var regs *btf.Struct
	if err := kspec.TypeByName("pt_regs", &regs); err != nil {
		t.Fatal(err)
	}
	args, rc, err := callRegs(kernelMachine(t))
	if err != nil {
		t.Skip(err)
	}
	for _, ref := range append(args[:], rc) {
		off, size, err := regOffset(regs, ref)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("pt_regs.%s[%d]: offset %d, %d bytes", ref.name, ref.index, off, size)
	}
}

func kernelMachine(t *testing.T) string {
	m, err := unameMachine()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSpecHasRegsVariables(t *testing.T) {
	spec, err := loadSecwrap()
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]any{"regs_arg": [3]uint32{112, 104, 96}, "regs_rc": uint32(80), "kword": uint32(4)} {
		if err := spec.Variables[name].Set(v); err != nil {
			t.Errorf("set %s: %v", name, err)
		}
	}
	if n := len(spec.Programs); n != 14 {
		t.Errorf("%d programs, want 14", n)
	}
}
