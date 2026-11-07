//go:build linux

package monitor

// The eBPF object is built once per byte order, not per CPU, so the kprobes
// can't use the compile-time register names of bpf_tracing.h. Instead, the
// position of the first arguments and of the return value in struct pt_regs
// is read here from the running kernel's BTF, and handed to the programs as
// constants (regs_arg, regs_rc, kword in common.bpf.h).

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// regRef names a pt_regs member, and an index when it is an array.
type regRef struct {
	name  string
	index int // -1: not an array
}

// callRegs: where the calling convention of each kernel architecture puts
// the first three arguments and the return value.
func callRegs(machine string) (args [3]regRef, rc regRef, err error) {
	r := func(name string) regRef { return regRef{name, -1} }
	a := func(name string, i int) regRef { return regRef{name, i} }
	switch {
	case machine == "x86_64":
		return [3]regRef{r("di"), r("si"), r("dx")}, r("ax"), nil
	case len(machine) == 4 && machine[0] == 'i' && strings.HasSuffix(machine, "86"): // i386..i686: regparm(3)
		return [3]regRef{r("ax"), r("dx"), r("cx")}, r("ax"), nil
	case machine == "aarch64" || machine == "arm64":
		return [3]regRef{a("regs", 0), a("regs", 1), a("regs", 2)}, a("regs", 0), nil
	case strings.HasPrefix(machine, "arm"):
		return [3]regRef{a("uregs", 0), a("uregs", 1), a("uregs", 2)}, a("uregs", 0), nil
	case strings.HasPrefix(machine, "mips"): // o32, n32 and n64: a0-a2 are $4-$6, v0 is $2
		return [3]regRef{a("regs", 4), a("regs", 5), a("regs", 6)}, a("regs", 2), nil
	case strings.HasPrefix(machine, "riscv"):
		return [3]regRef{r("a0"), r("a1"), r("a2")}, r("a0"), nil
	case strings.HasPrefix(machine, "loongarch"):
		return [3]regRef{a("regs", 4), a("regs", 5), a("regs", 6)}, a("regs", 4), nil
	case strings.HasPrefix(machine, "ppc"):
		return [3]regRef{a("gpr", 3), a("gpr", 4), a("gpr", 5)}, a("gpr", 3), nil
	case machine == "s390x":
		return [3]regRef{a("gprs", 2), a("gprs", 3), a("gprs", 4)}, a("gprs", 2), nil
	}
	return args, rc, fmt.Errorf("unsupported kernel architecture %q", machine)
}

// setKernelRegs sets regs_arg, regs_rc and kword in spec for this kernel.
func setKernelRegs(spec *ebpf.CollectionSpec) error {
	machine, err := unameMachine()
	if err != nil {
		return err
	}
	args, rc, err := callRegs(machine)
	if err != nil {
		return err
	}
	kspec, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("kernel BTF (needed to find the kprobe arguments): %w", err)
	}
	var regs *btf.Struct
	if err := kspec.TypeByName("pt_regs", &regs); err != nil {
		return fmt.Errorf("kernel BTF: struct pt_regs: %w", err)
	}
	var off [3]uint32
	word := uint32(0)
	for i, ref := range args {
		o, size, err := regOffset(regs, ref)
		if err != nil {
			return fmt.Errorf("%s kernel: %w", machine, err)
		}
		if word != 0 && size != word {
			return fmt.Errorf("%s kernel: pt_regs registers of different sizes", machine)
		}
		off[i], word = o, size
	}
	rcOff, _, err := regOffset(regs, rc)
	if err != nil {
		return fmt.Errorf("%s kernel: %w", machine, err)
	}
	if word != 4 && word != 8 {
		return fmt.Errorf("%s kernel: %d-byte registers", machine, word)
	}
	for name, v := range map[string]any{"regs_arg": off, "regs_rc": rcOff, "kword": word} {
		if err := spec.Variables[name].Set(v); err != nil {
			return fmt.Errorf("set %s: %w", name, err)
		}
	}
	return nil
}

// regOffset finds ref in s, also inside anonymous struct and union members
// (arm64 wraps regs[] in one), and returns its byte offset and size.
func regOffset(s btf.Type, ref regRef) (uint32, uint32, error) {
	off, typ, ok := findMember(s, ref.name)
	if !ok {
		return 0, 0, fmt.Errorf("no %q in struct pt_regs", ref.name)
	}
	if ref.index >= 0 {
		arr, isArr := btf.UnderlyingType(typ).(*btf.Array)
		if !isArr || uint32(ref.index) >= arr.Nelems {
			return 0, 0, fmt.Errorf("pt_regs.%s is not an array of %d+ registers", ref.name, ref.index+1)
		}
		typ = arr.Type
	}
	size, err := btf.Sizeof(typ)
	if err != nil {
		return 0, 0, err
	}
	if ref.index >= 0 {
		off += uint32(ref.index * size)
	}
	if off+uint32(size) > 512 {
		return 0, 0, errors.New("pt_regs register beyond 512 bytes")
	}
	return off, uint32(size), nil
}

func findMember(s btf.Type, name string) (uint32, btf.Type, bool) {
	for _, m := range compositeMembers(s) {
		if m.Name == name {
			return m.Offset.Bytes(), m.Type, true
		}
		if m.Name == "" {
			if o, t, ok := findMember(btf.UnderlyingType(m.Type), name); ok {
				return m.Offset.Bytes() + o, t, true
			}
		}
	}
	return 0, nil, false
}

// compositeMembers: the members of a struct or union, nil for other types.
func compositeMembers(c btf.Type) []btf.Member {
	switch t := c.(type) {
	case *btf.Struct:
		return t.Members
	case *btf.Union:
		return t.Members
	}
	return nil
}

// unameMachine is the kernel's architecture (uname -m), which may differ
// from secwrap's own (a 32-bit build on a 64-bit kernel).
func unameMachine() (string, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", err
	}
	return unix.ByteSliceToString(u.Machine[:]), nil
}
