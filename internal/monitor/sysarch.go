//go:build linux

package monitor

// What ask mode needs to know about the CPU it runs on: the seccomp audit
// architecture, which syscalls exist, and the size of pointers in the
// target. The target runs the same architecture as secwrap:
// the seccomp filter traps native syscalls only, and other ABIs (i386 on
// x86_64, arm on arm64) go through, still refused by the BPF hooks.

import (
	"encoding/binary"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ptrSize is the size of a pointer in the target.
const ptrSize = uint64(unsafe.Sizeof(uintptr(0)))

// noSyscall marks a syscall this architecture doesn't have.
const noSyscall = -1

// auditArch is the AUDIT_ARCH_* value seccomp reports for native syscalls.
func auditArch() (uint32, bool) {
	big := binary.NativeEndian.Uint16([]byte{0, 1}) == 1
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64, true
	case "386":
		return unix.AUDIT_ARCH_I386, true
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64, true
	case "arm":
		if big {
			return unix.AUDIT_ARCH_ARMEB, true
		}
		return unix.AUDIT_ARCH_ARM, true
	case "mips":
		return unix.AUDIT_ARCH_MIPS, true
	case "mipsle":
		return unix.AUDIT_ARCH_MIPSEL, true
	case "mips64":
		return unix.AUDIT_ARCH_MIPS64, true
	case "mips64le":
		return unix.AUDIT_ARCH_MIPSEL64, true
	case "riscv64":
		return unix.AUDIT_ARCH_RISCV64, true
	case "loong64":
		return unix.AUDIT_ARCH_LOONGARCH64, true
	case "ppc64":
		return unix.AUDIT_ARCH_PPC64, true
	case "ppc64le":
		return unix.AUDIT_ARCH_PPC64LE, true
	case "s390x":
		return unix.AUDIT_ARCH_S390X, true
	}
	return 0, false
}

// readPtr reads a pointer of the target's size at addr.
func readPtr(tid int, addr uint64) (uint64, bool) {
	var b [8]byte
	if !readMem(tid, addr, b[:ptrSize]) {
		return 0, false
	}
	if ptrSize == 4 {
		return uint64(binary.NativeEndian.Uint32(b[:4])), true
	}
	return binary.NativeEndian.Uint64(b[:]), true
}
