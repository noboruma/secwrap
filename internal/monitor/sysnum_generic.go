//go:build linux && (arm64 || riscv64 || loong64)

package monitor

// These architectures only have openat(2) and openat2(2).
const (
	sysOpen  = noSyscall
	sysCreat = noSyscall
)
