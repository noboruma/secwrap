//go:build linux && !arm64 && !riscv64 && !loong64

package monitor

import "golang.org/x/sys/unix"

// open(2) and creat(2): not on the architectures that only have openat.
const (
	sysOpen  = unix.SYS_OPEN
	sysCreat = unix.SYS_CREAT
)
