//go:build linux && (386 || mips || mipsle)

package monitor

import "golang.org/x/sys/unix"

// socketcall(2) multiplexes the socket syscalls on these architectures; C
// libraries may use it instead of connect(2) and friends.
const sysSocketcall = unix.SYS_SOCKETCALL
