//go:build linux && !(386 || mips || mipsle)

package monitor

const sysSocketcall = noSyscall
