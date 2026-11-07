//go:build linux

package monitor

// The seccomp side of ask mode. secwrap re-execs itself as a helper in the
// child: the helper installs a filter turning the trapped syscalls into
// SECCOMP_RET_USER_NOTIF, hands the listener fd to the parent and execs the
// target, which can then never hold the listener itself.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// AskHelperArg is the hidden argv[1] that makes secwrap act as the
// seccomp-installing exec helper. main must call RunAskHelper for it.
const AskHelperArg = "__secwrap-ask-exec"

// seccomp UAPI structs (not in x/sys/unix).
type seccompData struct {
	Nr                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

type seccompNotif struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  seccompData
}

type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

// ---------------------------------------------------------------------------
// Helper side: runs in the child, between fork and exec of the target.

var (
	netSyscalls  = syscalls(unix.SYS_CONNECT, unix.SYS_SENDTO, unix.SYS_SENDMSG, unix.SYS_SENDMMSG, sysSocketcall)
	fileSyscalls = syscalls(sysOpen, unix.SYS_OPENAT, unix.SYS_OPENAT2, sysCreat)
	execSyscalls = syscalls(unix.SYS_EXECVE, unix.SYS_EXECVEAT)
)

// syscalls leaves out those this architecture doesn't have.
func syscalls(nrs ...int) []uint32 {
	var out []uint32
	for _, nr := range nrs {
		if nr != noSyscall {
			out = append(out, uint32(nr))
		}
	}
	return out
}

// RunAskHelper installs the seccomp filter, hands the listener fd to the
// parent (fd 3 is a socketpair to it), waits for the ack, then execs the
// target. args is MODE CMD [ARGS...], MODE a comma list of net, files, exec.
// It never returns.
func RunAskHelper(args []string) {
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, "secwrap: ask helper:", err)
		os.Exit(127)
	}
	if len(args) < 2 {
		fail(errors.New("usage: MODE CMD [ARGS...]"))
	}
	var nrs []uint32
	for _, m := range strings.Split(args[0], ",") {
		switch m {
		case "net":
			nrs = append(nrs, netSyscalls...)
		case "files":
			nrs = append(nrs, fileSyscalls...)
		case "exec":
			nrs = append(nrs, execSyscalls...)
		default:
			fail(fmt.Errorf("unknown mode %q", m))
		}
	}
	argv := args[1:]
	// The filter is per-thread: install it and exec on the same OS thread.
	runtime.LockOSThread()

	path, err := exec.LookPath(argv[0])
	if err != nil {
		fail(err)
	}
	ctl := os.NewFile(3, "ask-ctl")

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fail(fmt.Errorf("no_new_privs: %w", err))
	}
	lfd, killable, err := installNotifyFilter(nrs)
	if err != nil {
		fail(fmt.Errorf("seccomp: %w", err))
	}
	// write/read are not trapped by the filter, so this cannot deadlock.
	var buf [4]byte
	v := uint32(lfd)
	if killable {
		v |= killableBit
	}
	binary.NativeEndian.PutUint32(buf[:], v)
	if _, err := ctl.Write(buf[:]); err != nil {
		fail(err)
	}
	if _, err := ctl.Read(buf[:1]); err != nil {
		fail(fmt.Errorf("waiting for supervisor: %w", err))
	}
	// The target must never hold the listener (it could approve itself).
	unix.Close(lfd)
	ctl.Close()

	err = unix.Exec(path, argv, os.Environ())
	fail(fmt.Errorf("exec %s: %w", path, err))
}

// seccompWaitKillableRecv is SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (5.19):
// once the supervisor has read a notification, the paused task waits for
// the answer killably, so a signal (or the cgroup freezer, which inline
// questions use) doesn't withdraw the question.
const seccompWaitKillableRecv = 1 << 5

// killableBit, in the listener fd the helper reports, says the filter has
// seccompWaitKillableRecv.
const killableBit = 1 << 31

// installNotifyFilter makes the syscalls in nrs return SECCOMP_RET_USER_NOTIF
// and allows everything else. Other ABIs (x32 numbers, i386 via int 0x80,
// arm on arm64) are allowed: the BPF cgroup/LSM hooks still refuse them.
// killable reports whether the kernel took seccompWaitKillableRecv.
func installNotifyFilter(nrs []uint32) (fd int, killable bool, err error) {
	const (
		ldAbs = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq   = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		ret   = unix.BPF_RET | unix.BPF_K
	)
	arch, ok := auditArch()
	if !ok {
		return -1, false, fmt.Errorf("ask mode is not supported on %s", runtime.GOARCH)
	}
	k := uint8(len(nrs))
	// 0 ld arch | 1 jeq arch | 2 ld nr | 3.. jeq nr_i | 3+k allow | 4+k notify
	filter := []unix.SockFilter{
		{Code: ldAbs, K: 4}, // seccomp_data.arch
		{Code: jeq, K: arch, Jt: 0, Jf: k + 1},
		{Code: ldAbs, K: 0}, // seccomp_data.nr
	}
	for i, nr := range nrs {
		filter = append(filter, unix.SockFilter{Code: jeq, K: nr, Jt: k - uint8(i)})
	}
	filter = append(filter,
		unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW},
		unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_USER_NOTIF},
	)
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	install := func(flags uintptr) (uintptr, unix.Errno) {
		r, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(&prog)))
		return r, errno
	}
	r, errno := install(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER | seccompWaitKillableRecv)
	killable = errno == 0
	if errno == unix.EINVAL { // before 5.19
		r, errno = install(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER)
	}
	runtime.KeepAlive(filter)
	if errno != 0 {
		return -1, false, errno
	}
	return int(r), killable, nil
}

// ---------------------------------------------------------------------------
// Supervisor side.

// askCommand prepares cmd to run the target through the helper. Call
// finish after cmd.Start to collect the listener and release the helper.
// finish's killable: see seccompWaitKillableRecv.
func askCommand(cmd *exec.Cmd, argv []string, net, files, execs bool) (finish func() (lfd int, killable bool, err error), err error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parent, child := os.NewFile(uintptr(fds[0]), "ask-ctl"), os.NewFile(uintptr(fds[1]), "ask-ctl")

	cmd.Path = self
	var modes []string
	if net {
		modes = append(modes, "net")
	}
	if files {
		modes = append(modes, "files")
	}
	if execs {
		modes = append(modes, "exec")
	}
	mode := strings.Join(modes, ",")
	cmd.Args = append([]string{argv[0], AskHelperArg, mode}, argv...)
	cmd.Err = nil // Command's LookPath of the original target is irrelevant now
	cmd.ExtraFiles = []*os.File{child}

	return func() (int, bool, error) {
		defer parent.Close()
		child.Close()
		parent.SetReadDeadline(time.Now().Add(10 * time.Second))
		var buf [4]byte
		if _, err := parent.Read(buf[:]); err != nil {
			return -1, false, fmt.Errorf("ask helper did not report a seccomp listener: %w", err)
		}
		pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
		if err != nil {
			return -1, false, fmt.Errorf("pidfd_open: %w", err)
		}
		defer unix.Close(pidfd)
		v := binary.NativeEndian.Uint32(buf[:])
		lfd, err := unix.PidfdGetfd(pidfd, int(v&^killableBit), 0)
		if err != nil {
			return -1, false, fmt.Errorf("pidfd_getfd (seccomp listener): %w", err)
		}
		if _, err := parent.Write([]byte{1}); err != nil {
			unix.Close(lfd)
			return -1, false, err
		}
		return lfd, v&killableBit != 0, nil
	}, nil
}

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}
