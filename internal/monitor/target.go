//go:build linux

package monitor

// Reading a paused task: syscall arguments from its memory (sockaddrs,
// paths), its sockets, and its view of the file system.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// readArgv reads up to 32 arguments of an execve argv array (each cut to
// 256 bytes), for display.
func readArgv(tid int, ptr uint64) []string {
	var args []string
	for i := uint64(0); ptr != 0 && i < 32; i++ {
		var p [8]byte
		if !readMem(tid, ptr+i*8, p[:]) {
			break
		}
		a := binary.NativeEndian.Uint64(p[:])
		if a == 0 {
			break
		}
		s, ok := readCString(tid, a, 256)
		if !ok {
			s = "…"
		}
		args = append(args, s)
	}
	return args
}

// readCString reads a NUL-terminated string of at most max bytes from the
// target, page by page so an unmapped page after the string is no problem.
func readCString(tid int, addr uint64, max int) (string, bool) {
	if addr == 0 {
		return "", false
	}
	const page = 4096
	var out []byte
	for len(out) < max {
		n := int(page - addr%page)
		buf := make([]byte, min(n, max-len(out)))
		if !readMem(tid, addr, buf) {
			return "", false
		}
		if i := bytes.IndexByte(buf, 0); i >= 0 {
			return string(append(out, buf[:i]...)), true
		}
		out = append(out, buf...)
		addr += uint64(len(buf))
	}
	return "", false
}

// resolveOpenPath turns the path given to open into the absolute path the
// kernel will report (d_path), from the target's point of view: relative to
// its cwd or dirfd, following symlinks, with /proc/self meaning the target.
// With create, a missing last component is fine (the file will be created).
func resolveOpenPath(tgid, tid int, dirfd int32, p string, create bool) (string, error) {
	if p == "" {
		return "", fs.ErrNotExist
	}
	resolved := "/"
	if !strings.HasPrefix(p, "/") {
		link := fmt.Sprintf("/proc/%d/fd/%d", tgid, dirfd)
		if dirfd == unix.AT_FDCWD {
			link = fmt.Sprintf("/proc/%d/task/%d/cwd", tgid, tid)
		}
		base, err := os.Readlink(link)
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(base, "/") {
			return "", fs.ErrInvalid
		}
		resolved = filepath.Clean(base)
	}

	pending := strings.Split(p, "/")
	links := 0
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		if resolved == "/proc" {
			switch c {
			case "self":
				c = strconv.Itoa(tgid)
			case "thread-self":
				resolved, c = fmt.Sprintf("/proc/%d/task", tgid), strconv.Itoa(tid)
			}
		}
		next := filepath.Join(resolved, c)
		fi, err := os.Lstat(next)
		if err != nil {
			if create && errors.Is(err, fs.ErrNotExist) && onlyTrivial(pending) {
				return next, nil
			}
			return "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			resolved = next
			continue
		}
		if links++; links > 40 {
			return "", unix.ELOOP
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(next, "/proc/") && !strings.HasPrefix(target, "/") {
			return target, nil // magic link to a pipe/socket/anon inode: not a path
		}
		if strings.HasPrefix(target, "/") {
			resolved = "/"
		}
		pending = append(strings.Split(target, "/"), pending...)
	}
	return resolved, nil
}

func onlyTrivial(cs []string) bool {
	for _, c := range cs {
		if c != "" && c != "." {
			return false
		}
	}
	return true
}

// appendPeer reads a sockaddr from the target and appends it if it is an
// IPv4/IPv6 address.
func appendPeer(out []netip.AddrPort, tid int, ptr, n uint64) []netip.AddrPort {
	if ptr == 0 || n < 16 {
		return out
	}
	var sa [28]byte // sizeof(sockaddr_in6)
	b := sa[:min(n, uint64(len(sa)))]
	if !readMem(tid, ptr, b) {
		return out
	}
	port := binary.BigEndian.Uint16(b[2:4])
	switch binary.NativeEndian.Uint16(b[0:2]) {
	case unix.AF_INET:
		return append(out, netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[4:8])), port))
	case unix.AF_INET6:
		if len(b) < 24 {
			return out
		}
		return append(out, netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[8:24])).Unmap(), port))
	}
	return out
}

// appendMsgPeer reads msg_name/msg_namelen from a struct msghdr.
func appendMsgPeer(out []netip.AddrPort, tid int, msghdr uint64) []netip.AddrPort {
	var h [12]byte // void *msg_name; socklen_t msg_namelen
	if msghdr == 0 || !readMem(tid, msghdr, h[:]) {
		return out
	}
	return appendPeer(out, tid, binary.NativeEndian.Uint64(h[0:8]), uint64(binary.NativeEndian.Uint32(h[8:12])))
}

func readMem(tid int, addr uint64, b []byte) bool {
	local := []unix.Iovec{{Base: &b[0], Len: uint64(len(b))}}
	remote := []unix.RemoteIovec{{Base: uintptr(addr), Len: len(b)}}
	n, err := unix.ProcessVMReadv(tid, local, remote, 0)
	return err == nil && n == len(b)
}

// sockProto copies the target's socket fd to ask its type.
func sockProto(tid, fd int) string {
	pidfd, err := unix.PidfdOpen(tgidOf(tid), 0)
	if err != nil {
		return ""
	}
	defer unix.Close(pidfd)
	sfd, err := unix.PidfdGetfd(pidfd, fd, 0)
	if err != nil {
		return ""
	}
	defer unix.Close(sfd)
	typ, err := unix.GetsockoptInt(sfd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return ""
	}
	switch typ {
	case unix.SOCK_STREAM:
		return "tcp"
	case unix.SOCK_DGRAM:
		return "udp"
	}
	return ""
}

func readComm(tid int) string {
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", tid))
	return strings.TrimSpace(string(b))
}

func tgidOf(tid int) int {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return tid
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "Tgid:"); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				return n
			}
		}
	}
	return tid
}
