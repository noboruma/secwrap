//go:build linux

package monitor

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
)

const cgroupRoot = "/sys/fs/cgroup"

// traceObjects is the subset of the BPF collection used for observation.
// Loading it separately keeps plain monitoring working even if the deny
// programs cannot be loaded on this kernel.
type traceObjects struct {
	HandleFork       *ebpf.Program `ebpf:"handle_fork"`
	HandleExit       *ebpf.Program `ebpf:"handle_exit"`
	KpTcpConnect     *ebpf.Program `ebpf:"kp_tcp_connect"`
	KrpInetCskAccept *ebpf.Program `ebpf:"krp_inet_csk_accept"`
	KpUdpSendmsg     *ebpf.Program `ebpf:"kp_udp_sendmsg"`
	KpUdpv6Sendmsg   *ebpf.Program `ebpf:"kp_udpv6_sendmsg"`

	Events  *ebpf.Map `ebpf:"events"`
	Tracked *ebpf.Map `ebpf:"tracked"`
}

func (o *traceObjects) Close() {
	for _, c := range []interface{ Close() error }{
		o.HandleFork, o.HandleExit, o.KpTcpConnect, o.KrpInetCskAccept,
		o.KpUdpSendmsg, o.KpUdpv6Sendmsg, o.Events, o.Tracked,
	} {
		if c != nil {
			c.Close()
		}
	}
}

// denyObjects are the cgroup programs that block all network access.
type denyObjects struct {
	DenyConnect4 *ebpf.Program `ebpf:"deny_connect4"`
	DenyConnect6 *ebpf.Program `ebpf:"deny_connect6"`
	DenySendmsg4 *ebpf.Program `ebpf:"deny_sendmsg4"`
	DenySendmsg6 *ebpf.Program `ebpf:"deny_sendmsg6"`
	DenyEgress   *ebpf.Program `ebpf:"deny_egress"`
	DenyIngress  *ebpf.Program `ebpf:"deny_ingress"`

	Dropped *ebpf.Map `ebpf:"dropped"`
	Allow   *ebpf.Map `ebpf:"allow"`
}

func (o *denyObjects) Close() {
	for _, c := range []interface{ Close() error }{
		o.DenyConnect4, o.DenyConnect6, o.DenySendmsg4, o.DenySendmsg6,
		o.DenyEgress, o.DenyIngress, o.Dropped, o.Allow,
	} {
		if c != nil {
			c.Close()
		}
	}
}

// probeDenyHelpers sets the have_*_helper constants so the deny programs only
// use current-task helpers this kernel allows for cgroup sock_addr programs.
func probeDenyHelpers(spec *ebpf.CollectionSpec) error {
	set := func(name string, fn asm.BuiltinFunc) error {
		v := uint8(0)
		if features.HaveProgramHelper(ebpf.CGroupSockAddr, fn) == nil {
			v = 1
		}
		return spec.Variables[name].Set(v)
	}
	if err := set("have_pid_helper", asm.FnGetCurrentPidTgid); err != nil {
		return err
	}
	return set("have_comm_helper", asm.FnGetCurrentComm)
}

// denyCgroup holds the deny programs and the cgroups they are attached to.
// Every process placed in one of those cgroups loses all IPv4/IPv6 network
// access (except what allow lets through).
//
// A process is never moved out of the cgroup it is in: it goes into a
// child "secwrap-deny-<pid>" of that cgroup, created on first use, so the
// limits and accounting of its container or systemd unit keep applying
// (cgroup v2 limits are hierarchical). The launched command gets a child
// of secwrap's own cgroup. Where a child cannot be created or used, one at
// the cgroup root is the fallback.
type denyCgroup struct {
	objs   denyObjects
	name   string              // directory name under each parent cgroup
	dirs   map[string]*denyDir // by the cgroup it serves (fallbacks share the root one)
	origin map[int]string      // attached pid -> cgroup to move it back to
}

// denyDir is one cgroup with the deny programs attached.
type denyDir struct {
	path    string
	restore string // where processes not in origin go back on Close
	dir     *os.File
	links   []link.Link
}

func setupDeny(spec *ebpf.CollectionSpec, events *ebpf.Map) (*denyCgroup, error) {
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		return nil, fmt.Errorf("deny mode needs cgroup v2 mounted at %s", cgroupRoot)
	}
	d := &denyCgroup{
		name:   fmt.Sprintf("secwrap-deny-%d", os.Getpid()),
		dirs:   map[string]*denyDir{},
		origin: map[int]string{},
	}
	opts := &ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{"events": events}}
	if err := spec.LoadAndAssign(&d.objs, opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("deny programs rejected by verifier: %+v", ve)
		}
		return nil, fmt.Errorf("load deny programs: %w", err)
	}
	return d, nil
}

// dirFor returns the deny cgroup for processes currently in parent,
// creating it as a child of parent (or, failing that, of the root).
func (d *denyCgroup) dirFor(parent string) (*denyDir, error) {
	if dd := d.dirs[parent]; dd != nil {
		return dd, nil
	}
	dd, err := d.create(parent)
	if err != nil && parent != cgroupRoot {
		// e.g. a threaded cgroup, or one we may not write to.
		if root, rerr := d.dirFor(cgroupRoot); rerr == nil {
			d.dirs[parent] = root
			return root, nil
		}
	}
	if err != nil {
		return nil, err
	}
	d.dirs[parent] = dd
	return dd, nil
}

func (d *denyCgroup) create(parent string) (*denyDir, error) {
	dd := &denyDir{path: filepath.Join(parent, d.name), restore: parent}
	if parent == cgroupRoot {
		// Shared fallback: the launched command's processes go back to
		// secwrap's cgroup (attached ones have their own origin).
		if own, err := cgroupOf(os.Getpid()); err == nil {
			dd.restore = own
		}
	}
	if err := os.Mkdir(dd.path, 0o755); err != nil {
		return nil, fmt.Errorf("create cgroup: %w", err)
	}
	attachments := []struct {
		typ  ebpf.AttachType
		prog *ebpf.Program
	}{
		{ebpf.AttachCGroupInet4Connect, d.objs.DenyConnect4},
		{ebpf.AttachCGroupInet6Connect, d.objs.DenyConnect6},
		{ebpf.AttachCGroupUDP4Sendmsg, d.objs.DenySendmsg4},
		{ebpf.AttachCGroupUDP6Sendmsg, d.objs.DenySendmsg6},
		{ebpf.AttachCGroupInetEgress, d.objs.DenyEgress},
		{ebpf.AttachCGroupInetIngress, d.objs.DenyIngress},
	}
	for _, a := range attachments {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: dd.path, Attach: a.typ, Program: a.prog})
		if err != nil {
			dd.close(nil)
			return nil, fmt.Errorf("attach deny program (%s): %w", a.typ, err)
		}
		dd.links = append(dd.links, l)
	}
	dir, err := os.Open(dd.path)
	if err != nil {
		dd.close(nil)
		return nil, err
	}
	dd.dir = dir
	return dd, nil
}

// home is the deny cgroup for the launched command: a child of secwrap's
// own cgroup.
func (d *denyCgroup) home() (*denyDir, error) {
	own, err := cgroupOf(os.Getpid())
	if err != nil {
		own = cgroupRoot
	}
	return d.dirFor(own)
}

// FD is the cgroup directory fd, for spawning a child directly inside it.
func (dd *denyDir) FD() int { return int(dd.dir.Fd()) }

// addPID moves a running process (all its threads) into the deny cgroup
// under its current cgroup and remembers where it came from. Its future
// children inherit the cgroup.
func (d *denyCgroup) addPID(pid int) error {
	orig, err := cgroupOf(pid)
	if err != nil {
		return err
	}
	if d.isOurs(orig) {
		return nil // already in (e.g. a child that inherited it meanwhile)
	}
	dd, err := d.dirFor(orig)
	if err != nil {
		return err
	}
	err = writeProcs(dd.path, pid)
	if err != nil && orig != cgroupRoot && dd != d.dirs[cgroupRoot] {
		if root, rerr := d.dirFor(cgroupRoot); rerr == nil && writeProcs(root.path, pid) == nil {
			err = nil
		}
	}
	if err != nil {
		return fmt.Errorf("move pid %d into deny cgroup: %w", pid, err)
	}
	d.origin[pid] = orig
	return nil
}

// isOurs reports whether path is one of the deny cgroups.
func (d *denyCgroup) isOurs(path string) bool {
	for _, dd := range d.dirs {
		if dd.path == path {
			return true
		}
	}
	return false
}

// unique lists each deny cgroup once (fallbacks share the root one).
func (d *denyCgroup) unique() []*denyDir {
	seen := map[*denyDir]bool{}
	var out []*denyDir
	for _, dd := range d.dirs {
		if !seen[dd] {
			seen[dd] = true
			out = append(out, dd)
		}
	}
	return out
}

// allow lets the cgroup reach addr (port 0 = any port): connects, UDP sends
// and the packets of those flows.
func (d *denyCgroup) allow(addr netip.Addr, port uint16) error {
	return d.objs.Allow.Put(peerKey(addr, port), uint8(1))
}

// disallow removes a rule added by allow.
func (d *denyCgroup) disallow(addr netip.Addr, port uint16) error {
	err := d.objs.Allow.Delete(peerKey(addr, port))
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

type allowKey struct {
	Family uint16
	Port   uint16
	Addr   [16]byte
}

func peerKey(addr netip.Addr, port uint16) allowKey {
	var k allowKey
	addr = addr.Unmap()
	if addr.Is4() {
		k.Family = afInet
		a4 := addr.As4()
		copy(k.Addr[:], a4[:])
	} else {
		k.Family, k.Addr = afInet6, addr.As16()
	}
	k.Port = port
	return k
}

// kill sends SIGKILL to every process still in the deny cgroups (cgroup.kill).
func (d *denyCgroup) kill() {
	for _, dd := range d.unique() {
		_ = os.WriteFile(filepath.Join(dd.path, "cgroup.kill"), []byte("1"), 0)
	}
}

// dropped returns how many packets the skb programs dropped (egress, ingress).
func (d *denyCgroup) dropped() (egress, ingress uint64) {
	sum := func(idx uint32) uint64 {
		var vals []uint64
		if err := d.objs.Dropped.Lookup(idx, &vals); err != nil {
			return 0
		}
		var n uint64
		for _, v := range vals {
			n += v
		}
		return n
	}
	return sum(0), sum(1)
}

// Close moves any processes still in the deny cgroups back to where they
// came from, detaches the programs and removes the cgroups. Once this
// returns, those processes have normal network access again.
func (d *denyCgroup) Close() {
	for _, dd := range d.unique() {
		dd.close(d.origin)
	}
	d.objs.Close()
}

func (dd *denyDir) close(origin map[int]string) {
	for _, pid := range readProcs(dd.path) {
		dst := origin[pid]
		if dst == "" {
			dst = dd.restore
		}
		if writeProcs(dst, pid) != nil && dst != dd.restore {
			_ = writeProcs(dd.restore, pid) // origin gone meanwhile
		}
	}
	for _, l := range dd.links {
		l.Close()
	}
	if dd.dir != nil {
		dd.dir.Close()
	}
	// rmdir fails with EBUSY while exiting tasks are still accounted.
	for i := 0; i < 20; i++ {
		if err := os.Remove(dd.path); err == nil || os.IsNotExist(err) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// cgroupOf returns the absolute cgroup v2 directory of pid.
func cgroupOf(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	path, err := parseCgroup(string(data))
	if err != nil {
		return "", fmt.Errorf("pid %d: %w", pid, err)
	}
	return path, nil
}

// parseCgroup returns the cgroup v2 directory in the contents of a
// /proc/PID/cgroup file.
func parseCgroup(data string) (string, error) {
	for _, line := range strings.Split(data, "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			// Relative to our cgroup namespace: "/.." means outside it.
			rest = strings.TrimSuffix(rest, " (deleted)")
			if rest == "/.." || strings.HasPrefix(rest, "/../") {
				return "", fmt.Errorf("cgroup %s is outside secwrap's cgroup namespace", rest)
			}
			return filepath.Join(cgroupRoot, rest), nil
		}
	}
	return "", errors.New("no cgroup v2 membership")
}

func writeProcs(dir string, pid int) error {
	return os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0)
}

func readProcs(dir string) []int {
	data, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return nil
	}
	var out []int
	for _, f := range strings.Fields(string(data)) {
		if pid, err := strconv.Atoi(f); err == nil {
			out = append(out, pid)
		}
	}
	return out
}
