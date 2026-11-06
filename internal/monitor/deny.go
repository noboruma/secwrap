//go:build linux

package monitor

import (
	"bufio"
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

// denyCgroup is a dedicated cgroup v2 with the deny programs attached.
// Every process placed in it loses all IPv4/IPv6 network access.
type denyCgroup struct {
	objs   denyObjects
	path   string
	dir    *os.File
	links  []link.Link
	origin map[int]string // attach mode: pid -> cgroup dir to restore
}

func setupDeny(spec *ebpf.CollectionSpec, events *ebpf.Map) (*denyCgroup, error) {
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		return nil, fmt.Errorf("deny mode needs cgroup v2 mounted at %s", cgroupRoot)
	}
	d := &denyCgroup{origin: map[int]string{}}
	opts := &ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{"events": events}}
	if err := spec.LoadAndAssign(&d.objs, opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("deny programs rejected by verifier: %+v", ve)
		}
		return nil, fmt.Errorf("load deny programs: %w", err)
	}

	d.path = filepath.Join(cgroupRoot, fmt.Sprintf("secwrap-deny-%d", os.Getpid()))
	if err := os.Mkdir(d.path, 0o755); err != nil {
		d.objs.Close()
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
		l, err := link.AttachCgroup(link.CgroupOptions{Path: d.path, Attach: a.typ, Program: a.prog})
		if err != nil {
			d.Close()
			return nil, fmt.Errorf("attach deny program (%s): %w", a.typ, err)
		}
		d.links = append(d.links, l)
	}

	dir, err := os.Open(d.path)
	if err != nil {
		d.Close()
		return nil, err
	}
	d.dir = dir
	return d, nil
}

// FD is the cgroup directory fd, for spawning a child directly inside it.
func (d *denyCgroup) FD() int { return int(d.dir.Fd()) }

// addPID moves a running process (all its threads) into the deny cgroup and
// remembers where it came from. Its future children inherit the cgroup.
func (d *denyCgroup) addPID(pid int) error {
	orig, err := cgroupOf(pid)
	if err != nil {
		return err
	}
	if err := writeProcs(d.path, pid); err != nil {
		return fmt.Errorf("move pid %d into deny cgroup: %w", pid, err)
	}
	d.origin[pid] = orig
	return nil
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

// kill sends SIGKILL to every process still in the cgroup (cgroup.kill).
func (d *denyCgroup) kill() {
	_ = os.WriteFile(filepath.Join(d.path, "cgroup.kill"), []byte("1"), 0)
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

// Close moves any processes still in the deny cgroup back to where they came
// from (or to our own cgroup), detaches the programs and removes the cgroup.
// Once this returns, those processes have normal network access again.
func (d *denyCgroup) Close() {
	if d.path != "" {
		fallback := ""
		for _, o := range d.origin {
			fallback = o
			break
		}
		if fallback == "" {
			fallback, _ = cgroupOf(os.Getpid())
		}
		for _, pid := range readProcs(d.path) {
			dst := d.origin[pid]
			if dst == "" {
				dst = fallback
			}
			if dst != "" {
				_ = writeProcs(dst, pid)
			}
		}
	}
	for _, l := range d.links {
		l.Close()
	}
	d.objs.Close()
	if d.dir != nil {
		d.dir.Close()
	}
	if d.path != "" {
		// rmdir fails with EBUSY while exiting tasks are still accounted.
		for i := 0; i < 20; i++ {
			if err := os.Remove(d.path); err == nil || os.IsNotExist(err) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// cgroupOf returns the absolute cgroup v2 directory of pid.
func cgroupOf(pid int) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			return filepath.Join(cgroupRoot, rest), nil
		}
	}
	return "", fmt.Errorf("pid %d: no cgroup v2 membership", pid)
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
