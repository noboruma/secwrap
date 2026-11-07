//go:build ignore

// SPDX-License-Identifier: GPL-2.0
// Network activity: TCP connect/accept and UDP sends by the tracked process
// tree (or everything when trace_all is set), and deny mode on its cgroup.

#include "common.bpf.h"

#define AF_INET  2
#define AF_INET6 10

#define EV_CONNECT  1
#define EV_ACCEPT   2
#define EV_UDP_SEND 3

#define PROTO_TCP 6
#define PROTO_UDP 17

struct event {
	u64 ts_ns;
	u32 pid;   /* thread id */
	u32 tgid;  /* process id */
	u32 uid;
	u16 kind;
	u16 family;
	u16 proto;
	u16 sport; /* host byte order */
	u16 dport; /* host byte order */
	u16 _pad;
	u8  saddr[16];
	u8  daddr[16];
	char comm[16];
};

/* Force BTF emission so bpf2go can generate the Go type. */
const struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

static __always_inline struct event *new_event(u16 kind, u16 proto)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	if (!should_trace(tgid))
		return NULL;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return NULL;
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = bpf_ktime_get_ns();
	e->pid = (u32)id;
	e->tgid = tgid;
	e->uid = (u32)bpf_get_current_uid_gid();
	e->kind = kind;
	e->proto = proto;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

static __always_inline void fill_from_sock(struct event *e, struct sock *sk)
{
	e->family = BPF_CORE_READ(sk, __sk_common.skc_family);
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	/* Note: BPF_CORE_READ_INTO copies sizeof(*dst) bytes, which is 1 for a
	 * u8 array, so copy with explicit sizes instead. */
	if (e->family == AF_INET) {
		bpf_core_read(e->saddr, 4, &sk->__sk_common.skc_rcv_saddr);
		bpf_core_read(e->daddr, 4, &sk->__sk_common.skc_daddr);
	} else if (e->family == AF_INET6) {
		bpf_core_read(e->saddr, 16, &sk->__sk_common.skc_v6_rcv_saddr);
		bpf_core_read(e->daddr, 16, &sk->__sk_common.skc_v6_daddr);
	}
}

/* Outbound TCP: called after route lookup and source port selection. */
SEC("kprobe/tcp_connect")
int BPF_KPROBE(kp_tcp_connect, struct sock *sk)
{
	struct event *e = new_event(EV_CONNECT, PROTO_TCP);
	if (!e)
		return 0;
	fill_from_sock(e, sk);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Inbound TCP: the accepted socket. */
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(krp_inet_csk_accept, struct sock *sk)
{
	if (!sk)
		return 0;
	struct event *e = new_event(EV_ACCEPT, PROTO_TCP);
	if (!e)
		return 0;
	fill_from_sock(e, sk);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int udp_send(struct sock *sk, struct msghdr *msg, u16 family)
{
	struct event *e = new_event(EV_UDP_SEND, PROTO_UDP);
	if (!e)
		return 0;
	fill_from_sock(e, sk);

	/* Unconnected sockets (sendto) carry the destination in msg_name,
	 * which the kernel has already copied to kernel memory. */
	void *name = BPF_CORE_READ(msg, msg_name);
	if (name) {
		if (family == AF_INET) {
			struct sockaddr_in sin = {};
			bpf_probe_read_kernel(&sin, sizeof(sin), name);
			if (sin.sin_family == AF_INET) {
				e->family = AF_INET;
				e->dport = bpf_ntohs(sin.sin_port);
				__builtin_memset(e->daddr, 0, sizeof(e->daddr));
				__builtin_memcpy(e->daddr, &sin.sin_addr.s_addr, 4);
			}
		} else {
			struct sockaddr_in6 sin6 = {};
			bpf_probe_read_kernel(&sin6, sizeof(sin6), name);
			if (sin6.sin6_family == AF_INET6) {
				e->family = AF_INET6;
				e->dport = bpf_ntohs(sin6.sin6_port);
				__builtin_memcpy(e->daddr, sin6.sin6_addr.in6_u.u6_addr8, 16);
			}
		}
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kp_udp_sendmsg, struct sock *sk, struct msghdr *msg)
{
	return udp_send(sk, msg, AF_INET);
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(kp_udpv6_sendmsg, struct sock *sk, struct msghdr *msg)
{
	return udp_send(sk, msg, AF_INET6);
}

/* ------------------------------------------------------------------------
 * Deny mode: attached to a dedicated cgroup v2 holding only the target.
 * Every inet connect / UDP send is rejected (syscall fails with EPERM) and
 * reported, unless the peer is in the allow map (filled by ask mode). Any
 * other packet (raw sockets, ICMP, inbound) not to/from an allowed peer is
 * dropped and counted.
 * ------------------------------------------------------------------------ */

#define EV_DENY_CONNECT 4
#define EV_DENY_SEND    5

#define SOCK_STREAM 1

/* Which current-task helpers this program type may call on this kernel.
 * Set from userspace after probing; dead branches are pruned by the
 * verifier, so unsupported helpers are never checked. */
const volatile u8 have_pid_helper = 0;
const volatile u8 have_comm_helper = 0;

/* Peers the user allowed (ask mode). port is host order; port 0 = any
 * port on that address. IPv4-mapped IPv6 addresses are stored as AF_INET.
 * Empty in plain deny mode, so everything is refused. */
struct peer_key {
	u16 family;
	u16 port;
	u8  addr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct peer_key);
	__type(value, u8);
} allow SEC(".maps");

static __always_inline bool peer_allowed(struct peer_key *k)
{
	if (bpf_map_lookup_elem(&allow, k))
		return true;
	u16 port = k->port;
	k->port = 0;
	bool ok = bpf_map_lookup_elem(&allow, k) != NULL;
	k->port = port;
	return ok;
}

/* [0] egress packets dropped, [1] ingress packets dropped */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, u64);
} dropped SEC(".maps");

static __always_inline int deny_addr(struct bpf_sock_addr *ctx, u16 kind, u16 family)
{
	struct peer_key k = {};
	k.family = family;
	k.port = bpf_ntohs((u16)ctx->user_port);
	if (family == AF_INET) {
		u32 ip = ctx->user_ip4;
		__builtin_memcpy(k.addr, &ip, 4);
	} else {
		u32 ip6[4];
		ip6[0] = ctx->user_ip6[0];
		ip6[1] = ctx->user_ip6[1];
		ip6[2] = ctx->user_ip6[2];
		ip6[3] = ctx->user_ip6[3];
		if (ip6[0] == 0 && ip6[1] == 0 && ip6[2] == bpf_htonl(0xffff)) {
			k.family = AF_INET; /* v4-mapped: packets will be IPv4 */
			__builtin_memcpy(k.addr, &ip6[3], 4);
		} else {
			__builtin_memcpy(k.addr, ip6, 16);
		}
	}

	u16 proto = ctx->type == SOCK_STREAM ? PROTO_TCP : PROTO_UDP;
	bool ok = peer_allowed(&k);
	/* Allowed TCP connects are already reported by kprobe/tcp_connect; the
	 * UDP kprobes are off in deny mode, so report allowed UDP here. */
	if (ok && proto == PROTO_TCP)
		return 1;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
		e->ts_ns = bpf_ktime_get_ns();
		if (have_pid_helper) {
			u64 id = bpf_get_current_pid_tgid();
			e->pid = (u32)id;
			e->tgid = id >> 32;
		}
		if (have_comm_helper)
			bpf_get_current_comm(&e->comm, sizeof(e->comm));
		e->uid = (u32)bpf_get_current_uid_gid();
		if (ok)
			e->kind = kind == EV_DENY_SEND ? EV_UDP_SEND : EV_CONNECT;
		else
			e->kind = kind;
		e->family = k.family;
		e->proto = proto;
		e->dport = k.port;
		__builtin_memcpy(e->daddr, k.addr, 16);
		bpf_ringbuf_submit(e, 0);
	}
	return ok ? 1 : 0;
}

SEC("cgroup/connect4")
int deny_connect4(struct bpf_sock_addr *ctx) { return deny_addr(ctx, EV_DENY_CONNECT, AF_INET); }

SEC("cgroup/connect6")
int deny_connect6(struct bpf_sock_addr *ctx) { return deny_addr(ctx, EV_DENY_CONNECT, AF_INET6); }

SEC("cgroup/sendmsg4")
int deny_sendmsg4(struct bpf_sock_addr *ctx) { return deny_addr(ctx, EV_DENY_SEND, AF_INET); }

SEC("cgroup/sendmsg6")
int deny_sendmsg6(struct bpf_sock_addr *ctx) { return deny_addr(ctx, EV_DENY_SEND, AF_INET6); }

/* Lets packets to/from an allowed peer through. skb data starts at the
 * network header for cgroup_skb programs. */
static __always_inline bool skb_allowed(struct __sk_buff *skb, bool egress)
{
	struct peer_key k = {};
	u8 hdr[40];
	u8 proto;
	u32 l4off;

	if (bpf_skb_load_bytes(skb, 0, hdr, 1))
		return false;
	if ((hdr[0] >> 4) == 4) {
		if (bpf_skb_load_bytes(skb, 0, hdr, 20))
			return false;
		k.family = AF_INET;
		__builtin_memcpy(k.addr, egress ? &hdr[16] : &hdr[12], 4);
		proto = hdr[9];
		l4off = (hdr[0] & 0xf) * 4;
	} else if ((hdr[0] >> 4) == 6) {
		if (bpf_skb_load_bytes(skb, 0, hdr, 40))
			return false;
		k.family = AF_INET6;
		__builtin_memcpy(k.addr, egress ? &hdr[24] : &hdr[8], 16);
		proto = hdr[6]; /* extension headers: falls back to any-port rules */
		l4off = 40;
	} else {
		return false;
	}

	if (proto == PROTO_TCP || proto == PROTO_UDP) {
		u16 ports[2];
		if (bpf_skb_load_bytes(skb, l4off, ports, sizeof(ports)) == 0) {
			k.port = bpf_ntohs(egress ? ports[1] : ports[0]);
			if (bpf_map_lookup_elem(&allow, &k))
				return true;
		}
	}
	k.port = 0;
	return bpf_map_lookup_elem(&allow, &k) != NULL;
}

static __always_inline int filter_skb(struct __sk_buff *skb, u32 idx)
{
	if (skb_allowed(skb, idx == 0))
		return 1;
	u64 *cnt = bpf_map_lookup_elem(&dropped, &idx);
	if (cnt)
		(*cnt)++;
	return 0; /* drop */
}

SEC("cgroup_skb/egress")
int deny_egress(struct __sk_buff *skb) { return filter_skb(skb, 0); }

SEC("cgroup_skb/ingress")
int deny_ingress(struct __sk_buff *skb) { return filter_skb(skb, 1); }
