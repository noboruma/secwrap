//go:build ignore

// SPDX-License-Identifier: GPL-2.0
// Network activity monitor: TCP connect/accept and UDP sends, filtered to a
// tracked process tree (or everything when trace_all is set).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

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

/* Set of tgids we follow. Children are added on fork. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, u32);
	__type(value, u8);
} tracked SEC(".maps");

const volatile u8 trace_all = 0;
const volatile u32 self_tgid = 0;

static __always_inline bool should_trace(u32 tgid)
{
	if (tgid == self_tgid)
		return false;
	if (trace_all)
		return true;
	return bpf_map_lookup_elem(&tracked, &tgid) != NULL;
}

/* Processes only: a new thread shares its parent's tgid, which is already
 * tracked. (Adding thread ids would leak entries: exit only removes
 * process leaders, and waitTreeExit waits for the map to empty.) */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(handle_fork, struct task_struct *parent_task, struct task_struct *child_task)
{
	u32 parent = parent_task->tgid;
	u32 child = child_task->tgid;
	if (child == parent || !bpf_map_lookup_elem(&tracked, &parent))
		return 0;
	u8 one = 1;
	bpf_map_update_elem(&tracked, &child, &one, BPF_ANY);
	return 0;
}

/* BTF tracepoints (fork above, exit here) need no tracefs, which is
 * usually not mounted in containers. */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_exit, struct task_struct *task)
{
	u32 tgid = task->tgid;
	if ((u32)task->pid != tgid)
		return 0; /* a thread, not the process leader */
	bpf_map_delete_elem(&tracked, &tgid);
	return 0;
}

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

/* ------------------------------------------------------------------------
 * File access (BPF LSM, needs "bpf" in /sys/kernel/security/lsm).
 * Every open by a traced task is reported with its full path. An open is
 * "in scope" when it writes/creates, or reads a sensitive path. With
 * file_enforce set (ask mode), in-scope opens need an allow rule in
 * file_rules, added by userspace once the user said yes; others get EPERM.
 * ------------------------------------------------------------------------ */

#define FMODE_WRITE   0x2
#define FMODE_EXEC    0x20
#define F_FMODE_EXEC  0x20 /* __FMODE_EXEC in f_flags: how open_exec marks the file */
#define FMODE_CREATED 0x100000
#define F_O_TMPFILE   020000000 /* __O_TMPFILE */

#define FPATH_MAX 512
#define NSENS     16
#define SENS_MAX  128

#define FILE_WRITE     1
#define FILE_CREATED   2
#define FILE_EXEC      4
#define FILE_SENSITIVE 8
#define FILE_BLOCKED   16
#define FILE_INSCOPE   32
#define FILE_LONGPATH  64
#define FILE_PROGRAM   128 /* an exec (bprm), not an open */

#define RULE_READ  1
#define RULE_WRITE 2
#define RULE_EXEC  4

struct file_event {
	u64 ts_ns;
	u32 pid;
	u32 tgid;
	u32 uid;
	u32 flags;
	char comm[16];
	char path[FPATH_MAX];
};

const struct file_event *unused_file_event __attribute__((unused));

struct path_buf {
	char p[FPATH_MAX];
};

/* bpf_d_path builds the string at the end of its buffer and then moves it
 * to the front, so bytes after the NUL are garbage. raw receives d_path's
 * output; key gets a clean, zero padded copy usable as a map key. */
struct path_scratch {
	struct path_buf key;
	char raw[FPATH_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 23);
} file_events SEC(".maps");

/* path (zero padded) -> RULE_* bits */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct path_buf);
	__type(value, u8);
} file_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct path_scratch);
} path_scratch SEC(".maps");

const volatile u8 file_enforce = 0;
const volatile u8 file_log_all = 1; /* 0: only report execs */
const volatile u8 exec_enforce = 0; /* --exec with --deny/--ask */
/* Sensitive paths. sens_dir[i]: also everything below sens_path[i]. */
const volatile u32 sens_count = 0;
const volatile u32 sens_len[NSENS] = {};
const volatile u8 sens_dir[NSENS] = {};
const volatile char sens_path[NSENS][SENS_MAX] = {};

/* p equals lit, or starts with lit + "/" */
#define UNDER(p, lit) under_lit(p, lit, sizeof(lit) - 1)
static __always_inline bool under_lit(const char *p, const char *lit, int n)
{
#pragma unroll
	for (int i = 0; i < n; i++)
		if (p[i] != lit[i])
			return false;
	return p[n] == 0 || p[n] == '/';
}

/* Never in scope: pseudo filesystems and non-path names (pipe:[..], ...). */
static __always_inline bool path_excluded(const char *p)
{
	return p[0] != '/' || UNDER(p, "/proc") || UNDER(p, "/sys") || UNDER(p, "/dev");
}

static __always_inline bool path_sensitive(const char *p)
{
	for (u32 i = 0; i < NSENS; i++) {
		if (i >= sens_count)
			break;
		u32 n = sens_len[i];
		if (n == 0 || n >= SENS_MAX)
			continue;
		bool eq = true;
		for (u32 j = 0; j < SENS_MAX; j++) {
			if (j >= n)
				break;
			if (p[j] != sens_path[i][j]) {
				eq = false;
				break;
			}
		}
		if (!eq)
			continue;
		char next = p[n & (SENS_MAX - 1)];
		if (next == 0 || (sens_dir[i] && next == '/'))
			return true;
	}
	return false;
}

/* Folder rules: allow every read and/or write below a directory. The path
 * is hashed once; at each '/' (and at the end) the hash of the prefix seen
 * so far is looked up. Two hashes seeded with random values set at load
 * time (the target cannot read them), one in the key and one checked in the
 * value, so a crafted path cannot pass for an allowed folder. */
const volatile u64 dir_seed1 = 0;
const volatile u64 dir_seed2 = 0;

struct dir_key {
	u64 h1;
	u32 len;
	u32 _pad;
};

struct dir_rule {
	u64 h2;
	u32 bits; /* RULE_READ | RULE_WRITE */
	u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct dir_key);
	__type(value, struct dir_rule);
} dir_rules SEC(".maps");

#define DIR_P1 0x100000001b3ULL       /* FNV-1a 64 prime */
#define DIR_P2 0x9e3779b97f4a7c15ULL  /* golden ratio */

static __always_inline bool dir_allowed(const char *p, u8 need)
{
	u64 h1 = dir_seed1, h2 = dir_seed2;
	for (u32 i = 0; i < FPATH_MAX; i++) {
		char c = p[i];
		if (i > 0 && (c == '/' || c == 0)) {
			struct dir_key k = { .h1 = h1, .len = i };
			struct dir_rule *r = bpf_map_lookup_elem(&dir_rules, &k);
			if (r && r->h2 == h2 && (r->bits & need))
				return true;
		}
		if (c == 0)
			break;
		h1 = (h1 ^ (u8)c) * DIR_P1;
		h2 = (h2 ^ (u8)c) * DIR_P2;
		h2 ^= h2 >> 31;
	}
	return false;
}

SEC("lsm/file_open")
int BPF_PROG(vc_file_open, struct file *file)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	if (!should_trace(tgid))
		return 0;

	u32 fmode = file->f_mode;
	u32 fflags = file->f_flags;
	/* An exec open: newer kernels mark it in f_flags (__FMODE_EXEC), which
	 * is what LSMs and fsnotify check; FMODE_EXEC in f_mode is not set. */
	bool is_exec = (fmode & FMODE_EXEC) || (fflags & F_FMODE_EXEC);
	/* Exec-only mode (SBOMs without --files): report executed files only. */
	if (!file_log_all && !is_exec)
		return 0;

	u32 zero = 0;
	struct path_scratch *sc = bpf_map_lookup_elem(&path_scratch, &zero);
	if (!sc)
		return 0;
	struct path_buf *b = &sc->key;
	__builtin_memset(b, 0, sizeof(*b));

	u32 flags = 0;
	if (fmode & FMODE_WRITE)
		flags |= FILE_WRITE;
	if (fmode & FMODE_CREATED)
		flags |= FILE_CREATED | FILE_WRITE;
	if (is_exec)
		flags |= FILE_EXEC;

	bool skip = (flags & FILE_EXEC) || (fflags & F_O_TMPFILE);
	bool inscope = false;
	long n = bpf_d_path(&file->f_path, sc->raw, sizeof(sc->raw));
	if (n > 0)
		n = bpf_probe_read_kernel_str(b->p, sizeof(b->p), sc->raw);
	if (n < 0) {
		/* Too long to check: in scope, so ask mode refuses it. */
		flags |= FILE_LONGPATH;
		inscope = !skip;
	} else if (!skip && !path_excluded(b->p)) {
		if (path_sensitive(b->p))
			flags |= FILE_SENSITIVE;
		inscope = flags & (FILE_WRITE | FILE_SENSITIVE);
	}
	if (inscope)
		flags |= FILE_INSCOPE;

	int ret = 0;
	if (inscope && file_enforce) {
		u8 need = (flags & FILE_WRITE) ? RULE_WRITE : RULE_READ;
		u8 *v = n < 0 ? NULL : bpf_map_lookup_elem(&file_rules, b);
		bool ok = v && (*v & need);
		if (!ok && n > 0)
			ok = dir_allowed(b->p, need);
		if (!ok) {
			flags |= FILE_BLOCKED;
			ret = -1; /* -EPERM */
		}
	}

	struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
	if (e) {
		e->ts_ns = bpf_ktime_get_ns();
		e->pid = (u32)id;
		e->tgid = tgid;
		e->uid = (u32)bpf_get_current_uid_gid();
		e->flags = flags;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		__builtin_memcpy(e->path, b->p, FPATH_MAX);
		bpf_ringbuf_submit(e, 0);
	}
	return ret;
}

/* --exec: every program executed, once per execve (bprm->file is the file
 * asked for; a script's interpreter is not checked again). With
 * exec_enforce, it needs an exec rule (file or folder) or it fails with
 * EPERM. */
SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(vc_bprm_exec, struct linux_binprm *bprm)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	if (!should_trace(tgid))
		return 0;

	u32 zero = 0;
	struct path_scratch *sc = bpf_map_lookup_elem(&path_scratch, &zero);
	if (!sc)
		return 0;
	struct path_buf *b = &sc->key;
	__builtin_memset(b, 0, sizeof(*b));

	u32 flags = FILE_EXEC | FILE_PROGRAM;
	long n = bpf_d_path(&bprm->file->f_path, sc->raw, sizeof(sc->raw));
	if (n > 0)
		n = bpf_probe_read_kernel_str(b->p, sizeof(b->p), sc->raw);
	if (n < 0)
		flags |= FILE_LONGPATH;

	int ret = 0;
	if (exec_enforce) {
		flags |= FILE_INSCOPE;
		u8 *v = n < 0 ? NULL : bpf_map_lookup_elem(&file_rules, b);
		bool ok = v && (*v & RULE_EXEC);
		if (!ok && n > 0)
			ok = dir_allowed(b->p, RULE_EXEC);
		if (!ok) {
			flags |= FILE_BLOCKED;
			ret = -1; /* -EPERM */
		}
	}

	struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
	if (e) {
		e->ts_ns = bpf_ktime_get_ns();
		e->pid = (u32)id;
		e->tgid = tgid;
		e->uid = (u32)bpf_get_current_uid_gid();
		e->flags = flags;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		__builtin_memcpy(e->path, b->p, FPATH_MAX);
		bpf_ringbuf_submit(e, 0);
	}
	return ret;
}

char LICENSE[] SEC("license") = "GPL";
