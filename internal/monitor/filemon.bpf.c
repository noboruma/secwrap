//go:build ignore

// SPDX-License-Identifier: GPL-2.0
// File access (BPF LSM, needs "bpf" in /sys/kernel/security/lsm).
// Every open by a traced task is reported with its full path. An open is
// "in scope" when it writes/creates, or reads a sensitive path. With
// file_enforce set (ask/deny mode), in-scope opens need an allow rule in
// file_rules (added by userspace once the user said yes) or a folder rule;
// others get EPERM.

#include "common.bpf.h"

#define FMODE_WRITE   0x2
#define FMODE_EXEC    0x20
#define F_FMODE_EXEC  0x20 /* __FMODE_EXEC in f_flags: how open_exec marks the file */
#define FMODE_CREATED 0x100000
#define F_O_TMPFILE   020000000 /* __O_TMPFILE */

const volatile u8 file_enforce = 0;
const volatile u8 file_log_all = 1; /* 0: only report execs */
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
