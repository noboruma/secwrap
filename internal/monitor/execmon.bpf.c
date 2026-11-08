//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Program execution (BPF LSM, needs "bpf" in /sys/kernel/security/lsm).

#include "common.bpf.h"

const volatile u8 exec_enforce = 0; /* --exec in deny/ask mode */

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
