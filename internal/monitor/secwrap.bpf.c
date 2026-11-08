//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// secwrap's eBPF object. The monitors are built as one object because they
// share maps: the tracked process tree (all), and the file and folder rules
// (filemon and execmon).
//
//   netmon.bpf.c   network: TCP connect/accept, UDP sends, cgroup deny mode
//   filemon.bpf.c  file opens (lsm/file_open)
//   execmon.bpf.c  programs executed (lsm/bprm_creds_for_exec)

#include "common.bpf.h"

/* Processes only: a new thread shares its parent's tgid, which is already
 * tracked. (Adding thread ids would leak entries: exit only removes
 * whole processes, and waitTreeExit waits for the map to empty.) */
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
 * usually not mounted in containers.
 *
 * A process is done when its last thread exits, not its leader: the leader
 * can pthread_exit while the other threads run on. do_exit decrements
 * signal->live before this tracepoint fires, so it reads 0 exactly for the
 * last thread of the group. */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_exit, struct task_struct *task)
{
	if (BPF_CORE_READ(task, signal, live.counter) != 0)
		return 0; /* other threads of the process still run */
	u32 tgid = task->tgid;
	bpf_map_delete_elem(&tracked, &tgid);
	return 0;
}

#include "netmon.bpf.c"
#include "filemon.bpf.c"
#include "execmon.bpf.c"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
