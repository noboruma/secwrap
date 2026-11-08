// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Shared by netmon, filemon and execmon: the tracked process tree and the
// path rules that file and exec enforcement both use.

#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* ------------------------------------------------------------------------
 * Process tree
 * ------------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------------
 * Architecture: the object is built once per byte order, not per CPU.
 * Userspace reads the running kernel's BTF and sets where the first
 * function arguments and the return value sit in struct pt_regs, and the
 * kernel's word size (4 on 32-bit kernels, whose pointers and longs are 32
 * bits while BPF's are 64).
 * ------------------------------------------------------------------------ */

const volatile u32 kword = 8;
const volatile u32 regs_arg[3] = {};
const volatile u32 regs_rc = 0;

/* A kernel long or pointer at p. */
static __always_inline u64 read_kword(const void *p)
{
	if (kword == 4) {
		u32 v = 0;
		bpf_probe_read_kernel(&v, sizeof(v), p);
		return v;
	}
	u64 v = 0;
	bpf_probe_read_kernel(&v, sizeof(v), p);
	return v;
}

/* Argument i (0-2) of the probed kernel function, and its return value. */
static __always_inline u64 kprobe_arg(struct pt_regs *ctx, int i)
{
	return read_kword((const char *)ctx + (regs_arg[i] & 511));
}

static __always_inline u64 kprobe_ret(struct pt_regs *ctx)
{
	return read_kword((const char *)ctx + (regs_rc & 511));
}

/* ------------------------------------------------------------------------
 * Paths and rules (filemon, execmon)
 * ------------------------------------------------------------------------ */

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
