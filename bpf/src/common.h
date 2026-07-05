/* SPDX-License-Identifier: Apache-2.0 */
/*
 * common.h — shared maps, constants, and helpers for RanA's CO-RE programs.
 *
 * P2 (observation is inert): nothing in this file or anything that
 * includes it may call the user-memory write helper, the signal-delivery
 * helper, or the return-value override helper.
 * internal/bpf/invariants_test.go greps every .c/.h source under bpf/src
 * for these symbols and fails the build if any appear.
 */

#ifndef RANA_COMMON_H
#define RANA_COMMON_H

#include "vmlinux_min.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h> /* bpf_htons/bpf_ntohs for the cgroup_skb DNS hook */
#include "records.h"

/* RANA_COMP_MAX: per-path-component copy window (NAME_MAX + NUL). The
 * resolve-path emit loop guards and copies in units of this CONSTANT so
 * every verifier-visible bound is constant-vs-constant (see the design
 * note in rana_resolve_path). */
#define RANA_COMP_MAX 256

#ifndef true
#define true 1
#define false 0
#endif

/* Maximum resolved-path components walked per file op (D7: "bounded
 * dentry+mount path walk ≤48 components"). Kept as a #define so both the
 * unrolled walk loop and any userspace doc-cross-check can reference the
 * same number. */
#define RANA_MAX_PATH_COMPONENTS 48

/* rana_sessions: cgid -> session slot. Populated by userspace (ranad) when
 * a session's cgroup leaf is created (D6); every event-producing program
 * filters on membership in this map before doing any further work, so
 * non-session noise never reaches the ring buffer (P2/P6). Value is a
 * placeholder u8 (map is used as a set); a real session-id string never
 * lives in kernel memory — cgid<->session-id mapping happens in
 * internal/collector's Enricher, userspace, per CONTRACTS.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);   /* cgid */
	__type(value, __u8);
} rana_sessions SEC(".maps");

/* rana_session_pids: in-kernel session pid-map (D7 amendment): fork/exit
 * maintain this so a session member remains attributable even after it
 * leaves its cgroup (delegated spawns, escapes) — governor shedding in
 * userspace never degrades this map because it's maintained entirely
 * in-kernel, unconditionally, for every fork/exit of a session member. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);   /* pid */
	__type(value, __u64); /* cgid at time of fork (the "home" session) */
} rana_session_pids SEC(".maps");

/* rana_events: single ring buffer shared by every program in this
 * project. Sized generously (16MiB) — userspace governs downstream
 * (internal/collector.Governor), not the kernel (P2: no kernel-side
 * blocking or dropping-with-signal; a full ringbuf simply fails the
 * reserve and the record is silently not emitted from this exec, which
 * ranad accounts for as a "ringbuf_full" gap on the userspace side via
 * BPF_MAP_TYPE_RINGBUF's own drop counter, read via bpf_ringbuf_query if
 * available, else inferred from a monotonic sequence gap). */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 * 1024);
} rana_events SEC(".maps");

/* rana_sensitive_prefixes: pinned watchlist of path prefixes (D9),
 * populated by userspace from the active profile's sensitive-read rules
 * plus RanA's own datadir (D27b). Key is a fixed-size prefix string
 * (matched against the resolved path in security_file_open); value is a
 * small rule-id used to populate fs.sensitive_read{rule}. */
#define RANA_SENSITIVE_PREFIX_MAX 256

struct rana_sensitive_prefix_key {
	__u8 len;
	__u8 prefix[RANA_SENSITIVE_PREFIX_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, struct rana_sensitive_prefix_key);
	__type(value, __u32); /* rule id */
} rana_sensitive_prefixes SEC(".maps");

/* rana_sensitive_inodes: pinned (dev,inode) identity for files that exist
 * and match the watchlist at session start (D7/D9: defeats symlink and
 * most hardlink dodges for pre-existing sensitive files). */
struct rana_dev_inode_key {
	__u32 dev;
	__u64 ino;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct rana_dev_inode_key);
	__type(value, __u32); /* rule id */
} rana_sensitive_inodes SEC(".maps");

/* rana_scratch: per-CPU scratch for intermediates too large for the
 * 512-byte BPF stack (the resolve-path component stack is 48*8=384B;
 * the fs pre-match path staging is RANA_CAP_FSOP_PATH=2048B — both blew
 * the stack limit when declared as locals). Safe to share across the
 * programs that use it: they are all process-context tp_btf/fentry hooks
 * running on the current task (at most one at a time per CPU, and none
 * is reachable from inside another); the one softirq-context program
 * (cgroup_skb DNS) never touches this scratch. Sequential uses within a
 * single invocation (exe_path then cwd; staging then copy-out) each
 * consume the scratch before the next begins.
 *
 * comps stores only the component NAME pointers (dentry names are
 * NUL-terminated; the emit loop reads them with a constant-size
 * bpf_probe_read_kernel_str, so qstr.len is never needed) — storing full
 * qstrs and using their len made the emit loop depend on a
 * variable-to-variable bound (clen <= space) the verifier does not
 * track, failing loads on every kernel. */
struct rana_scratch {
	const unsigned char *comps[RANA_MAX_PATH_COMPONENTS]; /* rana_resolve_path walk */
	__u8 path_buf[RANA_CAP_FSOP_PATH];                    /* rana_fs pre-match staging */
};

/* The value is declared by SIZE, not type: struct rana_scratch embeds
 * struct qstr, whose `name` member is a kernel pointer — bpf2go cannot
 * generate a Go type for it and fails generation if the map's value
 * carries that BTF. Userspace never reads this map (pure kernel-side
 * scratch), so an opaque value loses nothing; the programs cast the
 * lookup result back to struct rana_scratch* (rana_scratch() below). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__uint(value_size, sizeof(struct rana_scratch));
} rana_scratch_map SEC(".maps");

static __always_inline struct rana_scratch *rana_scratch(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&rana_scratch_map, &zero);
}

/* Returns the cgroup id (cgid) of the default/unified (v2) hierarchy for
 * the given task, via CO-RE-relocated field reads — the
 * css_set->dfl_cgrp->kn->id chain bpf_get_current_cgroup_id() walks
 * (dfl_cgrp, not subsys[0]: see vmlinux_min.h's cgroup note). This is
 * the single source of truth for "which cgroup is this task in" used by
 * every program's session filter. */
static __always_inline __u64 rana_task_cgid(struct task_struct *task)
{
	struct css_set *cgroups = BPF_CORE_READ(task, cgroups);
	if (!cgroups)
		return 0;
	struct cgroup *cgrp = BPF_CORE_READ(cgroups, dfl_cgrp);
	if (!cgrp)
		return 0;
	return BPF_CORE_READ(cgrp, kn, id);
}

/* Returns 1 iff cgid belongs to a session RanA is recording. Session
 * membership is the in-kernel noise filter (P6: "in-kernel filtering
 * keeps non-session noise out of the ringbuf entirely"). */
static __always_inline int rana_cgid_in_session(__u64 cgid)
{
	return bpf_map_lookup_elem(&rana_sessions, &cgid) != NULL;
}

/* Returns 1 iff pid is a known member of some session via the in-kernel
 * pid-map (D7 amendment) — used by escape/migration detection so a
 * session member is still attributable after leaving its cgroup. Writes
 * the pid's home cgid to *home_cgid when found. */
static __always_inline int rana_pid_in_session(__u32 pid, __u64 *home_cgid)
{
	__u64 *v = bpf_map_lookup_elem(&rana_session_pids, &pid);
	if (!v)
		return 0;
	if (home_cgid)
		*home_cgid = *v;
	return 1;
}

/*
 * rana_resolve_path: bounded dentry+mount walk (D7), ≤RANA_MAX_PATH_COMPONENTS
 * components, writing the resolved absolute path into `out` (capacity
 * `out_cap`) and returning the number of bytes written (0 on failure).
 * This is the walk that makes fs.* events path_source=resolved instead of
 * the TOCTOU-racy syscall-argument path_source=claimed fallback.
 *
 * Implementation walks dentry->d_parent from the leaf to the mount root,
 * pushing each component's name into a fixed-size scratch stack (bounded
 * unrolled loop — the verifier requires a static bound), then copies the
 * components back out in root-to-leaf order with '/' separators. Never
 * writes anywhere but the caller-supplied ringbuf record; a read-only
 * walk of kernel dentry structures (P2: no probe_write, no blocking).
 *
 * On kernels/paths deeper than RANA_MAX_PATH_COMPONENTS, the walk stops
 * at the bound and the caller still emits a resolved (not claimed) path
 * — a bounded truncation of a resolved walk, never a fabricated one; the
 * emitted path is the nearest RANA_MAX_PATH_COMPONENTS-component suffix
 * to the leaf, which is what downstream sensitive-prefix matching needs
 * most (matching happens on the tail nearest the file, not the root).
 */
static __always_inline int rana_resolve_path(struct dentry *dentry, __u8 *out, int out_cap)
{
	if (!dentry || !out || out_cap <= RANA_COMP_MAX + 2)
		return 0; /* every real caller passes >= 1024; see RANA_COMP_MAX */

	/* Scratch pointers to each component's name, nearest-leaf first —
	 * held in the per-CPU scratch map, not the stack (384B against the
	 * 512B BPF stack limit, alongside the caller's own locals). */
	struct rana_scratch *scratch = rana_scratch();
	if (!scratch)
		return 0;
	int n = 0;

	struct dentry *d = dentry;
	#pragma unroll
	for (int i = 0; i < RANA_MAX_PATH_COMPONENTS; i++) {
		if (!d)
			break;
		struct dentry *parent = BPF_CORE_READ(d, d_parent);
		if (parent == d) {
			/* reached a mount/filesystem root */
			break;
		}
		scratch->comps[n] = BPF_CORE_READ(d, d_name.name);
		n++;
		d = parent;
	}

	/* Emit root-to-leaf: iterate comps[] in reverse, writing "/" + name
	 * for each, bounded by out_cap.
	 *
	 * Verifier design (learned from real 5.15/6.x load rejections):
	 * every bound here is a comparison against a COMPILE-TIME CONSTANT
	 * (out_cap is constant at each inlined call site; RANA_COMP_MAX is a
	 * macro), and the per-component copy uses a CONSTANT maximum size
	 * with bpf_probe_read_kernel_str. The previous shape — clamping a
	 * length loaded from map memory against remaining space — depended
	 * on a variable-to-variable relation (clen <= space) the verifier
	 * does not track, and on clamped registers surviving helper calls
	 * without being reloaded from (possibly-aliased) map memory; it was
	 * rejected on every kernel. Constants on both sides of every
	 * comparison leave nothing to lose track of. */
	int off = 0;
	#pragma unroll
	for (int i = RANA_MAX_PATH_COMPONENTS - 1; i >= 0; i--) {
		if (i >= n)
			continue;
		/* '/' plus a full component must provably fit. */
		if (off < 0 || off > out_cap - RANA_COMP_MAX - 2)
			break;
		out[off] = '/';
		off++;

		const unsigned char *name = scratch->comps[i];
		if (!name)
			continue;
		/* Constant-size bounded copy; dentry names are NUL-terminated.
		 * Returns bytes written INCLUDING the NUL (>=1), which the next
		 * component's '/' (or the final terminator) overwrites. */
		long l = bpf_probe_read_kernel_str(out + off, RANA_COMP_MAX, name);
		if (l > 1)
			off += l - 1;
	}

	if (off < 0)
		off = 0;
	if (off == 0) {
		out[0] = '/';
		off = 1;
	}
	if (off < out_cap)
		out[off] = 0;
	return off;
}

#endif /* RANA_COMMON_H */
