// SPDX-License-Identifier: Apache-2.0
/*
 * rana_escape.c — cgroup-migration/escape precursor detection (D7).
 *
 * raw_tracepoint/cgroup_attach_task fires whenever any task (session
 * member or not) is attached to a cgroup. Filtered by the in-kernel
 * session pid-map (rana_session_pids, common.h, maintained by
 * rana_exec.c's fork/exit hooks): a migration is only reported when the
 * migrating pid is a known session member being moved to a cgroup that
 * is NOT its home session cgid — this is exactly the mechanism plan
 * §6.4/D7 describes: "the in-kernel session pid-map... makes a session
 * member visible even after it leaves the cgroup — a cgroup_attach_task
 * migration of an in-session pid to a foreign cgroup... raises
 * alert.cgroup_escape{pid, from, to}". The raw record only carries the
 * bare fact (pid, from_cgid, to_cgid); internal/collector's Enricher
 * resolves cgids to session ids and decides alert vs. precursor
 * classification (schema/enrichment concerns, not kernel concerns).
 *
 * P2: raw_tracepoint programs have no return-value contract with the
 * kernel operation at all (unlike LSM/cgroup_sock_addr hooks) — there is
 * no way for this hook to block or alter the attach; it is pure
 * observation by construction.
 */

#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * raw_tracepoint/cgroup_attach_task context: the kernel passes
 * (struct cgroup *dst_cgrp, const char *path, struct task_struct *task,
 * bool threadgroup) as the raw tracepoint's args array. We only need
 * dst_cgrp (for the destination cgid) and task (for pid + identity).
 */
SEC("raw_tp/cgroup_attach_task")
int rana_cgroup_attach_task(struct bpf_raw_tracepoint_args *ctx)
{
	struct cgroup *dst_cgrp = (struct cgroup *)ctx->args[0];
	struct task_struct *task = (struct task_struct *)ctx->args[2];
	if (!task)
		return 0;

	__u32 pid = BPF_CORE_READ(task, tgid);

	__u64 home_cgid = 0;
	if (!rana_pid_in_session(pid, &home_cgid))
		return 0; /* not a session member: not our concern (P6 — this
			   * hook, like every other, only ever reports on
			   * pids RanA is already recording). */

	__u64 to_cgid = dst_cgrp ? BPF_CORE_READ(dst_cgrp, kn_id) : 0;
	if (to_cgid == home_cgid)
		return 0; /* moving within its own session cgroup (or a
			   * no-op attach): not a migration worth reporting. */

	struct rana_migration_record *rec = bpf_ringbuf_reserve(&rana_events, sizeof(*rec), 0);
	if (!rec)
		return 0;

	rec->version = RANA_RECORD_VERSION;
	rec->kind = RANA_KIND_MIGRATION;
	rec->pid = pid;
	rec->from_cgid = home_cgid;
	rec->to_cgid = to_cgid;
	rec->ts_mono = bpf_ktime_get_ns();
	rec->ts_wall = bpf_ktime_get_boot_ns();

	bpf_ringbuf_submit(rec, 0);
	return 0;
}
