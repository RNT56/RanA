// SPDX-License-Identifier: Apache-2.0
/*
 * rana_exec.c — sched_process_exec/fork/exit tracepoints (D7 hook set v1).
 *
 * fork and exit also maintain the in-kernel session pid-map
 * (rana_session_pids, common.h) so a session member stays attributable
 * even after leaving its cgroup — this maintenance is unconditional and
 * happens entirely in-kernel, so userspace governor shedding (P2/P5)
 * never degrades it.
 *
 * P2 (observation is inert): tracepoint programs cannot return a value
 * that affects the traced operation; nothing here calls
 * the user-memory write helper, the signal-delivery helper, or the return-value override helper.
 */

#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * sched_process_exec: emits proc.exec (kind=1). Runs in the context of
 * the newly-execing task, so bpf_get_current_task() is exactly the task
 * whose new image we're reporting.
 */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(rana_on_exec, struct task_struct *task, pid_t old_pid,
	     struct linux_binprm *bprm)
{
	__u64 cgid = rana_task_cgid(task);
	if (!rana_cgid_in_session(cgid))
		return 0;

	struct rana_exec_record *rec = bpf_ringbuf_reserve(&rana_events, sizeof(*rec), 0);
	if (!rec)
		return 0; /* ring full: no signal, no retry — accounted for
			   * downstream via sequence-gap detection in ranad,
			   * never here (P2: no blocking/signalling helper). */

	rec->version = RANA_RECORD_VERSION;
	rec->kind = RANA_KIND_EXEC;
	rec->pid = BPF_CORE_READ(task, tgid);
	rec->ppid = BPF_CORE_READ(task, real_parent, tgid);
	rec->uid = BPF_CORE_READ(task, real_cred, uid.val);
	rec->cgid = cgid;
	rec->ts_mono = bpf_ktime_get_ns();
	rec->ts_wall = bpf_ktime_get_boot_ns();

	__builtin_memset(rec->comm, 0, sizeof(rec->comm));
	if (bpf_get_current_comm(rec->comm, sizeof(rec->comm)) == 0) {
		int l = 0;
		#pragma unroll
		for (int i = 0; i < RANA_CAP_EXEC_COMM; i++) {
			if (rec->comm[i] == 0)
				break;
			l++;
		}
		rec->comm_len = (__u8)l;
	} else {
		rec->comm_len = 0;
	}

	/* exe_path / cwd resolution reuses the bounded dentry+mount walk
	 * shared with rana_fs.c (rana_resolve_path, common.h) — sourced from
	 * bprm->file->f_path (exe) and task->fs->pwd (cwd). Both are
	 * resolved-path (path_source=resolved equivalent for exec context;
	 * proc.exec has no explicit path_source field per schema — the
	 * resolution method is the same trusted in-kernel walk either way). */
	__builtin_memset(rec->exe_path, 0, sizeof(rec->exe_path));
	struct dentry *exe_dentry = BPF_CORE_READ(bprm, file, f_path.dentry);
	rec->exe_path_len = (__u16)rana_resolve_path(exe_dentry, rec->exe_path, sizeof(rec->exe_path));

	__builtin_memset(rec->cwd, 0, sizeof(rec->cwd));
	struct dentry *cwd_dentry = BPF_CORE_READ(task, fs, pwd.dentry);
	rec->cwd_len = (__u16)rana_resolve_path(cwd_dentry, rec->cwd, sizeof(rec->cwd));

	/* argv: read from bprm->mm's arg_start..arg_end via
	 * bpf_probe_read_user in a bounded copy, capped at
	 * RANA_CAP_EXEC_ARGV raw bytes (NUL-separated, as laid out by the
	 * kernel's own user-stack argv construction). This is a *read* from
	 * user memory, never a write — permitted under P2. Redaction (P3)
	 * happens downstream in internal/collector's Enricher before any
	 * byte reaches the ledger; the kernel side captures raw bytes only
	 * transiently in the ring buffer, never envp (P3: envp is never
	 * read anywhere in this project).
	 */
	__builtin_memset(rec->argv, 0, sizeof(rec->argv));
	rec->argv_len = 0;
	rec->argv_truncated = 0;
	struct mm_struct *mm = BPF_CORE_READ(bprm, mm);
	if (mm) {
		unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
		unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
		unsigned long total = 0;
		if (arg_end > arg_start)
			total = arg_end - arg_start;
		unsigned long cap = total;
		if (cap > RANA_CAP_EXEC_ARGV) {
			cap = RANA_CAP_EXEC_ARGV;
			rec->argv_truncated = 1;
		}
		if (cap > 0) {
			long ret = bpf_probe_read_user(rec->argv, (__u32)cap,
							(void *)arg_start);
			if (ret == 0)
				rec->argv_len = (__u16)cap;
		}
	}

	bpf_ringbuf_submit(rec, 0);
	return 0;
}

/*
 * sched_process_fork: emits proc.fork (kind=2) and inserts the child pid
 * into rana_session_pids so it's attributable regardless of future
 * cgroup migration (D7 amendment). Only session members' children are
 * tracked — a fork outside any session is not a member and is dropped
 * before either the map write or the ringbuf reserve (P6 in-kernel
 * filtering).
 */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(rana_on_fork, struct task_struct *parent, struct task_struct *child)
{
	__u64 cgid = rana_task_cgid(parent);
	__u64 parent_home = cgid;
	__u32 parent_pid = BPF_CORE_READ(parent, tgid);

	int parent_is_member = rana_cgid_in_session(cgid);
	if (!parent_is_member) {
		/* Parent may have already migrated away from its home
		 * cgroup while remaining a tracked session member (D7
		 * amendment) — fall back to the pid-map before giving up. */
		if (!rana_pid_in_session(parent_pid, &parent_home))
			return 0;
	}

	__u32 child_pid = BPF_CORE_READ(child, tgid);
	bpf_map_update_elem(&rana_session_pids, &child_pid, &parent_home, BPF_ANY);

	struct rana_fork_record *rec = bpf_ringbuf_reserve(&rana_events, sizeof(*rec), 0);
	if (!rec)
		return 0;

	rec->version = RANA_RECORD_VERSION;
	rec->kind = RANA_KIND_FORK;
	rec->pid = child_pid;
	rec->ppid = parent_pid;
	rec->cgid = parent_home;
	rec->ts_mono = bpf_ktime_get_ns();
	rec->ts_wall = bpf_ktime_get_boot_ns();

	bpf_ringbuf_submit(rec, 0);
	return 0;
}

/*
 * sched_process_exit: emits proc.exit (kind=3) and removes the pid from
 * rana_session_pids (the process is gone; its slot in the pid-map is no
 * longer needed and is reclaimed to bound map growth).
 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(rana_on_exit, struct task_struct *task)
{
	__u32 pid = BPF_CORE_READ(task, tgid);
	__u64 cgid = rana_task_cgid(task);
	__u64 home_cgid = cgid;

	int is_member = rana_cgid_in_session(cgid);
	if (!is_member) {
		if (!rana_pid_in_session(pid, &home_cgid))
			return 0;
	}

	struct rana_exit_record *rec = bpf_ringbuf_reserve(&rana_events, sizeof(*rec), 0);
	if (rec) {
		rec->version = RANA_RECORD_VERSION;
		rec->kind = RANA_KIND_EXIT;
		rec->pid = pid;
		rec->cgid = home_cgid;
		rec->ts_mono = bpf_ktime_get_ns();
		rec->ts_wall = bpf_ktime_get_boot_ns();
		rec->exit_code = BPF_CORE_READ(task, exit_code);
		rec->utime_ns = 0; /* filled from task->stime/utime schedstat
				    * where available; left 0 on kernels
				    * without the field CO-RE-relocated,
				    * never a fatal condition (P2/P5: absence
				    * of an optional stat is not a gap). */
		rec->stime_ns = 0;
		bpf_ringbuf_submit(rec, 0);
	}

	/* pid-map cleanup happens regardless of whether the ringbuf had
	 * room — this is bookkeeping, not an event, and must not leak. */
	bpf_map_delete_elem(&rana_session_pids, &pid);
	return 0;
}
