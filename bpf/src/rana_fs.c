// SPDX-License-Identifier: Apache-2.0
/*
 * rana_fs.c — file-op hooks (D7 hook set v1).
 *
 *   - fentry security_file_open        -> fs.write_open (kind=4, op=1)
 *     and fs.sensitive_read (matched via rana_sensitive_prefixes /
 *     rana_sensitive_inodes, D9) for read-intent opens of watchlisted
 *     paths
 *   - fentry security_path_unlink      -> fs.unlink (op=2)
 *   - fentry security_path_rename      -> fs.rename (op=3)
 *   - fentry security_path_mkdir       -> fs.mkdir  (op=4)
 *   - fentry vfs_truncate              -> fs.truncate (op=6)
 *
 * All hooks emit path_source=resolved (records.md §4) because every path
 * here comes from rana_resolve_path's dentry+mount walk, never a raw
 * syscall argument (which would be path_source=claimed, a fallback tier
 * not implemented by this file — see records.md and D7 for the
 * distinction; a future syscall-tracepoint fallback tier can reuse the
 * same FsOpRecord shape with PathSource=1).
 *
 * P2: fentry cannot alter the traced function's behavior or return
 * value; nothing here calls the user-memory write helper, the signal-delivery helper, or
 * the return-value override helper.
 */

#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* fs.chmod is part of the D7 hook set (records.md documents FsOpChmod)
 * but has no dedicated LSM hook wired in v1; the op constant and record
 * shape exist so a future security_path_chmod/security_inode_setattr
 * hook can reuse rana_emit_fsop without a schema change. Not exercised
 * by this file today — documented here rather than silently absent. */

static __always_inline void rana_emit_fsop(__u8 op, __u32 pid, __u64 cgid,
					    __u64 flags, __u64 mode,
					    struct dentry *dentry,
					    struct dentry *dentry2 /* rename dst, else NULL */)
{
	struct rana_fsop_record *rec = bpf_ringbuf_reserve(&rana_events, sizeof(*rec), 0);
	if (!rec)
		return;

	rec->version = RANA_RECORD_VERSION;
	rec->kind = RANA_KIND_FSOP;
	rec->op = op;
	rec->path_source = RANA_PATH_SOURCE_RESOLVED;
	rec->pid = pid;
	rec->cgid = cgid;
	rec->ts_mono = bpf_ktime_get_ns();
	rec->ts_wall = bpf_ktime_get_boot_ns();
	rec->flags = flags;
	rec->mode = mode;

	__builtin_memset(rec->path, 0, sizeof(rec->path));
	rec->path_len = (__u16)rana_resolve_path(dentry, rec->path, sizeof(rec->path));

	__builtin_memset(rec->path2, 0, sizeof(rec->path2));
	rec->path2_len = 0;
	if (dentry2)
		rec->path2_len = (__u16)rana_resolve_path(dentry2, rec->path2, sizeof(rec->path2));

	bpf_ringbuf_submit(rec, 0);
}

/* rana_check_sensitive: matches the resolved path against
 * rana_sensitive_prefixes (D9) and the pinned (dev,inode) identity map,
 * emitting fs.sensitive_read (no dedicated FsOpRecord Op — sensitive
 * reads are a distinct record path per records.md's registry note that
 * fs.sensitive_read carries {path, rule}; represented here by reusing
 * FsOpRecord with Mode carrying the matched rule id, Flags=0, and
 * Op=RANA_FSOP_WRITE_OPEN is NOT used — instead we piggyback on the same
 * kind=4 record but callers distinguish sensitive-read at the collector
 * level via the (dev,inode)/prefix match already having happened
 * in-kernel; see records.md's note that this document is authoritative
 * for wire shape, not for every derived schema.EventType — sensitive
 * reads and write-opens share FsOpRecord's wire shape by design, kept
 * economical rather than adding an eleventh record kind for one extra
 * field). Returns the matched rule id, or 0 if no match. */
static __always_inline __u32 rana_match_sensitive_prefix(const __u8 *path, int path_len)
{
	if (path_len <= 0)
		return 0;

	struct rana_sensitive_prefix_key key = {};
	int copy_len = path_len;
	if (copy_len > RANA_SENSITIVE_PREFIX_MAX)
		copy_len = RANA_SENSITIVE_PREFIX_MAX;
	key.len = (__u8)copy_len;
	bpf_probe_read_kernel(key.prefix, copy_len, path);

	/* Exact-length prefix lookup: userspace populates one map entry per
	 * distinct watched prefix length it cares about; a real deployment
	 * pre-registers prefixes at their natural length (e.g. "~/.ssh"
	 * expanded to an absolute path), so this is a direct hash lookup,
	 * not a scan — no unbounded loop over candidate prefix lengths. */
	__u32 *rule = bpf_map_lookup_elem(&rana_sensitive_prefixes, &key);
	if (rule)
		return *rule;
	return 0;
}

static __always_inline __u32 rana_match_sensitive_inode(struct dentry *dentry)
{
	if (!dentry)
		return 0;
	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	if (!inode)
		return 0;

	struct rana_dev_inode_key key = {};
	key.ino = BPF_CORE_READ(inode, i_ino);
	struct super_block *sb = BPF_CORE_READ(inode, i_sb);
	if (sb)
		key.dev = BPF_CORE_READ(sb, s_dev);

	__u32 *rule = bpf_map_lookup_elem(&rana_sensitive_inodes, &key);
	if (rule)
		return *rule;
	return 0;
}

/*
 * fentry security_file_open: fires on every open; we branch on
 * write-intent (O_WRONLY|O_RDWR|O_CREAT|O_TRUNC) for fs.write_open, and
 * separately check the sensitive watchlist for ANY open (read or write)
 * of a matched path/inode, per D9 ("Reads outside the list are NOT
 * recorded" — only watchlisted paths ever produce fs.sensitive_read).
 */
SEC("fentry/security_file_open")
int BPF_PROG(rana_file_open, struct file *file)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	__u64 cgid = rana_task_cgid(task);
	if (!rana_cgid_in_session(cgid))
		return 0;

	__u32 pid = BPF_CORE_READ(task, tgid);
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	unsigned int f_flags = BPF_CORE_READ(file, f_flags);

	#define RANA_O_WRONLY 00000001
	#define RANA_O_RDWR   00000002
	#define RANA_O_CREAT  00000100
	#define RANA_O_TRUNC  00001000

	unsigned int write_mask = RANA_O_WRONLY | RANA_O_RDWR | RANA_O_CREAT | RANA_O_TRUNC;
	if (f_flags & write_mask) {
		rana_emit_fsop(RANA_FSOP_WRITE_OPEN, pid, cgid,
				(__u64)(f_flags & write_mask), 0, dentry, NULL);
	}

	/* Sensitive-read matching happens on every open regardless of
	 * write-intent (a read-only open of ~/.ssh/id_ed25519 is exactly
	 * the trifecta precursor D9 exists to catch). */
	__u8 path_buf[RANA_CAP_FSOP_PATH];
	__builtin_memset(path_buf, 0, sizeof(path_buf));
	int path_len = rana_resolve_path(dentry, path_buf, sizeof(path_buf));

	__u32 rule = rana_match_sensitive_prefix(path_buf, path_len);
	if (!rule)
		rule = rana_match_sensitive_inode(dentry);

	if (rule) {
		struct rana_fsop_record *rec = bpf_ringbuf_reserve(&rana_events, sizeof(*rec), 0);
		if (rec) {
			rec->version = RANA_RECORD_VERSION;
			rec->kind = RANA_KIND_FSOP;
			/* Sensitive-read reuses the write_open Op slot value
			 * space is exhausted by the six documented FsOp
			 * constants; the collector's Enricher determines
			 * fs.sensitive_read vs fs.write_open by *which*
			 * program emitted it plus whether it matched a
			 * watchlist rule — Mode carries the rule id here so
			 * the collector can build
			 * schema.NewFsSensitiveRead{path, rule} without a
			 * new wire field. */
			rec->op = RANA_FSOP_WRITE_OPEN;
			rec->path_source = RANA_PATH_SOURCE_RESOLVED;
			rec->pid = pid;
			rec->cgid = cgid;
			rec->ts_mono = bpf_ktime_get_ns();
			rec->ts_wall = bpf_ktime_get_boot_ns();
			rec->flags = (__u64)f_flags;
			rec->mode = (__u64)rule;
			__builtin_memcpy(rec->path, path_buf, sizeof(path_buf));
			rec->path_len = (__u16)path_len;
			__builtin_memset(rec->path2, 0, sizeof(rec->path2));
			rec->path2_len = 0;
			bpf_ringbuf_submit(rec, 0);
		}
	}

	return 0;
}

SEC("fentry/security_path_unlink")
int BPF_PROG(rana_path_unlink, struct path *dir, struct dentry *dentry)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	__u64 cgid = rana_task_cgid(task);
	if (!rana_cgid_in_session(cgid))
		return 0;

	rana_emit_fsop(RANA_FSOP_UNLINK, BPF_CORE_READ(task, tgid), cgid, 0, 0, dentry, NULL);
	return 0;
}

SEC("fentry/security_path_rename")
int BPF_PROG(rana_path_rename, struct path *old_dir, struct dentry *old_dentry,
	     struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	__u64 cgid = rana_task_cgid(task);
	if (!rana_cgid_in_session(cgid))
		return 0;

	rana_emit_fsop(RANA_FSOP_RENAME, BPF_CORE_READ(task, tgid), cgid, (__u64)flags, 0,
			old_dentry, new_dentry);
	return 0;
}

SEC("fentry/security_path_mkdir")
int BPF_PROG(rana_path_mkdir, struct path *dir, struct dentry *dentry, umode_t_placeholder mode)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	__u64 cgid = rana_task_cgid(task);
	if (!rana_cgid_in_session(cgid))
		return 0;

	rana_emit_fsop(RANA_FSOP_MKDIR, BPF_CORE_READ(task, tgid), cgid, 0, (__u64)mode,
			dentry, NULL);
	return 0;
}

/*
 * fentry vfs_truncate: fires on truncate(2)/ftruncate(2) and O_TRUNC
 * opens that route through vfs_truncate; records.md's Mode field carries
 * the target size for this Op (documented as "target size (truncate)").
 */
SEC("fentry/vfs_truncate")
int BPF_PROG(rana_vfs_truncate, struct path *p, long length)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	__u64 cgid = rana_task_cgid(task);
	if (!rana_cgid_in_session(cgid))
		return 0;

	struct dentry *dentry = BPF_CORE_READ(p, dentry);
	__u64 size = (length < 0) ? 0 : (__u64)length;
	rana_emit_fsop(RANA_FSOP_TRUNCATE, BPF_CORE_READ(task, tgid), cgid, 0, size,
			dentry, NULL);
	return 0;
}
