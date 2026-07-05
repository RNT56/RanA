// SPDX-License-Identifier: Apache-2.0
/*
 * rana_fs.c — file-op hooks (D7 hook set v1).
 *
 *   - fentry security_file_open        -> fs.write_open (kind=4, op=1) for
 *     write-intent opens, and fs.sensitive_read (kind=4, op=7) for opens
 *     (read or write) of a watchlisted path/inode (rana_sensitive_prefixes /
 *     rana_sensitive_inodes, D9)
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

/* BTF type anchors: at -O2 clang may optimize away the debug info of
 * pointer locals, dropping the record struct from the object's BTF and
 * breaking bpf2go's -type collection ("looking up type ...: not
 * found"). An unused global pointer per exported record type forces the
 * full type into BTF regardless of optimization — the canonical
 * libbpf-tools idiom. Never read or written at runtime. */
const struct rana_fsop_record *__rana_btf_rana_fsop_record __attribute__((unused));

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

	/* No zero-fill of the multi-KB path buffers — see the buffer-tail
	 * note in rana_exec.c: the decoder reads exactly path{,2}_len bytes;
	 * a multi-KB memset cannot be lowered for the BPF target anyway. */
	rec->path_len = (__u16)rana_resolve_path(dentry, rec->path, sizeof(rec->path));

	rec->path2_len = 0;
	if (dentry2)
		rec->path2_len = (__u16)rana_resolve_path(dentry2, rec->path2, sizeof(rec->path2));

	bpf_ringbuf_submit(rec, 0);
}

/* rana_match_sensitive_prefix / rana_match_sensitive_inode: match the
 * resolved path against rana_sensitive_prefixes (D9) and the pinned
 * (dev,inode) identity map. A match produces an fs.sensitive_read event via
 * an FsOpRecord (kind=4) with op=RANA_FSOP_SENSITIVE_READ and Mode carrying
 * the matched rule id — a dedicated op, so the collector never confuses a
 * watchlisted read with an fs.write_open. FsOpRecord's wire shape is reused
 * (no eleventh record kind) since sensitive_read needs only {path, rule}.
 * Returns the matched rule id, or 0 if no match. */
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
	 * the trifecta precursor D9 exists to catch). The staging buffer is
	 * per-CPU scratch, not stack (2048B > the 512B BPF stack limit) —
	 * resolve_path writes path_buf *after* its comps walk, so the two
	 * scratch fields never overlap within this call. */
	struct rana_scratch *scratch = rana_scratch();
	if (!scratch)
		return 0;
	__u8 *path_buf = scratch->path_buf;
	int path_len = rana_resolve_path(dentry, path_buf, RANA_CAP_FSOP_PATH);

	__u32 rule = rana_match_sensitive_prefix(path_buf, path_len);
	if (!rule)
		rule = rana_match_sensitive_inode(dentry);

	if (rule) {
		struct rana_fsop_record *rec = bpf_ringbuf_reserve(&rana_events, sizeof(*rec), 0);
		if (rec) {
			rec->version = RANA_RECORD_VERSION;
			rec->kind = RANA_KIND_FSOP;
			/* Sensitive-read carries its own dedicated op
			 * (RANA_FSOP_SENSITIVE_READ) so the collector maps it to
			 * fs.sensitive_read, never fs.write_open — a read-only open
			 * of ~/.ssh is a read, not a write. Mode carries the matched
			 * rule id, which the collector renders into the event's
			 * `rule` field (schema.NewFsSensitiveRead{path, rule}). */
			rec->op = RANA_FSOP_SENSITIVE_READ;
			rec->path_source = RANA_PATH_SOURCE_RESOLVED;
			rec->pid = pid;
			rec->cgid = cgid;
			rec->ts_mono = bpf_ktime_get_ns();
			rec->ts_wall = bpf_ktime_get_boot_ns();
			rec->flags = (__u64)f_flags;
			rec->mode = (__u64)rule;
			/* Bounded helper copy, not memcpy: a 2048B memcpy
			 * cannot be lowered for the BPF target, and only
			 * path_len bytes are meaningful (decoder slices by
			 * path_len; see the buffer-tail note in rana_exec.c). */
			rec->path_len = 0;
			if (path_len > 0 && path_len <= RANA_CAP_FSOP_PATH) {
				if (bpf_probe_read_kernel(rec->path, (__u32)path_len, path_buf) == 0)
					rec->path_len = (__u16)path_len;
			}
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

/*
 * fentry security_path_link (linkat(2)/link(2) creating a new hardlink):
 * closes the documented hardlink dodge (LIMITS.md "Hardlinks into the
 * sensitive watchlist" row) for links created DURING a recorded session.
 *
 * A hardlink shares its target's (dev,inode) — rana_sensitive_inodes
 * already defeats a hardlink to a file that was PINNED AT SESSION START
 * (D7/D9). The gap is a file that only matches a *prefix* rule (e.g.
 * "~/.ssh") rather than being individually pinned by inode: if a session
 * process hardlinks that file to a path outside the watched prefix, a
 * later open under the new alias path won't match the prefix string, and
 * — until now — the target inode wasn't in rana_sensitive_inodes either
 * (only pre-existing-at-start files got pinned), so the aliased read was
 * invisible to fs.sensitive_read matching.
 *
 * Fix: on every hardlink creation, resolve the EXISTING (old) dentry's
 * path and check it against the sensitive-prefix map exactly like
 * security_file_open does; if it matches, pin the underlying inode's
 * (dev,ino) into rana_sensitive_inodes right now (re-pin), so ANY future
 * open — including through the brand-new alias path — is caught by the
 * inode-identity check regardless of which name it's opened under. This
 * is a map write, not a ringbuf event by itself (no new record kind is
 * introduced — the fs.rename/fs.write_open-shaped record already carries
 * the create-a-hardlink fact if/when a future dedicated fs.link op is
 * added; today the point of this hook is purely the defensive re-pin, so
 * a compromised agent cannot outrun the watchlist by hardlinking a
 * prefix-matched sensitive file to a fresh, unwatched path before reading
 * it under the new name).
 *
 * P2: fentry cannot alter security_path_link's return value or block the
 * link — purely observational bookkeeping into a map RanA itself owns.
 */
SEC("fentry/security_path_link")
int BPF_PROG(rana_path_link, struct dentry *old_dentry, struct path *new_dir,
	     struct dentry *new_dentry)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	__u64 cgid = rana_task_cgid(task);
	if (!rana_cgid_in_session(cgid))
		return 0;

	/* Per-CPU scratch staging (see the file_open site above). */
	struct rana_scratch *scratch = rana_scratch();
	if (!scratch)
		return 0;
	__u8 *path_buf = scratch->path_buf;
	int path_len = rana_resolve_path(old_dentry, path_buf, RANA_CAP_FSOP_PATH);

	__u32 rule = rana_match_sensitive_prefix(path_buf, path_len);
	if (!rule) {
		/* Already-pinned-by-inode files need no re-pin (they're caught
		 * regardless of alias path already); only a prefix-only match
		 * needs the defensive re-pin below. */
		return 0;
	}

	struct inode *inode = BPF_CORE_READ(old_dentry, d_inode);
	if (!inode)
		return 0;

	struct rana_dev_inode_key key = {};
	key.ino = BPF_CORE_READ(inode, i_ino);
	struct super_block *sb = BPF_CORE_READ(inode, i_sb);
	if (sb)
		key.dev = BPF_CORE_READ(sb, s_dev);

	/* Re-pin: from this point on, ANY path resolving to this (dev,ino) —
	 * old name or the brand-new hardlinked alias — matches
	 * rana_match_sensitive_inode in security_file_open, independent of
	 * the alias's own path string. BPF_ANY: fine to overwrite an existing
	 * pin with the same rule id (idempotent). */
	bpf_map_update_elem(&rana_sensitive_inodes, &key, &rule, BPF_ANY);
	return 0;
}
