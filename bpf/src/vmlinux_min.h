/* SPDX-License-Identifier: Apache-2.0 */
/*
 * vmlinux_min.h — minimal, hand-written CO-RE type definitions.
 *
 * CLAUDE.md/CONTRACTS §internal/bpf requires "minimal manually-defined
 * CO-RE structs with preserve_access_index, NOT a giant vmlinux.h". Every
 * struct here declares only the fields RanA's programs actually read, in
 * the order the real kernel struct declares them up to and including the
 * field we need — BPF CO-RE (via bpf_core_read / __builtin_preserve_...)
 * relocates field offsets against the *target* kernel's BTF at load time,
 * so this header only needs to describe field *names and relative shape*
 * accurately enough for the compiler to generate a relocatable access;
 * the loader (internal/bpf/loader.go) fails closed if BTF disagrees.
 *
 * Every struct is marked with a bare forward-compatible field set behind
 * __attribute__((preserve_access_index)); we never rely on struct sizeof,
 * only on named field access, per CO-RE convention.
 */

#ifndef RANA_VMLINUX_MIN_H
#define RANA_VMLINUX_MIN_H

#include <linux/types.h>

/* The BPF UAPI (map-type / update-flags enums and, critically, the
 * `struct __sk_buff` program context the cgroup_skb DNS hook parses) comes
 * from the authoritative <linux/bpf.h>. This is deliberately NOT part of the
 * "minimal hand-defined CO-RE" set: __sk_buff is a fixed-layout *UAPI context*
 * struct whose field offsets the verifier rewrites at load — a hand-rolled
 * copy with a wrong offset would compile cleanly yet be rejected at load, the
 * worst failure mode. The hand-defined structs below remain kernel-internal
 * CO-RE types (task_struct, path, …), relocated against target BTF; only the
 * stable UAPI is sourced here. */
#include <linux/bpf.h>

typedef unsigned short umode_t_placeholder;

/* Kernel pid_t (used by the sched_process_exec tracepoint prototype).
 * Userspace <linux/types.h> defines only __kernel_pid_t; the kernel's
 * `typedef __kernel_pid_t pid_t` (= int) is stable UAPI, restated here. */
typedef int pid_t;
typedef unsigned int dev_t_placeholder;

/* Forward declarations so field types below can reference each other
 * regardless of definition order. */
struct task_struct;
struct fs_struct;
struct cred;
struct cgroup;
struct cgroup_subsys_state;
struct css_set;
struct qstr;
struct dentry;
struct vfsmount;
struct mount;
struct path;
struct inode;
struct super_block;
struct file;
struct sock_common;
struct sock;
struct linux_binprm;
struct mm_struct;
struct socket;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

/* task_struct: only the ancestry/identity fields RanA reads. */
struct task_struct {
	int pid;
	int tgid;
	int exit_code;
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	unsigned int flags;
	struct css_set *cgroups;
	struct cred *real_cred;
	struct nsproxy *nsproxy;
	struct fs_struct *fs;
};

/* path: the (mnt, dentry) pair fs_struct.pwd and file.f_path resolve against.
 * Defined (not just forward-declared) because fs_struct embeds it BY VALUE;
 * the pointed-to vfsmount/dentry stay incomplete (only pointer access). */
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

/* fs_struct: current working directory, for proc.exec's cwd field. */
struct fs_struct {
	struct path pwd;
};

/* cred: uid we attribute exec/open events to. kuid_t is a struct{u32 val}
 * in the real kernel; the .c files read ->uid.val via BPF_CORE_READ,
 * which tolerates the wrapper via CO-RE's nested-field relocation, so we
 * declare uid as the wrapper shape rather than a bare int. */
struct kuid_wrapper {
	__u32 val;
};

struct cred {
	struct kuid_wrapper uid;
};

/* cgroup plumbing: only what's needed to read a task's cgroup id (cgid)
 * for the default (v2) hierarchy, per D6 (one cgroup v2 leaf = one
 * session). */
struct cgroup {
	__u64 kn_id; /* mirrors cgroup->kn->id via a flattened CO-RE read
	              * helper in the .c files (BPF_CORE_READ chases
	              * ->kn->id); declared flat here only to document the
	              * final integer this ultimately resolves to. */
};

struct cgroup_subsys_state {
	struct cgroup *cgroup;
};

struct css_set {
	struct cgroup_subsys_state *subsys[1]; /* index 0 is enough: we only
	                                         * ever read subsys[0]->cgroup
	                                         * for the unified (v2)
	                                         * hierarchy id. */
};

/* dentry/path/mount: bounded resolved-path walk (D7) for file ops,
 * bounded to RANA_MAX_PATH_COMPONENTS (<=48) segments. */
struct qstr {
	const unsigned char *name;
	__u32 len;
};

struct dentry {
	struct dentry *d_parent;
	struct qstr d_name;
	struct inode *d_inode;
	struct super_block *d_sb;
};

struct vfsmount {
	struct dentry *mnt_root;
	struct super_block *mnt_sb;
};

struct mount {
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
};

struct inode {
	unsigned long i_ino;
	struct super_block *i_sb;
	umode_t_placeholder i_mode;
};

struct super_block {
	dev_t_placeholder s_dev;
};

/* file: security_file_open's argument; we only need f_path. */
struct file {
	struct path f_path;
	unsigned int f_flags;
	umode_t_placeholder f_mode;
};

/* struct sock / inet_sock fields read from cgroup_sock_addr /
 * inet_sock_set_state programs — kept minimal, address family + state
 * only (the actual 4-tuple comes from the sock_addr/skops context
 * structs the verifier already understands, not from this struct). */
struct sock_common {
	unsigned short skc_family;
	__u8 skc_state;
};

struct sock {
	struct sock_common __sk_common;
};

/* linux_binprm: sched_process_exec's third argument — the exec image
 * being loaded. mm carries arg_start/arg_end, the user-space argv blob
 * rana_exec.c reads with bpf_probe_read_user (never write). */
struct mm_struct {
	unsigned long arg_start;
	unsigned long arg_end;
};

struct linux_binprm {
	struct file *file;
	struct mm_struct *mm;
};

/* socket: unix_stream_connect's first argument; unused beyond the fentry
 * signature match (the sun_path we care about comes from the `addr`
 * argument, not from walking into `sock`). Declared so the function
 * prototype in rana_net.c type-checks against the real kernel symbol. */
struct socket {
	struct sock *sk;
};

/* sockaddr: the kernel-internal generic socket address (the LSM
 * socket_connect / unix_stream_connect hooks pass it). UAPI
 * <linux/socket.h> deliberately does not define it; its layout
 * (sa_family at offset 0, 14 opaque data bytes) has been ABI-stable
 * since 4.2BSD, so restating it here is safe. Only sa_family is ever
 * read generically; family-specific casts go through the UAPI
 * sockaddr_in/sockaddr_in6 definitions. */
struct sockaddr {
	__u16 sa_family;
	char sa_data[14];
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#pragma clang diagnostic pop

#endif /* RANA_VMLINUX_MIN_H */
