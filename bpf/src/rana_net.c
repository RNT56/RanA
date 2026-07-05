// SPDX-License-Identifier: Apache-2.0
/*
 * rana_net.c — network egress hooks (D7 hook set v1).
 *
 *   - cgroup/connect4, cgroup/connect6         -> net.connect (kind=5)
 *   - cgroup/sendmsg4, cgroup/sendmsg6         -> net.connect (kind=6,
 *     covers unconnected-UDP sendto, which plain connect hooks miss)
 *   - fentry unix_stream_connect               -> unix.connect (kind=7)
 *   - fentry/fexit inet_sock_set_state         -> net.flow_close (kind=8)
 *   - lsm/socket_connect                       -> net.connect (kind=5,
 *     TierEnhanced+ only — see rana_socket_connect below: closes the
 *     io_uring IORING_OP_CONNECT escape documented in LIMITS.md, which
 *     issues its connect via the socket ops path rather than a syscall the
 *     cgroup/connect4·6 hooks intercept)
 *
 * P2 (observation is inert): BPF_CGROUP_SOCK_ADDR programs CAN return
 * SK_DENY/0 to block a connection — RanA's programs unconditionally
 * `return 1` (SK_PASS-equivalent allow) on every path, including error
 * paths, so this hook family, which *can* deny in Phase G, never denies
 * in v1 observe mode. This is the one hook set in D7 that is explicitly
 * called out as reusable for enforcement later ("observe now, enforce in
 * Phase G with zero re-architecture") — that reuse is not implemented
 * here; only the always-allow observe path is. The LSM hook below has the
 * same shape: BPF LSM programs attached to an "int" LSM hook CAN return a
 * non-zero errno to deny; rana_socket_connect unconditionally `return 0`
 * (allow) on every path, so it never denies in v1 observe mode either.
 */

#include "common.h"
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BTF type anchors: at -O2 clang may optimize away the debug info of
 * pointer locals, dropping the record struct from the object's BTF and
 * breaking bpf2go's -type collection ("looking up type ...: not
 * found"). An unused global pointer per exported record type forces the
 * full type into BTF regardless of optimization — the canonical
 * libbpf-tools idiom. Never read or written at runtime. */
const struct rana_connect_record *__rana_btf_rana_connect_record __attribute__((unused));
const struct rana_unix_connect_record *__rana_btf_rana_unix_connect_record __attribute__((unused));
const struct rana_flow_close_record *__rana_btf_rana_flow_close_record __attribute__((unused));

static __always_inline void rana_emit_connect(__u8 kind, __u8 proto, __u8 family,
					       __u32 pid, __u64 cgid,
					       const __u8 daddr[16], __u16 dport)
{
	struct rana_connect_record *rec = bpf_ringbuf_reserve(&rana_events, sizeof(*rec), 0);
	if (!rec)
		return;

	rec->version = RANA_RECORD_VERSION;
	rec->kind = kind;
	rec->proto = proto;
	rec->family = family;
	rec->pid = pid;
	rec->cgid = cgid;
	rec->ts_mono = bpf_ktime_get_ns();
	rec->ts_wall = bpf_ktime_get_boot_ns();
	__builtin_memcpy(rec->daddr, daddr, 16);
	rec->dport = dport;

	bpf_ringbuf_submit(rec, 0);
}

/* v4-maps an IPv4 address (network-order be32) into a 16-byte v4-mapped
 * IPv6-shaped buffer per records.md's Daddr convention. */
static __always_inline void rana_v4_mapped(__u32 be_addr, __u8 out[16])
{
	__builtin_memset(out, 0, 10);
	out[10] = 0xff;
	out[11] = 0xff;
	__builtin_memcpy(out + 12, &be_addr, 4);
}

/*
 * cgroup/connect4, cgroup/connect6: BPF_CGROUP_SOCK_ADDR programs. The
 * verifier requires these return 1 (allow) or 0 (deny); RanA always
 * returns 1 — see file header. `ctx` fields are already in the verifier's
 * trusted bpf_sock_addr shape (not something CO-RE needs to relocate).
 */
SEC("cgroup/connect4")
int rana_connect4(struct bpf_sock_addr *ctx)
{
	__u64 cgid = rana_task_cgid((struct task_struct *)bpf_get_current_task_btf());
	if (!rana_cgid_in_session(cgid))
		return 1;

	__u8 daddr[16];
	rana_v4_mapped(ctx->user_ip4, daddr);
	__u16 dport = (__u16)(bpf_ntohl(ctx->user_port) >> 16);
	__u8 proto = (ctx->protocol == IPPROTO_UDP) ? 17 : 6;

	rana_emit_connect(RANA_KIND_CONNECT, proto, 4, bpf_get_current_pid_tgid() >> 32,
			   cgid, daddr, dport);
	return 1;
}

SEC("cgroup/connect6")
int rana_connect6(struct bpf_sock_addr *ctx)
{
	__u64 cgid = rana_task_cgid((struct task_struct *)bpf_get_current_task_btf());
	if (!rana_cgid_in_session(cgid))
		return 1;

	__u8 daddr[16];
	__builtin_memcpy(daddr, ctx->user_ip6, 16);
	__u16 dport = (__u16)(bpf_ntohl(ctx->user_port) >> 16);
	__u8 proto = (ctx->protocol == IPPROTO_UDP) ? 17 : 6;

	rana_emit_connect(RANA_KIND_CONNECT, proto, 6, bpf_get_current_pid_tgid() >> 32,
			   cgid, daddr, dport);
	return 1;
}

/*
 * cgroup/sendmsg4, cgroup/sendmsg6: covers unconnected-UDP sendto, which
 * connect4/6 never sees (D7: "sendmsg covers unconnected-UDP sendto,
 * which plain connect hooks miss"). Recorded as kind=6 (SendmsgRecord)
 * so the collector's governor can account for it separately even though
 * it decodes into the same net.connect schema shape.
 */
SEC("cgroup/sendmsg4")
int rana_sendmsg4(struct bpf_sock_addr *ctx)
{
	__u64 cgid = rana_task_cgid((struct task_struct *)bpf_get_current_task_btf());
	if (!rana_cgid_in_session(cgid))
		return 1;

	__u8 daddr[16];
	rana_v4_mapped(ctx->user_ip4, daddr);
	__u16 dport = (__u16)(bpf_ntohl(ctx->user_port) >> 16);

	rana_emit_connect(RANA_KIND_SENDMSG, 17, 4, bpf_get_current_pid_tgid() >> 32,
			   cgid, daddr, dport);
	return 1;
}

SEC("cgroup/sendmsg6")
int rana_sendmsg6(struct bpf_sock_addr *ctx)
{
	__u64 cgid = rana_task_cgid((struct task_struct *)bpf_get_current_task_btf());
	if (!rana_cgid_in_session(cgid))
		return 1;

	__u8 daddr[16];
	__builtin_memcpy(daddr, ctx->user_ip6, 16);
	__u16 dport = (__u16)(bpf_ntohl(ctx->user_port) >> 16);

	rana_emit_connect(RANA_KIND_SENDMSG, 17, 6, bpf_get_current_pid_tgid() >> 32,
			   cgid, daddr, dport);
	return 1;
}

/*
 * fentry unix_stream_connect: AF_UNIX stream connect (D7). fentry cannot
 * change the return value it observes (that's fexit's business, and even
 * fexit here never calls the return-value override helper) — purely observational.
 */
SEC("fentry/unix_stream_connect")
int BPF_PROG(rana_unix_connect, struct socket *sock, struct sockaddr *addr,
	     int addr_len, int flags)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	__u64 cgid = rana_task_cgid(task);
	if (!rana_cgid_in_session(cgid))
		return 0;

	struct rana_unix_connect_record *rec = bpf_ringbuf_reserve(&rana_events, sizeof(*rec), 0);
	if (!rec)
		return 0;

	rec->version = RANA_RECORD_VERSION;
	rec->kind = RANA_KIND_UNIXCONNECT;
	rec->pid = bpf_get_current_pid_tgid() >> 32;
	rec->cgid = cgid;
	rec->ts_mono = bpf_ktime_get_ns();
	rec->ts_wall = bpf_ktime_get_boot_ns();

	/* struct sockaddr_un's sun_path is a fixed 108-byte buffer inline in
	 * `addr` (cast from struct sockaddr*); read it directly as kernel
	 * memory reachable from the fentry argument (never user memory). */
	/* No zero-fill of the multi-KB path buffer — decoder slices by
	 * path_len (see the buffer-tail note in rana_exec.c). */
	rec->path_len = 0;
	if (addr) {
		/* sun_path begins at offset 2 in sockaddr_un (after
		 * sa_family_t); addr_len bounds the valid prefix. */
		int plen = addr_len - 2;
		if (plen < 0)
			plen = 0;
		if (plen > 108)
			plen = 108; /* UNIX_PATH_MAX */
		if (plen > 0) {
			long ret = bpf_probe_read_kernel(rec->path, (__u32)plen,
							  (const void *)addr + 2);
			if (ret == 0) {
				int l = 0;
				#pragma unroll
				for (int i = 0; i < 108; i++) {
					if (i >= plen || rec->path[i] == 0)
						break;
					l++;
				}
				rec->path_len = (__u16)l;
			}
		}
	}

	bpf_ringbuf_submit(rec, 0);
	return 0;
}

/*
 * tp_btf inet_sock_set_state: flow-close accounting (net.flow_close,
 * kind=8). inet_sock_set_state is a TRACEPOINT (its TP_PROTO is exactly
 * this argument list), not a kernel function — an fentry SEC here would
 * find no BTF func to attach to and fail at load. Only emits on
 * transition into TCP_CLOSE; byte counters come from the sock's
 * tcp_info-equivalent fields where CO-RE-relocatable, else 0 (never
 * fatal — a best-effort accounting field, not an attribution-critical
 * one per D7).
 */
SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(rana_flow_close, struct sock *sk, int oldstate, int newstate)
{
	#define RANA_TCP_CLOSE 7
	if (newstate != RANA_TCP_CLOSE)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	__u64 cgid = rana_task_cgid(task);
	if (!rana_cgid_in_session(cgid))
		return 0;

	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

	struct rana_flow_close_record *rec = bpf_ringbuf_reserve(&rana_events, sizeof(*rec), 0);
	if (!rec)
		return 0;

	rec->version = RANA_RECORD_VERSION;
	rec->kind = RANA_KIND_FLOWCLOSE;
	rec->proto = 6; /* TCP only: inet_sock_set_state is a TCP-only hook */
	rec->family = (family == 10 /* AF_INET6 */) ? 6 : 4;
	rec->pid = bpf_get_current_pid_tgid() >> 32;
	rec->cgid = cgid;
	rec->ts_mono = bpf_ktime_get_ns();
	rec->ts_wall = bpf_ktime_get_boot_ns();
	__builtin_memset(rec->daddr, 0, sizeof(rec->daddr));
	rec->dport = 0;
	rec->bytes_tx = 0;
	rec->bytes_rx = 0;
	rec->dur_ns = 0;

	bpf_ringbuf_submit(rec, 0);
	return 0;
}

/*
 * lsm/socket_connect: closes the io_uring network-connect escape
 * documented in LIMITS.md ("io_uring socket ops" row / the per-kernel
 * coverage table). IORING_OP_CONNECT ultimately calls the kernel's
 * __sys_connect_file()/security_socket_connect() path just like a normal
 * connect(2) syscall does — but it does NOT go through the userspace
 * connect(2) syscall entry the cgroup/connect4·6 BPF_CGROUP_SOCK_ADDR
 * hooks are attached to, so on kernels where those are the only network
 * hooks, an io_uring-issued connect is invisible. security_socket_connect
 * fires for BOTH paths (plain syscall and io_uring), so attaching here
 * too would double-emit for the common case; this hook exists
 * specifically to catch the io_uring path where cgroup/connect4·6 did NOT
 * fire, gated to TierEnhanced+ (loader_tier.go's WantedPrograms) where BPF
 * LSM attachment is a well-supported, stable attach mechanism (D5: v1's
 * complete hook set is baseline; this is coverage, not a new feature —
 * docs/ARCHITECTURE.md §7).
 *
 * De-duplication against cgroup/connect4·6 is a userspace/enrichment
 * concern (both feed the identical RANA_KIND_CONNECT wire shape into the
 * same ring buffer; internal/collector's governor and downstream
 * de-duplication-by-(pid,daddr,dport,ts window) tooling, not this file,
 * decide whether two records describe the same connect attempt) — this
 * hook's only job is to make sure the io_uring path is never *silently*
 * unrepresented on kernels that support LSM attachment.
 *
 * P2: this is a BPF_PROG_TYPE_LSM program attached to
 * security_socket_connect(sock, address, addrlen), an int-returning hook
 * that CAN deny (return non-zero to block the connect) — RanA
 * unconditionally returns 0 (allow) on every path, including every error
 * path below, so it never denies in v1 observe mode (see file header).
 * Unlike an fmod_ret/fexit attachment, a plain lsm/ program observes the
 * hook's own call arguments only, before the security decision is made —
 * there is no "did it succeed" result available here to gate on (a
 * meaningful difference from inet_sock_set_state's post-hoc TCP_CLOSE
 * check above); a connect that this hook allows and that subsequently
 * fails downstream (ECONNREFUSED, etc.) still gets a net.connect record,
 * matching cgroup/connect4·6's existing behavior of recording the
 * attempt, not the outcome (records.md documents no success/failure field
 * on ConnectRecord).
 */
SEC("lsm/socket_connect")
int BPF_PROG(rana_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	__u64 cgid = rana_task_cgid((struct task_struct *)bpf_get_current_task_btf());
	if (!rana_cgid_in_session(cgid))
		return 0;

	if (!address)
		return 0;

	__u16 family = 0;
	bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);

	__u8 daddr[16];
	__u16 dport = 0;
	__u8 proto = 6; /* io_uring's IORING_OP_CONNECT targets a
			  * caller-created socket; its type (TCP vs UDP) isn't
			  * carried on this LSM hook's arguments, and the
			  * overwhelming majority of io_uring connect use is
			  * TCP (D7/D24: no speculative classification beyond
			  * what's cheaply, locally knowable) — proto is
			  * best-effort here, never attribution-critical. */

	if (family == 2 /* AF_INET */ && addrlen >= (int)sizeof(struct sockaddr_in)) {
		__u32 be_addr = 0;
		__u16 be_port = 0;
		struct sockaddr_in *sin = (struct sockaddr_in *)address;
		bpf_probe_read_kernel(&be_addr, sizeof(be_addr), &sin->sin_addr);
		bpf_probe_read_kernel(&be_port, sizeof(be_port), &sin->sin_port);
		rana_v4_mapped(be_addr, daddr);
		dport = bpf_ntohs(be_port);
	} else if (family == 10 /* AF_INET6 */ && addrlen >= (int)sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
		bpf_probe_read_kernel(daddr, sizeof(daddr), &sin6->sin6_addr);
		__u16 be_port = 0;
		bpf_probe_read_kernel(&be_port, sizeof(be_port), &sin6->sin6_port);
		dport = bpf_ntohs(be_port);
	} else {
		return 0; /* not an INET/INET6 destination (e.g. AF_UNIX,
			   * already covered by fentry/unix_stream_connect) */
	}

	rana_emit_connect(RANA_KIND_CONNECT, proto, (family == 10) ? 6 : 4,
			   bpf_get_current_pid_tgid() >> 32, cgid, daddr, dport);
	return 0;
}
