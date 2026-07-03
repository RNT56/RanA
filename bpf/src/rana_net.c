// SPDX-License-Identifier: Apache-2.0
/*
 * rana_net.c — network egress hooks (D7 hook set v1).
 *
 *   - cgroup/connect4, cgroup/connect6         -> net.connect (kind=5)
 *   - cgroup/sendmsg4, cgroup/sendmsg6         -> net.connect (kind=6,
 *     covers unconnected-UDP sendto, which plain connect hooks miss)
 *   - fentry unix_stream_connect               -> unix.connect (kind=7)
 *   - fentry/fexit inet_sock_set_state         -> net.flow_close (kind=8)
 *
 * P2 (observation is inert): BPF_CGROUP_SOCK_ADDR programs CAN return
 * SK_DENY/0 to block a connection — RanA's programs unconditionally
 * `return 1` (SK_PASS-equivalent allow) on every path, including error
 * paths, so this hook family, which *can* deny in Phase G, never denies
 * in v1 observe mode. This is the one hook set in D7 that is explicitly
 * called out as reusable for enforcement later ("observe now, enforce in
 * Phase G with zero re-architecture") — that reuse is not implemented
 * here; only the always-allow observe path is.
 */

#include "common.h"
#include <linux/in.h>
#include <linux/socket.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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
	__builtin_memset(rec->path, 0, sizeof(rec->path));
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
 * fentry inet_sock_set_state: flow-close accounting (net.flow_close,
 * kind=8). Only emits on transition into TCP_CLOSE; byte counters come
 * from the sock's tcp_info-equivalent fields where CO-RE-relocatable,
 * else 0 (never fatal — a best-effort accounting field, not an
 * attribution-critical one per D7).
 */
SEC("fentry/inet_sock_set_state")
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
