// SPDX-License-Identifier: Apache-2.0
/*
 * rana_dns.c — DNS query capture (D7 hook set v1).
 *
 * cgroup_skb/egress, filtered to UDP dst-port 53, parses the DNS wire
 * format's question section (qname, ≤4 questions per the plan's bound —
 * this file, like records.md, caps the *answers* at 4 since real-world
 * outbound queries almost always carry exactly one question; a query
 * with more than one question still yields its first qname) and, for
 * responses seen egressing (rare but possible for a resolver-in-session
 * case), the answer section addresses.
 *
 * ONLY qname and answer addresses are ever read — never any other DNS
 * record data (TXT, MX content, etc.) and never the payload of any
 * non-port-53 UDP flow. This is a hard scope wall: RanA is not payload
 * capture (CLAUDE.md §2), and DNS is the sole, explicitly-carved-out
 * exception, bounded to exactly the fields records.md's DNSRecord
 * declares.
 *
 * P2: cgroup_skb programs return 1 (allow) or 0 (drop the packet) to the
 * stack. Every path in this file returns 1 — observation is inert; this
 * hook is never used to drop traffic in v1.
 */

#include "common.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BTF type anchors: at -O2 clang may optimize away the debug info of
 * pointer locals, dropping the record struct from the object's BTF and
 * breaking bpf2go's -type collection ("looking up type ...: not
 * found"). An unused global pointer per exported record type forces the
 * full type into BTF regardless of optimization — the canonical
 * libbpf-tools idiom. Never read or written at runtime. */
const struct rana_dns_record *__rana_btf_rana_dns_record __attribute__((unused));

#define RANA_DNS_PORT 53
#define RANA_ETH_HLEN 14
#define RANA_DNS_HDR_LEN 12
#define RANA_DNS_MAX_LABEL 63
#define RANA_DNS_MAX_NAME_WALK 128 /* bounded loop over wire-format labels;
				    * generous vs. the 255-byte qname cap so
				    * legitimate names never truncate early,
				    * while still giving the verifier a
				    * static bound. */

struct rana_dns_cursor {
	struct __sk_buff *skb;
	__u32 off;
};

/* rana_read_u8/u16 read via bpf_skb_load_bytes, which bounds-checks
 * against the skb at RUNTIME inside the helper — no packet pointers, no
 * verifier range reasoning. This is deliberate, and the result of a real
 * bring-up fight: direct data/data_end access in this dynamically-offset
 * parser was rejected by the verifier across three successive shapes
 * (re-derived pointers, single-lineage pointers, barrier-pinned
 * pointers) because clang kept materializing an alternate derivation of
 * the checked pointer — the compare blessed one register id, the load
 * used another (e.g. "R4(id=35,off=1,r=0) offset is outside of the
 * packet" while the id=36 twin was checked). The helper form removes the
 * entire class by construction; the cost is one helper call per read on
 * UDP-port-53 packets only. Nothing beyond the DNS header +
 * question/answer name and type/class fields is ever read (never
 * TXT/MX/other rdata, per the file header). */
static __always_inline int rana_read_u8(struct rana_dns_cursor *c, __u8 *out)
{
	if (bpf_skb_load_bytes(c->skb, c->off, out, 1) < 0)
		return -1;
	c->off += 1;
	return 0;
}

static __always_inline int rana_read_u16(struct rana_dns_cursor *c, __u16 *out)
{
	__u8 b[2];
	if (bpf_skb_load_bytes(c->skb, c->off, b, 2) < 0)
		return -1;
	*out = ((__u16)b[0] << 8) | b[1];
	c->off += 2;
	return 0;
}

/*
 * rana_parse_qname: reads a DNS wire-format name (length-prefixed
 * labels, NUL-terminated by a zero-length label; compression pointers
 * are NOT followed — a compressed pointer in the question section is
 * rare for egress queries and following one safely under the verifier's
 * bounded-loop requirement adds complexity for a case that doesn't
 * affect the qname we actually want, the question's own name, which
 * DNS clients always encode literally, never compressed, being first in
 * the packet). Writes a dotted-ASCII name into `out` (capacity `cap`),
 * returns the number of bytes written, or -1 on a malformed packet.
 */
static __always_inline int rana_parse_qname(struct rana_dns_cursor *c, __u8 *out, int cap)
{
	/* Deliberately NOT unrolled: the fully-unrolled form (128 outer x 63
	 * inner reads) blew the verifier's 1M-instruction processing budget.
	 * Bounded loops verify natively since 5.3 (well inside the 5.15
	 * floor) and state pruning keeps the cost tiny. Each label is copied
	 * with ONE bpf_skb_load_bytes of label_len bytes (verifier-bounded
	 * [1,63]) instead of byte-at-a-time, so the loop body is a handful
	 * of instructions. */
	int out_off = 0;
	for (int i = 0; i < RANA_DNS_MAX_NAME_WALK; i++) {
		__u8 label_len;
		if (rana_read_u8(c, &label_len) < 0)
			return -1;
		if (label_len == 0)
			break; /* root label: end of name */
		if (label_len & 0xC0)
			return -1; /* compression pointer: not followed, see above */
		if (label_len > RANA_DNS_MAX_LABEL)
			return -1;

		/* '.' plus a max-size label must provably fit (constant
		 * compare; cap is a constant at the single call site). */
		if (out_off < 0 || out_off > cap - RANA_DNS_MAX_LABEL - 2)
			break;
		if (out_off > 0) {
			out[out_off] = '.';
			out_off++;
		}

		if (bpf_skb_load_bytes(c->skb, c->off, out + out_off, label_len) < 0)
			return -1;
		c->off += label_len;
		out_off += label_len;
	}
	if (out_off < 0)
		out_off = 0;
	if (out_off < cap)
		out[out_off] = 0;
	return out_off;
}

static __always_inline void rana_v4_mapped_dns(const __u8 addr[4], __u8 out[16])
{
	__builtin_memset(out, 0, 10);
	out[10] = 0xff;
	out[11] = 0xff;
	__builtin_memcpy(out + 12, addr, 4);
}

SEC("cgroup_skb/egress")
int rana_dns_egress(struct __sk_buff *skb)
{
	/* Only UDP dst-port 53 is ever parsed; every other flow returns 1
	 * (allow, unexamined) immediately — this hook never even looks at
	 * TCP DNS (rare, and out of v1 scope) or any other UDP traffic. */
	if (skb->protocol != bpf_htons(ETH_P_IP))
		return 1;

	/* Header fields via bpf_skb_load_bytes, like the cursor reads below
	 * (see the note above rana_read_u8 for why this program avoids
	 * direct packet pointers entirely). Byte 0 = version/ihl, byte 9 =
	 * protocol; UDP dest port sits 2 bytes into the UDP header. */
	__u8 vihl, l4proto;
	if (bpf_skb_load_bytes(skb, 0, &vihl, 1) < 0)
		return 1;
	if (bpf_skb_load_bytes(skb, 9, &l4proto, 1) < 0)
		return 1;
	if (l4proto != IPPROTO_UDP)
		return 1;

	__u32 ip_hlen = (__u32)(vihl & 0x0f) * 4;
	if (ip_hlen < sizeof(struct iphdr))
		return 1;

	__u8 dportb[2];
	if (bpf_skb_load_bytes(skb, ip_hlen + 2, dportb, 2) < 0)
		return 1;
	if ((((__u16)dportb[0] << 8) | dportb[1]) != RANA_DNS_PORT)
		return 1;

	/* Attribution comes from the SOCKET's cgroup (bpf_skb_cgroup_id),
	 * never from `current`: cgroup_skb egress runs in softirq context,
	 * where the current task is whatever happened to be interrupted —
	 * current-task helpers are both unavailable to this program type
	 * (the load failed with "unknown func bpf_get_current_pid_tgid")
	 * and, where they exist, WRONG attribution. The skb's socket-owner
	 * cgroup is the kernel truth (P1). */
	__u64 cgid = bpf_skb_cgroup_id(skb);
	if (!rana_cgid_in_session(cgid))
		return 1;

	struct rana_dns_cursor cur = {
		.skb = skb,
		.off = ip_hlen + (__u32)sizeof(struct udphdr),
	};

	__u16 qdcount;
	{
		/* DNS header: id(2) flags(2) qdcount(2) ancount(2) nscount(2)
		 * arcount(2). We only need qdcount (question count, capped
		 * at 4 per records.md) and, later, ancount for answers. */
		cur.off += 4; /* id, flags */
		if (rana_read_u16(&cur, &qdcount) < 0)
			return 1;
	}
	__u16 ancount;
	if (rana_read_u16(&cur, &ancount) < 0)
		return 1;
	cur.off += 4; /* nscount, arcount */

	if (qdcount == 0)
		return 1; /* not a query we can extract a qname from */

	struct rana_dns_record *rec = bpf_ringbuf_reserve(&rana_events, sizeof(*rec), 0);
	if (!rec)
		return 1;

	rec->version = RANA_RECORD_VERSION;
	rec->kind = RANA_KIND_DNS;
	rec->pid = 0; /* softirq: no meaningful current task (see the cgid
		       * note above). 0 = honestly unknown; the collector's
		       * DNS join window correlates the query to its flow
		       * (and thus pid) userspace-side — never fabricated
		       * here (P5's no-guessing rule). */
	rec->cgid = cgid;
	rec->ts_mono = bpf_ktime_get_ns();
	rec->ts_wall = bpf_ktime_get_boot_ns();
	rec->ttl = 0;
	rec->answer_count = 0;
	rec->answers_truncated = 0;
	__builtin_memset(rec->qname, 0, sizeof(rec->qname));
	__builtin_memset(rec->answers, 0, sizeof(rec->answers));

	int qlen = rana_parse_qname(&cur, rec->qname, sizeof(rec->qname));
	if (qlen < 0) {
		bpf_ringbuf_discard(rec, 0);
		return 1;
	}
	rec->qname_len = (__u8)qlen;

	/* Skip qtype(2) + qclass(2) for the first question; additional
	 * questions beyond the first are not walked (qname already
	 * captured is the one that matters for attribution — a second
	 * question in the same query is vanishingly rare in practice). */
	cur.off += 4;

	/* Answer section (present only when this "egress" capture happens
	 * to observe a response — e.g. a local resolver relaying within
	 * the same session's cgroup). Bounded to 4 answers per
	 * RANA_CAP_DNS_ANSWERS; only A/AAAA rdata (the address itself) is
	 * ever copied, never any other rtype's rdata. */
	int n = 0;
	#pragma unroll
	for (int i = 0; i < RANA_CAP_DNS_ANSWERS; i++) {
		if (i >= ancount)
			break;

		/* name (compressed pointer, 2 bytes, in a well-formed
		 * response answer section) + type(2) + class(2) + ttl(4) +
		 * rdlength(2) */
		__u16 name_ptr;
		if (rana_read_u16(&cur, &name_ptr) < 0)
			break;
		__u16 rtype, rclass, rdlength;
		__u32 rttl;
		if (rana_read_u16(&cur, &rtype) < 0)
			break;
		if (rana_read_u16(&cur, &rclass) < 0)
			break;
		{
			__u16 ttl_hi, ttl_lo;
			if (rana_read_u16(&cur, &ttl_hi) < 0)
				break;
			if (rana_read_u16(&cur, &ttl_lo) < 0)
				break;
			rttl = ((__u32)ttl_hi << 16) | ttl_lo;
		}
		if (rana_read_u16(&cur, &rdlength) < 0)
			break;

		if (rtype == 1 && rdlength == 4) { /* A record */
			__u8 addr[4];
			if (bpf_skb_load_bytes(cur.skb, cur.off, addr, 4) < 0)
				goto done;
			cur.off += 4;
			rana_v4_mapped_dns(addr, rec->answers[n]);
			n++;
			rec->ttl = rttl;
		} else if (rtype == 28 && rdlength == 16) { /* AAAA record */
			if (bpf_skb_load_bytes(cur.skb, cur.off, rec->answers[n], 16) < 0)
				goto done;
			cur.off += 16;
			n++;
			rec->ttl = rttl;
		} else {
			/* Not an address record: skip rdlength bytes without
			 * ever copying them into the record (qname/answers
			 * only, per the file header scope wall). Bounds via
			 * skb->len — the cursor holds no packet pointers. */
			if (cur.off + (__u32)rdlength > skb->len)
				break;
			cur.off += rdlength;
		}
	}
done:
	rec->answer_count = (__u8)n;
	rec->answers_truncated = (ancount > RANA_CAP_DNS_ANSWERS) ? 1 : 0;

	bpf_ringbuf_submit(rec, 0);
	return 1;
}
