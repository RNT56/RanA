package alerts

import (
	"fmt"
	"net"
	"time"

	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// ---- new_domain ----

// newDomainRule fires the first time a session contacts a given qname or
// destination IP, tracked in an in-memory, per-session seen-set
// (CONTRACTS: "first-contact qname or IP per session store"). qname and IP
// are deliberately independent namespaces within a session: a DNS lookup
// for a domain and a later raw-IP connect to the address it resolved to
// are two different observable facts (RanA cannot always prove they are
// the same destination — DoH/DoT hides the qname entirely, plan §6.4) and
// each is independently the first time RanA has *seen this key*, so each
// gets exactly one alert the first time it appears and never again.
type newDomainRule struct {
	seen map[string]map[string]bool // session -> key -> true
}

func newNewDomainRule() *newDomainRule {
	return &newDomainRule{seen: make(map[string]map[string]bool)}
}

func (r *newDomainRule) check(ev schema.Event) (firing, bool) {
	// value is what gets carried into the synthesized alert.new_domain
	// event's qname field. For net.dns it is the already-redacted qname
	// straight from the triggering event's Data (P3: never re-derived from
	// a raw string — it is the same redact.Redacted value the kernel/svc
	// path already produced). For net.connect there is no string field to
	// reuse (daddr is raw address bytes, per schema.NewNetConnect); the
	// dotted-quad/hex rendering of a destination address is not free-text
	// captured data (it cannot contain a secret — it is a fixed-shape
	// numeric rendering of 16 address bytes), so it is safe to mark via
	// redact.Literal the same way schema.NewNetConnect itself marks
	// proto/family: those are also derived-not-freeform values, not
	// compile-time string constants in the strictest sense, but
	// structurally incapable of carrying a secret.
	var value redact.Redacted
	var key string

	// Egress-intelligence additive fields (local-only, zero network calls,
	// D24): computed here because they depend on which triggering event
	// shape fired the rule (net.dns vs net.connect) and, for net.connect,
	// on Data already produced upstream by internal/collector.Enricher
	// (the DNSCache join into Data["qname"] — enricher.go EnrichConnect).
	var netClass redact.Redacted // net.connect only; absent for net.dns
	var netClassSet bool
	var asn redact.Redacted
	dnsBypass := false // net.connect only: true iff no joined qname precursor
	dnsRebind := false // net.dns only: true iff any answer is non-public

	switch ev.Type {
	case schema.EventTypeNetDNS:
		qname, _ := ev.Data["qname"].(redact.Redacted)
		key = string(qname)
		value = qname
		dnsRebind = anyAnswerNonPublic(ev.Data["answers"])
	case schema.EventTypeNetConnect:
		daddr, _ := ev.Data["daddr"].([]byte)
		key = ipToDotted(daddr)
		value = redact.Literal(key)
		if ip := dottedToIP(key); ip != nil {
			class, asnLabel := classifyIP(ip)
			netClass, netClassSet = redact.Literal(class), true
			if asnLabel != "" {
				asn = redact.Literal(asnLabel)
			}
		}
		if _, joined := ev.Data["qname"]; !joined {
			dnsBypass = true
		}
	default:
		return firing{}, false
	}
	if key == "" {
		return firing{}, false
	}

	sessionSeen := r.seen[ev.Session]
	if sessionSeen == nil {
		sessionSeen = make(map[string]bool)
		r.seen[ev.Session] = sessionSeen
	}
	if sessionSeen[key] {
		return firing{}, false
	}
	sessionSeen[key] = true

	return firing{
		synth: func(session string, seg, idx, tsMono, tsWall uint64, pid uint32) schema.Event {
			alertEv := schema.NewAlertNewDomain(session, seg, idx, tsMono, tsWall, pid, value)
			if netClassSet {
				alertEv.Data["net_class"] = netClass
				if asn != "" {
					alertEv.Data["asn"] = asn
				}
			}
			alertEv.Data["dns_bypass"] = dnsBypass
			alertEv.Data["dns_rebind"] = dnsRebind
			return alertEv
		},
		title: "RanA: new destination",
		body:  fmt.Sprintf("first contact: %s", key),
	}, true
}

// dottedToIP parses a dotted-quad or colon-hex rendering produced by
// ipToDotted back into a net.IP for classification purposes. This is safe
// under P3: the string being parsed is not captured free-text, it is the
// same fixed-shape numeric address rendering ipToDotted already produced
// from raw address bytes (see ipToDotted's doc comment) — classification
// never touches raw captured strings.
func dottedToIP(s string) net.IP {
	if s == "" {
		return nil
	}
	return net.ParseIP(s)
}

// anyAnswerNonPublic reports whether any of a net.dns event's Data["answers"]
// ([]redact.Redacted, already passed through the redaction pipeline by
// internal/collector.Enricher) parses as an IP address classified as
// anything other than "public" — i.e. a DNS answer pointing at a private,
// loopback, link-local, or CGNAT address (a "dns_rebind" signal: a public
// domain name resolving somewhere it structurally should not). Answers that
// fail to parse as a plain IP (e.g. because the redaction pipeline masked
// them as entropy-shaped) are silently skipped — no fact is fabricated from
// a value RanA can no longer read.
func anyAnswerNonPublic(v any) bool {
	answers, ok := v.([]redact.Redacted)
	if !ok {
		return false
	}
	for _, a := range answers {
		ip := dottedToIP(string(a))
		if ip == nil {
			continue
		}
		if class, _ := classifyIP(ip); class != "public" {
			return true
		}
	}
	return false
}

// ---- coarse net classification + curated ASN-prefix table (D24: local
// only, zero network calls, embedded at build time) ----

// classifyIP returns a coarse net_class ("private", "loopback",
// "link_local", "cgnat", "public") for ip, plus a curated ASN/org label if
// ip falls within curatedASNPrefixes (empty string if no match — most
// public addresses have no entry; the table is intentionally small and is
// NOT a reputation service, just a handful of well-known, stable anchors
// useful for narrating a timeline, e.g. "this is Google DNS").
func classifyIP(ip net.IP) (class string, asn string) {
	if ip.IsLoopback() {
		return "loopback", ""
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return "link_local", ""
	}
	if isCGNAT(ip) {
		return "cgnat", ""
	}
	if ip.IsPrivate() {
		return "private", ""
	}
	for _, p := range curatedASNPrefixes {
		if p.network.Contains(ip) {
			return "public", p.label
		}
	}
	return "public", ""
}

// cgnatBlock is 100.64.0.0/10, RFC 6598 — carrier-grade NAT space. Go's
// net.IP.IsPrivate() (RFC 1918 + RFC 4193) does not classify this range, so
// RanA checks it explicitly: CGNAT addresses are not internet-routable but
// are also not classic "private" LAN space, and treating them as plain
// "public" would misrepresent an address the agent's own ISP assigned it
// behind, not one it reached out to on the open internet.
var cgnatBlock = func() *net.IPNet {
	_, n, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		panic(err) // unreachable: compile-time-constant, valid CIDR
	}
	return n
}()

func isCGNAT(ip net.IP) bool {
	return cgnatBlock.Contains(ip)
}

// asnPrefix is one curated, embedded (ip-prefix -> label) anchor. Values are
// hand-picked, well-known, stable network operators chosen for narrating a
// timeline ("first contact: 8.8.8.8 (Google Public DNS)") — this is
// explicitly NOT an IP-reputation or geolocation database, has no update
// mechanism, and never makes a network call to resolve or refresh (D24, plan
// §2 scope walls: RanA does no phone-home, no third-party lookups).
type asnPrefix struct {
	network *net.IPNet
	label   string
}

func mustPrefix(cidr, label string) asnPrefix {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err) // unreachable: cidr values below are compile-time constants
	}
	return asnPrefix{network: n, label: label}
}

// curatedASNPrefixes is intentionally tiny — a handful of well-known,
// long-lived anchor blocks, not a general ASN database. Order does not
// matter (ranges are disjoint by construction).
var curatedASNPrefixes = []asnPrefix{
	mustPrefix("8.8.8.0/24", "Google Public DNS"),
	mustPrefix("8.8.4.0/24", "Google Public DNS"),
	mustPrefix("1.1.1.0/24", "Cloudflare Public DNS"),
	mustPrefix("9.9.9.0/24", "Quad9 Public DNS"),
	mustPrefix("140.82.112.0/20", "GitHub"),
	mustPrefix("13.107.42.0/24", "Microsoft"),
	mustPrefix("172.217.0.0/16", "Google"),
	mustPrefix("142.250.0.0/15", "Google"),
	mustPrefix("104.16.0.0/13", "Cloudflare"),
	mustPrefix("151.101.0.0/16", "Fastly"),
}

// ipToDotted renders a 16-byte v4-mapped address as dotted-quad text, or
// colon-hex for a genuine v6 address. Empty/zero input yields "".
func ipToDotted(addr []byte) string {
	if len(addr) != 16 {
		return ""
	}
	isV4Mapped := true
	for i := 0; i < 10; i++ {
		if addr[i] != 0 {
			isV4Mapped = false
			break
		}
	}
	if isV4Mapped && addr[10] == 0xff && addr[11] == 0xff {
		if addr[12] == 0 && addr[13] == 0 && addr[14] == 0 && addr[15] == 0 {
			return ""
		}
		return fmt.Sprintf("%d.%d.%d.%d", addr[12], addr[13], addr[14], addr[15])
	}
	allZero := true
	for _, b := range addr {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		uint16(addr[0])<<8|uint16(addr[1]), uint16(addr[2])<<8|uint16(addr[3]),
		uint16(addr[4])<<8|uint16(addr[5]), uint16(addr[6])<<8|uint16(addr[7]),
		uint16(addr[8])<<8|uint16(addr[9]), uint16(addr[10])<<8|uint16(addr[11]),
		uint16(addr[12])<<8|uint16(addr[13]), uint16(addr[14])<<8|uint16(addr[15]))
}

// ---- sensitive_read ----

// sensitiveReadRule synthesizes alert.sensitive_read for every
// fs.sensitive_read event, passing the path and matched rule id straight
// through (CONTRACTS: "sensitive_read passthrough severity" — no
// suppression/dedup: every sensitive read is independently newsworthy).
type sensitiveReadRule struct{}

func newSensitiveReadRule() *sensitiveReadRule { return &sensitiveReadRule{} }

func (r *sensitiveReadRule) check(ev schema.Event) (firing, bool) {
	if ev.Type != schema.EventTypeFsSensitiveRead {
		return firing{}, false
	}
	path, _ := ev.Data["path"].(redact.Redacted)
	rule, _ := ev.Data["rule"].(redact.Redacted)

	return firing{
		synth: func(session string, seg, idx, tsMono, tsWall uint64, pid uint32) schema.Event {
			return schema.NewAlertSensitiveRead(session, seg, idx, tsMono, tsWall, pid, path, rule)
		},
		title: "RanA: sensitive file read",
		body:  fmt.Sprintf("%s matched rule %s", path, rule),
	}, true
}

// ---- escape passthroughs ----

// escapePassthroughRule handles alert.cgroup_escape and
// alert.escape_precursor events. These are already fully-formed alert.*
// events by the time Engine sees them post-persist (the escape detection
// itself happens upstream, in the session/collector layer that has direct
// access to the in-kernel session pid-map — plan §6.4, docs/ARCHITECTURE.md
// §4.2.3 — Engine has no independent way to detect an escape from the
// event stream alone). The rule's only job is the best-effort desktop
// notification; it MUST NOT synthesize a second alert event for a fact
// that is already the alert (CONTRACTS: rules "consuming schema events
// post-persist" — passthrough means route-and-notify, not re-emit).
type escapePassthroughRule struct{}

func newEscapePassthroughRule() *escapePassthroughRule { return &escapePassthroughRule{} }

func (r *escapePassthroughRule) check(ev schema.Event) (firing, bool) {
	switch ev.Type {
	case schema.EventTypeAlertCgroupEscape:
		pid, _ := ev.Data["pid"].(uint64)
		from, _ := ev.Data["from"].(redact.Redacted)
		to, _ := ev.Data["to"].(redact.Redacted)
		return firing{
			synth: nil,
			title: "RanA: cgroup escape",
			body:  fmt.Sprintf("pid %d moved %s -> %s", pid, from, to),
		}, true
	case schema.EventTypeAlertEscapePrecursor:
		precursor, _ := ev.Data["precursor"].(redact.Redacted)
		return firing{
			synth: nil,
			title: "RanA: escape precursor",
			body:  fmt.Sprintf("observed: %s", precursor),
		}, true
	default:
		return firing{}, false
	}
}

// ---- burst ----

// defaultBurstThreshold/defaultBurstWindow are the burst rule's defaults
// absent an explicit WithBurstThreshold Option. Chosen conservatively: 200
// sheddable-class events for one session within one second is well above
// ordinary interactive agent activity but well below what governor
// shedding (collector.Governor, 50k/s synthetic bursts) is built to
// survive — it is meant to catch a session gone very chatty, not to fire
// on ordinary bursts of file writes.
const (
	defaultBurstThreshold uint64        = 200
	defaultBurstWindow    time.Duration = time.Second
)

// burstClassOf maps an event type to the burst rule's accounting class, or
// "" if the type is exempt from burst alerting. Exemption mirrors
// collector.Governor's never-shed set (CONTRACTS §internal/collector: exec,
// connect, sensitive_read, session.*, gap never shed) plus the alert.* and
// gap families themselves and markers — bursting on the very events meant
// to carry loss/security signal, or on enrichment, would be self-defeating
// noise. Only the governor's sheddable classes are tracked: fork/exit, fs
// metadata, fs.write_open, flow_close/dns.
func burstClassOf(t schema.EventType) string {
	switch t {
	case schema.EventTypeProcFork, schema.EventTypeProcExit:
		return "fork_exit"
	case schema.EventTypeFsUnlink, schema.EventTypeFsRename, schema.EventTypeFsMkdir, schema.EventTypeFsChmod, schema.EventTypeFsTruncate:
		return "fs.meta"
	case schema.EventTypeFsWriteOpen:
		return "fs.write_open"
	case schema.EventTypeNetFlowClose, schema.EventTypeNetDNS:
		return "flow_dns"
	default:
		return ""
	}
}

// burstRule fires alert.burst when a session's rate of same-class events
// exceeds threshold within a sliding window (CONTRACTS: "burst (rate over
// threshold in window)"). The window is a true sliding window — a
// chronological deque per (session, class) that is evicted of anything
// older than window on every check, so the *count* the rule reasons about
// is always "events in the last `window`, right now."
//
// Firing is edge-triggered, not level-triggered: once fired, the rule
// arms a per-(session,class) cooldown and will not fire again for that
// class until the in-window count has dropped back below threshold at
// least once (i.e. the burst has genuinely subsided) — otherwise a
// sustained burst that stays above threshold for many events/seconds
// would emit one alert.burst per event, which is exactly the alert-fatigue
// this rule exists to prevent. A later, distinct threshold-crossing
// (after the count has dipped below threshold) re-arms and fires again.
type burstRule struct {
	threshold uint64
	window    time.Duration
	// times[session][class] is a chronological (oldest-first) slice of
	// event timestamps still inside the sliding window.
	times map[string]map[string][]time.Time
	// armed[session][class] is false while a fired burst has not yet
	// subsided below threshold (edge-trigger cooldown).
	armed map[string]map[string]bool
}

func newBurstRule(threshold uint64, window time.Duration) *burstRule {
	return &burstRule{
		threshold: threshold,
		window:    window,
		times:     make(map[string]map[string][]time.Time),
		armed:     make(map[string]map[string]bool),
	}
}

func (r *burstRule) check(ev schema.Event, now time.Time) (firing, bool) {
	class := burstClassOf(ev.Type)
	if class == "" {
		return firing{}, false
	}

	sessionTimes := r.times[ev.Session]
	if sessionTimes == nil {
		sessionTimes = make(map[string][]time.Time)
		r.times[ev.Session] = sessionTimes
	}
	sessionArmed := r.armed[ev.Session]
	if sessionArmed == nil {
		sessionArmed = make(map[string]bool)
		r.armed[ev.Session] = sessionArmed
	}
	// Default to armed (true) the first time a class is seen.
	if _, seen := sessionArmed[class]; !seen {
		sessionArmed[class] = true
	}

	cutoff := now.Add(-r.window)
	kept := sessionTimes[class][:0]
	for _, t := range sessionTimes[class] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	sessionTimes[class] = kept

	count := uint64(len(kept))
	if count < r.threshold {
		sessionArmed[class] = true // burst (if any) has subsided; re-arm
		return firing{}, false
	}
	if !sessionArmed[class] {
		return firing{}, false // still above threshold from a prior firing; cooldown
	}

	sessionArmed[class] = false // fired; require a dip below threshold before firing again

	classLiteral := redact.Literal(class) // program-defined enum label, not captured data
	windowNs := uint64(r.window.Nanoseconds())
	return firing{
		synth: func(session string, seg, idx, tsMono, tsWall uint64, pid uint32) schema.Event {
			return schema.NewAlertBurst(session, seg, idx, tsMono, tsWall, pid, classLiteral, count, windowNs)
		},
		title: "RanA: burst detected",
		body:  fmt.Sprintf("%d %s events within %s", count, class, r.window),
	}, true
}
