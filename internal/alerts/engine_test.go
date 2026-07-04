package alerts

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// fakeClock is a deterministic, manually-advanced Clock for tests (CONTRACTS
// testing bar: injectable clocks everywhere time matters, no real sleeps).
type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)}
}

// sink collects every schema.Event emitted by the Engine, in order.
type sink struct {
	events []schema.Event
	err    error // if set, returned from every Emit call (and the event is still recorded)
}

func (s *sink) Emit(ev schema.Event) error {
	s.events = append(s.events, ev)
	return s.err
}

func testPipeline(t *testing.T) *redact.Pipeline {
	t.Helper()
	p, err := redact.NewPipeline([]byte("test-salt-0123456789"))
	if err != nil {
		t.Fatalf("redact.NewPipeline: %v", err)
	}
	return p
}

func v4mapped(a, b, c, d byte) []byte {
	addr := make([]byte, 16)
	addr[10] = 0xff
	addr[11] = 0xff
	addr[12], addr[13], addr[14], addr[15] = a, b, c, d
	return addr
}

func mustParseV4Mapped(t *testing.T, s string) []byte {
	t.Helper()
	ip4 := net.ParseIP(s).To4()
	if ip4 == nil {
		t.Fatalf("not a v4 address: %q", s)
	}
	return v4mapped(ip4[0], ip4[1], ip4[2], ip4[3])
}

func newTestEngine(t *testing.T, clk Clock, sk *sink, notifier Notifier, opts ...Option) *Engine {
	t.Helper()
	eng, err := NewEngine(Config{
		Clock:    clk,
		Sink:     sk.Emit,
		Notifier: notifier,
	}, opts...)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

func dnsEvent(session string, seg, idx uint64, pid uint32, qname string) schema.Event {
	return schema.NewNetDNS(session, seg, idx, 1, 1, pid, redact.Literal(qname), nil, 300)
}

func connectEvent(session string, seg, idx uint64, pid uint32, daddr []byte) schema.Event {
	return schema.NewNetConnect(session, seg, idx, 1, 1, pid, "tcp", daddr, 443, "AF_INET")
}

// connectEventWithQname builds a net.connect event that carries a joined
// Data["qname"] field, mirroring what internal/collector.Enricher produces
// when its DNSCache.Join succeeds for daddr within the join window (see
// enricher.go EnrichConnect). Its absence (plain connectEvent) is what
// dns_bypass detection keys off: a connect with no preceding, joinable DNS
// answer for that address.
func connectEventWithQname(session string, seg, idx uint64, pid uint32, daddr []byte, qname string) schema.Event {
	ev := connectEvent(session, seg, idx, pid, daddr)
	ev.Data["qname"] = redact.Literal(qname)
	return ev
}

func dnsEventWithAnswers(session string, seg, idx uint64, pid uint32, qname string, answers ...string) schema.Event {
	red := make([]redact.Redacted, 0, len(answers))
	for _, a := range answers {
		red = append(red, redact.Literal(a))
	}
	return schema.NewNetDNS(session, seg, idx, 1, 1, pid, redact.Literal(qname), red, 300)
}

func sensitiveReadEvent(session string, seg, idx uint64, pid uint32, path, rule string) schema.Event {
	return schema.NewFsSensitiveRead(session, seg, idx, 1, 1, pid, redact.Literal(path), redact.Literal(rule))
}

// ---- new_domain ----

func TestNewDomainRule_FirstContactQnameFires(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	ev := dnsEvent("sess-1", 0, 0, 100, "api.example.com")
	if err := eng.Observe(ev, 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	if len(alerts) != 1 {
		t.Fatalf("got %d alert.new_domain events, want 1: %+v", len(alerts), sk.events)
	}
	qname, ok := alerts[0].Data["qname"].(redact.Redacted)
	if !ok || string(qname) != "api.example.com" {
		t.Errorf("alert qname = %v, want api.example.com", alerts[0].Data["qname"])
	}
	if len(fn.Calls) != 1 {
		t.Errorf("notifier calls = %d, want 1", len(fn.Calls))
	}
}

func TestNewDomainRule_RepeatQnameDoesNotFireAgain(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	for i := 0; i < 3; i++ {
		ev := dnsEvent("sess-1", 0, uint64(i), 100, "api.example.com")
		if err := eng.Observe(ev, 0); err != nil {
			t.Fatalf("Observe[%d]: %v", i, err)
		}
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	if len(alerts) != 1 {
		t.Fatalf("got %d alert.new_domain events across 3 identical DNS lookups, want exactly 1", len(alerts))
	}
	if len(fn.Calls) != 1 {
		t.Errorf("notifier calls = %d, want 1 (no repeat notification)", len(fn.Calls))
	}
}

func TestNewDomainRule_DifferentSessionsIndependentSeenSets(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	if err := eng.Observe(dnsEvent("sess-A", 0, 0, 1, "api.example.com"), 0); err != nil {
		t.Fatalf("Observe A: %v", err)
	}
	if err := eng.Observe(dnsEvent("sess-B", 0, 0, 1, "api.example.com"), 0); err != nil {
		t.Fatalf("Observe B: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	if len(alerts) != 2 {
		t.Fatalf("got %d alert.new_domain events, want 2 (one per session, independent seen-sets)", len(alerts))
	}
}

func TestNewDomainRule_NewIPAfterKnownQnameStillFiresOnce(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	daddr := mustParseV4Mapped(t, "93.184.216.34")

	if err := eng.Observe(connectEvent("sess-1", 0, 0, 1, daddr), 0); err != nil {
		t.Fatalf("Observe connect: %v", err)
	}
	// Same IP again — must not re-fire.
	if err := eng.Observe(connectEvent("sess-1", 0, 1, 1, daddr), 0); err != nil {
		t.Fatalf("Observe connect repeat: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	if len(alerts) != 1 {
		t.Fatalf("got %d alert.new_domain events for repeated IP contact, want 1", len(alerts))
	}
	daddrGot, ok := alerts[0].Data["qname"].(redact.Redacted)
	if !ok {
		t.Fatalf("alert.new_domain qname field missing or wrong type: %+v", alerts[0].Data)
	}
	if string(daddrGot) != "93.184.216.34" {
		t.Errorf("alert qname = %q, want dotted-quad IP %q", daddrGot, "93.184.216.34")
	}
}

func TestNewDomainRule_QnameThenItsIPDoesNotDoubleFire(t *testing.T) {
	// A DNS lookup for a domain followed by a connect to the IP it resolved
	// to should still only be one novel "domain" contact from the alerting
	// point of view of qname-vs-IP tracking being independent namespaces is
	// acceptable, but repeats within the SAME namespace must never re-fire.
	// This test locks in that qname and IP are tracked as separate keys
	// (each fires once), not that they're unified — see engine.go doc
	// comment for the documented rationale.
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	if err := eng.Observe(dnsEvent("sess-1", 0, 0, 1, "example.com"), 0); err != nil {
		t.Fatalf("Observe dns: %v", err)
	}
	if err := eng.Observe(dnsEvent("sess-1", 0, 1, 1, "example.com"), 0); err != nil {
		t.Fatalf("Observe dns repeat: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	if len(alerts) != 1 {
		t.Fatalf("got %d alert.new_domain, want 1 for repeated identical qname", len(alerts))
	}
}

func TestNewDomainRule_EmptyQnameIgnored(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	ev := dnsEvent("sess-1", 0, 0, 1, "")
	if err := eng.Observe(ev, 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	if len(alerts) != 0 {
		t.Errorf("got %d alert.new_domain for empty qname, want 0", len(alerts))
	}
}

// ---- egress intelligence: net_class ----

func TestNewDomainRule_NetClassPrivate(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	daddr := mustParseV4Mapped(t, "10.1.2.3")
	if err := eng.Observe(connectEvent("sess-1", 0, 0, 1, daddr), 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	if len(alerts) != 1 {
		t.Fatalf("got %d alert.new_domain events, want 1", len(alerts))
	}
	class, _ := alerts[0].Data["net_class"].(redact.Redacted)
	if string(class) != "private" {
		t.Errorf("net_class = %q, want %q", class, "private")
	}
}

func TestNewDomainRule_NetClassLoopback(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	daddr := mustParseV4Mapped(t, "127.0.0.1")
	if err := eng.Observe(connectEvent("sess-1", 0, 0, 1, daddr), 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	class, _ := alerts[0].Data["net_class"].(redact.Redacted)
	if string(class) != "loopback" {
		t.Errorf("net_class = %q, want %q", class, "loopback")
	}
}

func TestNewDomainRule_NetClassLinkLocal(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	daddr := mustParseV4Mapped(t, "169.254.1.1")
	if err := eng.Observe(connectEvent("sess-1", 0, 0, 1, daddr), 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	class, _ := alerts[0].Data["net_class"].(redact.Redacted)
	if string(class) != "link_local" {
		t.Errorf("net_class = %q, want %q", class, "link_local")
	}
}

func TestNewDomainRule_NetClassCGNAT(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	daddr := mustParseV4Mapped(t, "100.64.5.5")
	if err := eng.Observe(connectEvent("sess-1", 0, 0, 1, daddr), 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	class, _ := alerts[0].Data["net_class"].(redact.Redacted)
	if string(class) != "cgnat" {
		t.Errorf("net_class = %q, want %q", class, "cgnat")
	}
}

func TestNewDomainRule_NetClassPublic(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	daddr := mustParseV4Mapped(t, "93.184.216.34")
	if err := eng.Observe(connectEvent("sess-1", 0, 0, 1, daddr), 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	class, _ := alerts[0].Data["net_class"].(redact.Redacted)
	if string(class) != "public" {
		t.Errorf("net_class = %q, want %q", class, "public")
	}
}

func TestNewDomainRule_NetClassKnownASNPrefix(t *testing.T) {
	// Locks in that a curated, embedded ASN-prefix hit annotates an "asn"
	// field in addition to net_class=public — no network lookup, purely a
	// small embedded table match (D24: zero network calls).
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	daddr := mustParseV4Mapped(t, "8.8.8.8") // curated table entry: Google DNS
	if err := eng.Observe(connectEvent("sess-1", 0, 0, 1, daddr), 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	class, _ := alerts[0].Data["net_class"].(redact.Redacted)
	if string(class) != "public" {
		t.Errorf("net_class = %q, want %q", class, "public")
	}
	asn, ok := alerts[0].Data["asn"].(redact.Redacted)
	if !ok || asn == "" {
		t.Errorf("asn = %q, want a non-empty curated-table label for 8.8.8.8", asn)
	}
}

func TestNewDomainRule_NetClassAppliesToDNSTriggeredAlertsToo(t *testing.T) {
	// net_class is computed on whatever address information the triggering
	// event carries; for a net.dns first-contact, that's the qname itself
	// (not an address) so net_class must not be fabricated — it is only
	// meaningful for IP-addressed contacts (net.connect). This locks in that
	// a qname-triggered new_domain does NOT carry a net_class field.
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	if err := eng.Observe(dnsEvent("sess-1", 0, 0, 1, "example.com"), 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	if _, ok := alerts[0].Data["net_class"]; ok {
		t.Errorf("qname-triggered alert.new_domain carries net_class = %v, want absent (no address to classify)", alerts[0].Data["net_class"])
	}
}

// ---- egress intelligence: dns_bypass ----

func TestNewDomainRule_DNSBypassTrueWhenNoPrecedingDNS(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	daddr := mustParseV4Mapped(t, "93.184.216.34")
	if err := eng.Observe(connectEvent("sess-1", 0, 0, 1, daddr), 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	bypass, _ := alerts[0].Data["dns_bypass"].(bool)
	if !bypass {
		t.Errorf("dns_bypass = %v, want true (connect with no joined qname)", bypass)
	}
}

func TestNewDomainRule_DNSBypassFalseWhenQnameJoined(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	daddr := mustParseV4Mapped(t, "93.184.216.34")
	ev := connectEventWithQname("sess-1", 0, 0, 1, daddr, "example.com")
	if err := eng.Observe(ev, 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	bypass, _ := alerts[0].Data["dns_bypass"].(bool)
	if bypass {
		t.Errorf("dns_bypass = %v, want false (connect carried a joined qname)", bypass)
	}
}

func TestNewDomainRule_DNSBypassAbsentForQnameTrigger(t *testing.T) {
	// dns_bypass is a property of an address-only contact lacking a DNS
	// precursor; a net.dns-triggered new_domain IS the DNS lookup, so
	// dns_bypass is meaningless there and must be false, not fabricated.
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	if err := eng.Observe(dnsEvent("sess-1", 0, 0, 1, "example.com"), 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	bypass, _ := alerts[0].Data["dns_bypass"].(bool)
	if bypass {
		t.Errorf("dns_bypass = %v, want false for a net.dns-triggered alert", bypass)
	}
}

// ---- egress intelligence: dns_rebind ----

func TestNewDomainRule_DNSRebindTrueWhenAnswerIsPrivate(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	ev := dnsEventWithAnswers("sess-1", 0, 0, 1, "evil.example.com", "10.0.0.5")
	if err := eng.Observe(ev, 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	rebind, _ := alerts[0].Data["dns_rebind"].(bool)
	if !rebind {
		t.Errorf("dns_rebind = %v, want true (answer resolves to a private address)", rebind)
	}
}

func TestNewDomainRule_DNSRebindTrueWhenAnswerIsLoopback(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	ev := dnsEventWithAnswers("sess-1", 0, 0, 1, "evil.example.com", "127.0.0.1")
	if err := eng.Observe(ev, 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	rebind, _ := alerts[0].Data["dns_rebind"].(bool)
	if !rebind {
		t.Errorf("dns_rebind = %v, want true (answer resolves to loopback)", rebind)
	}
}

func TestNewDomainRule_DNSRebindFalseWhenAllAnswersPublic(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	ev := dnsEventWithAnswers("sess-1", 0, 0, 1, "example.com", "93.184.216.34", "93.184.216.35")
	if err := eng.Observe(ev, 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	rebind, _ := alerts[0].Data["dns_rebind"].(bool)
	if rebind {
		t.Errorf("dns_rebind = %v, want false (all answers public)", rebind)
	}
}

func TestNewDomainRule_DNSRebindAbsentForConnectTrigger(t *testing.T) {
	// dns_rebind is a property of a DNS answer set; a net.connect-triggered
	// new_domain carries no answer set to evaluate, so dns_rebind must be
	// false, not fabricated.
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	daddr := mustParseV4Mapped(t, "93.184.216.34")
	if err := eng.Observe(connectEvent("sess-1", 0, 0, 1, daddr), 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	rebind, _ := alerts[0].Data["dns_rebind"].(bool)
	if rebind {
		t.Errorf("dns_rebind = %v, want false for a net.connect-triggered alert", rebind)
	}
}

// ---- sensitive_read passthrough ----

func TestSensitiveReadRule_Passthrough(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	ev := sensitiveReadEvent("sess-1", 0, 0, 42, "/home/user/.ssh/id_ed25519", "ssh-key")
	if err := eng.Observe(ev, 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertSensitiveRead)
	if len(alerts) != 1 {
		t.Fatalf("got %d alert.sensitive_read events, want 1", len(alerts))
	}
	got := alerts[0]
	if got.Session != "sess-1" || got.Pid != 42 {
		t.Errorf("alert envelope = %+v, want session=sess-1 pid=42", got)
	}
	path, _ := got.Data["path"].(redact.Redacted)
	rule, _ := got.Data["rule"].(redact.Redacted)
	if string(path) != "/home/user/.ssh/id_ed25519" || string(rule) != "ssh-key" {
		t.Errorf("alert data = %+v, want path/rule passed through unchanged", got.Data)
	}
	if len(fn.Calls) != 1 {
		t.Errorf("notifier calls = %d, want 1", len(fn.Calls))
	}
}

func TestSensitiveReadRule_FiresEveryTime(t *testing.T) {
	// Unlike new_domain, every sensitive read is independently alertable —
	// there is no seen-set suppression (CONTRACTS: "sensitive_read
	// passthrough severity" — no dedup semantics specified, and reading the
	// same sensitive file twice is independently newsworthy).
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	for i := 0; i < 2; i++ {
		ev := sensitiveReadEvent("sess-1", 0, uint64(i), 42, "/home/user/.ssh/id_ed25519", "ssh-key")
		if err := eng.Observe(ev, 0); err != nil {
			t.Fatalf("Observe[%d]: %v", i, err)
		}
	}
	alerts := filterType(sk.events, schema.EventTypeAlertSensitiveRead)
	if len(alerts) != 2 {
		t.Fatalf("got %d alert.sensitive_read events for 2 reads, want 2", len(alerts))
	}
}

// ---- escape passthroughs ----

func TestCgroupEscapeRule_Passthrough(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	ev := schema.NewAlertCgroupEscape("sess-1", 0, 0, 1, 1, 7, 999, redact.Literal("rana.slice/sess-1"), redact.Literal("other.slice"))
	if err := eng.Observe(ev, 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// Passthrough: the rule must NOT synthesize a second alert.cgroup_escape
	// event (the fact was already fully formed upstream) — it only
	// notifies.
	alerts := filterType(sk.events, schema.EventTypeAlertCgroupEscape)
	if len(alerts) != 0 {
		t.Fatalf("got %d synthesized alert.cgroup_escape events, want 0 (passthrough must not double-emit)", len(alerts))
	}
	if len(fn.Calls) != 1 {
		t.Fatalf("notifier calls = %d, want 1", len(fn.Calls))
	}
}

func TestEscapePrecursorRule_Passthrough(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	ev := schema.NewAlertEscapePrecursor("sess-1", 0, 0, 1, 1, 7, redact.Literal("systemd-run"))
	if err := eng.Observe(ev, 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertEscapePrecursor)
	if len(alerts) != 0 {
		t.Fatalf("got %d synthesized alert.escape_precursor events, want 0 (passthrough must not double-emit)", len(alerts))
	}
	if len(fn.Calls) != 1 {
		t.Fatalf("notifier calls = %d, want 1", len(fn.Calls))
	}
}

// ---- burst ----

func TestBurstRule_FiresOnceThresholdCrossedWithinWindow(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithBurstThreshold(3, time.Second))

	// 3 fs.write_open events in quick succession (same class) should cross
	// a threshold of 3 within a 1s window on the 3rd event.
	for i := 0; i < 3; i++ {
		ev := schema.NewFsWriteOpen("sess-1", 0, uint64(i), 1, 1, 1, redact.Literal("/tmp/x"), schema.PathSourceResolved, 0, 0)
		if err := eng.Observe(ev, 0); err != nil {
			t.Fatalf("Observe[%d]: %v", i, err)
		}
		clk.Advance(10 * time.Millisecond)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertBurst)
	if len(alerts) != 1 {
		t.Fatalf("got %d alert.burst events, want exactly 1 on threshold crossing", len(alerts))
	}
	count, _ := alerts[0].Data["count"].(uint64)
	if count != 3 {
		t.Errorf("alert.burst count = %d, want 3", count)
	}
}

func TestBurstRule_DoesNotFireBelowThreshold(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithBurstThreshold(5, time.Second))

	for i := 0; i < 3; i++ {
		ev := schema.NewFsWriteOpen("sess-1", 0, uint64(i), 1, 1, 1, redact.Literal("/tmp/x"), schema.PathSourceResolved, 0, 0)
		if err := eng.Observe(ev, 0); err != nil {
			t.Fatalf("Observe[%d]: %v", i, err)
		}
		clk.Advance(10 * time.Millisecond)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertBurst)
	if len(alerts) != 0 {
		t.Fatalf("got %d alert.burst events below threshold, want 0", len(alerts))
	}
}

func TestBurstRule_SlidingWindowExpiresOldEvents(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithBurstThreshold(3, time.Second))

	// 2 events, then advance past the window, then 2 more: the window
	// should have forgotten the first 2, so we never cross 3 in-window.
	for i := 0; i < 2; i++ {
		ev := schema.NewFsWriteOpen("sess-1", 0, uint64(i), 1, 1, 1, redact.Literal("/tmp/x"), schema.PathSourceResolved, 0, 0)
		if err := eng.Observe(ev, 0); err != nil {
			t.Fatalf("Observe[%d]: %v", i, err)
		}
	}
	clk.Advance(2 * time.Second) // window is 1s; this fully expires the first 2
	for i := 2; i < 4; i++ {
		ev := schema.NewFsWriteOpen("sess-1", 0, uint64(i), 1, 1, 1, redact.Literal("/tmp/x"), schema.PathSourceResolved, 0, 0)
		if err := eng.Observe(ev, 0); err != nil {
			t.Fatalf("Observe[%d]: %v", i, err)
		}
	}

	alerts := filterType(sk.events, schema.EventTypeAlertBurst)
	if len(alerts) != 0 {
		t.Fatalf("got %d alert.burst events, want 0 (sliding window should have expired the earlier events)", len(alerts))
	}
}

func TestBurstRule_FiresAgainAfterWindowRefillsPastThreshold(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithBurstThreshold(3, time.Second))

	fire := func(n int) {
		for i := 0; i < n; i++ {
			ev := schema.NewFsWriteOpen("sess-1", 0, uint64(len(sk.events)+i), 1, 1, 1, redact.Literal("/tmp/x"), schema.PathSourceResolved, 0, 0)
			if err := eng.Observe(ev, 0); err != nil {
				t.Fatalf("Observe: %v", err)
			}
			clk.Advance(10 * time.Millisecond)
		}
	}

	fire(3) // crosses threshold once
	clk.Advance(2 * time.Second)
	fire(3) // window fully reset, crosses threshold again

	alerts := filterType(sk.events, schema.EventTypeAlertBurst)
	if len(alerts) != 2 {
		t.Fatalf("got %d alert.burst events across two separate bursts, want 2", len(alerts))
	}
}

func TestBurstRule_DoesNotReFireEveryEventOnceOverThreshold(t *testing.T) {
	// Once a burst has been reported for a class/session, continuing to
	// exceed threshold within the SAME still-active window must not spam
	// one alert per additional event.
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithBurstThreshold(3, time.Second))

	for i := 0; i < 6; i++ {
		ev := schema.NewFsWriteOpen("sess-1", 0, uint64(i), 1, 1, 1, redact.Literal("/tmp/x"), schema.PathSourceResolved, 0, 0)
		if err := eng.Observe(ev, 0); err != nil {
			t.Fatalf("Observe[%d]: %v", i, err)
		}
		clk.Advance(10 * time.Millisecond)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertBurst)
	if len(alerts) != 1 {
		t.Fatalf("got %d alert.burst events for a single sustained burst, want 1", len(alerts))
	}
}

func TestBurstRule_NeverShedClassesExemptFromBurstAlerting(t *testing.T) {
	// proc.exec, net.connect, fs.sensitive_read, session.*, gap are the
	// governor's never-shed classes (collector.Governor); burst-alerting on
	// them would be noise on legitimate high-throughput sessions. The rule
	// only tracks sheddable classes (fork/exit, fs metadata, fs.write_open,
	// flow_close/dns) — this locks that scope in.
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithBurstThreshold(2, time.Second))

	for i := 0; i < 5; i++ {
		ev := connectEvent("sess-1", 0, uint64(i), 1, mustParseV4Mapped(t, "1.2.3.4"))
		if err := eng.Observe(ev, 0); err != nil {
			t.Fatalf("Observe[%d]: %v", i, err)
		}
		clk.Advance(10 * time.Millisecond)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertBurst)
	if len(alerts) != 0 {
		t.Fatalf("got %d alert.burst events for net.connect traffic, want 0 (never-shed classes are exempt)", len(alerts))
	}
}

func TestBurstRule_PerSessionIndependentWindows(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithBurstThreshold(3, time.Second))

	for i := 0; i < 2; i++ {
		ev := schema.NewFsWriteOpen("sess-A", 0, uint64(i), 1, 1, 1, redact.Literal("/tmp/x"), schema.PathSourceResolved, 0, 0)
		if err := eng.Observe(ev, 0); err != nil {
			t.Fatalf("Observe A[%d]: %v", i, err)
		}
	}
	for i := 0; i < 2; i++ {
		ev := schema.NewFsWriteOpen("sess-B", 0, uint64(i), 1, 1, 1, redact.Literal("/tmp/x"), schema.PathSourceResolved, 0, 0)
		if err := eng.Observe(ev, 0); err != nil {
			t.Fatalf("Observe B[%d]: %v", i, err)
		}
	}

	alerts := filterType(sk.events, schema.EventTypeAlertBurst)
	if len(alerts) != 0 {
		t.Fatalf("got %d alert.burst events, want 0 (2+2 across independent sessions never crosses per-session threshold 3)", len(alerts))
	}
}

// ---- well-formedness of synthesized events ----

func TestSynthesizedAlerts_AreWellFormedSchemaEvents(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithBurstThreshold(1, time.Second))

	triggers := []schema.Event{
		dnsEvent("sess-1", 3, 0, 55, "novel.example.com"),
		sensitiveReadEvent("sess-1", 3, 1, 55, "/etc/shadow", "passwd-file"),
		schema.NewFsWriteOpen("sess-1", 3, 2, 1, 1, 55, redact.Literal("/tmp/x"), schema.PathSourceResolved, 0, 0),
	}
	for i, trig := range triggers {
		if err := eng.Observe(trig, 3); err != nil {
			t.Fatalf("Observe[%d]: %v", i, err)
		}
	}

	if len(sk.events) == 0 {
		t.Fatalf("expected synthesized alert events, got none")
	}
	for _, ev := range sk.events {
		if err := schema.Validate(ev); err != nil {
			t.Errorf("synthesized event failed schema.Validate: %v (event: %+v)", err, ev)
		}
		if ev.V != 1 {
			t.Errorf("event.V = %d, want 1", ev.V)
		}
		if ev.Session != "sess-1" {
			t.Errorf("event.Session = %q, want sess-1", ev.Session)
		}
		if ev.Seg != 3 {
			t.Errorf("event.Seg = %d, want 3 (passed through from Observe)", ev.Seg)
		}
		if ev.Origin != schema.OriginSVC {
			t.Errorf("event.Origin = %q, want svc (alert.* is svc-emitted)", ev.Origin)
		}
		if ev.State != schema.StateObserved {
			t.Errorf("event.State = %q, want observed", ev.State)
		}
	}
}

func TestSynthesizedAlerts_MonotonicIdxPerSession(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	if err := eng.Observe(dnsEvent("sess-1", 0, 0, 1, "a.example.com"), 0); err != nil {
		t.Fatalf("Observe 1: %v", err)
	}
	if err := eng.Observe(dnsEvent("sess-1", 0, 1, 1, "b.example.com"), 0); err != nil {
		t.Fatalf("Observe 2: %v", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	if len(alerts) != 2 {
		t.Fatalf("got %d alert.new_domain events, want 2", len(alerts))
	}
	if alerts[0].Idx >= alerts[1].Idx {
		t.Errorf("Idx not monotonically increasing: %d then %d", alerts[0].Idx, alerts[1].Idx)
	}
}

// ---- Notifier failure isolation ----

func TestEngine_NotifierErrorDoesNotBlockPipeline(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{Err: errors.New("notification daemon unreachable")}
	eng := newTestEngine(t, clk, sk, fn)

	ev := dnsEvent("sess-1", 0, 0, 1, "example.com")
	if err := eng.Observe(ev, 0); err != nil {
		t.Fatalf("Observe returned error from a failed (best-effort) notification: %v — notifier failures must never propagate", err)
	}

	alerts := filterType(sk.events, schema.EventTypeAlertNewDomain)
	if len(alerts) != 1 {
		t.Fatalf("got %d alert.new_domain events despite notifier failure, want 1 (sink emission must proceed)", len(alerts))
	}
}

func TestEngine_SinkErrorPropagates(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{err: errors.New("ledger write failed")}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	ev := dnsEvent("sess-1", 0, 0, 1, "example.com")
	if err := eng.Observe(ev, 0); err == nil {
		t.Fatalf("Observe returned nil error though the sink failed; sink errors must propagate to the caller")
	}
}

func TestEngine_NilNotifierIsSafe(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	eng, err := NewEngine(Config{Clock: clk, Sink: sk.Emit})
	if err != nil {
		t.Fatalf("NewEngine with nil Notifier: %v", err)
	}
	ev := dnsEvent("sess-1", 0, 0, 1, "example.com")
	if err := eng.Observe(ev, 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}
}

func TestNewEngine_RequiresClockAndSink(t *testing.T) {
	if _, err := NewEngine(Config{Sink: func(schema.Event) error { return nil }}); err == nil {
		t.Error("NewEngine with nil Clock should error")
	}
	if _, err := NewEngine(Config{Clock: newFakeClock()}); err == nil {
		t.Error("NewEngine with nil Sink should error")
	}
}

// ---- irrelevant events are ignored ----

func TestEngine_IgnoresEventsNoRuleCaresAbout(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn)

	ev := schema.NewProcFork("sess-1", 0, 0, 1, 1, 100, 1)
	if err := eng.Observe(ev, 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if len(sk.events) != 0 {
		t.Errorf("got %d emitted events for a proc.fork with no matching rule, want 0", len(sk.events))
	}
	if len(fn.Calls) != 0 {
		t.Errorf("got %d notifications for a proc.fork with no matching rule, want 0", len(fn.Calls))
	}
}

// ---- sensitive-read trifecta correlation (D9 "trifecta precursor") ----

func TestTrifecta_SensitiveReadThenNewDomainWithinWindowEscalates(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithTrifectaWindow(30*time.Second))

	if err := eng.Observe(sensitiveReadEvent("sess-1", 0, 0, 42, "/home/user/.ssh/id_ed25519", "ssh-key"), 0); err != nil {
		t.Fatalf("Observe sensitive_read: %v", err)
	}
	clk.Advance(5 * time.Second)
	daddr := mustParseV4Mapped(t, "93.184.216.34")
	if err := eng.Observe(connectEvent("sess-1", 0, 1, 42, daddr), 0); err != nil {
		t.Fatalf("Observe new_domain trigger: %v", err)
	}

	reads := filterType(sk.events, schema.EventTypeAlertSensitiveRead)
	if len(reads) != 2 {
		t.Fatalf("got %d alert.sensitive_read events, want 2 (original passthrough + escalated correlation)", len(reads))
	}
	// The first is the original, unescalated passthrough.
	if _, ok := reads[0].Data["exfil_precursor"]; ok {
		t.Errorf("original alert.sensitive_read carries exfil_precursor = %v, want absent (append-only: original must be untouched)", reads[0].Data["exfil_precursor"])
	}
	// The second is the escalated correlation event.
	escalated := reads[1]
	precursor, _ := escalated.Data["exfil_precursor"].(bool)
	if !precursor {
		t.Fatalf("escalated alert.sensitive_read exfil_precursor = %v, want true", precursor)
	}
	sev, _ := escalated.Data["severity"].(redact.Redacted)
	if string(sev) != "high" {
		t.Errorf("escalated severity = %q, want %q", sev, "high")
	}
	host, ok := escalated.Data["correlated_host"].(redact.Redacted)
	if !ok || string(host) != "93.184.216.34" {
		t.Errorf("escalated correlated_host = %v, want %q", escalated.Data["correlated_host"], "93.184.216.34")
	}
	path, _ := escalated.Data["path"].(redact.Redacted)
	if string(path) != "/home/user/.ssh/id_ed25519" {
		t.Errorf("escalated path = %q, want original sensitive path preserved", path)
	}
}

func TestTrifecta_NewDomainThenSensitiveReadWithinWindowEscalates(t *testing.T) {
	// Order must not matter: new_domain first, sensitive_read second, still
	// within the window, must still escalate (D9: "either order").
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithTrifectaWindow(30*time.Second))

	daddr := mustParseV4Mapped(t, "93.184.216.34")
	if err := eng.Observe(connectEvent("sess-1", 0, 0, 42, daddr), 0); err != nil {
		t.Fatalf("Observe new_domain trigger: %v", err)
	}
	clk.Advance(5 * time.Second)
	if err := eng.Observe(sensitiveReadEvent("sess-1", 0, 1, 42, "/home/user/.ssh/id_ed25519", "ssh-key"), 0); err != nil {
		t.Fatalf("Observe sensitive_read: %v", err)
	}

	reads := filterType(sk.events, schema.EventTypeAlertSensitiveRead)
	if len(reads) != 2 {
		t.Fatalf("got %d alert.sensitive_read events, want 2 (original passthrough + escalated correlation)", len(reads))
	}
	escalated := reads[1]
	precursor, _ := escalated.Data["exfil_precursor"].(bool)
	if !precursor {
		t.Fatalf("escalated alert.sensitive_read exfil_precursor = %v, want true (new_domain-then-sensitive_read order)", precursor)
	}
	host, _ := escalated.Data["correlated_host"].(redact.Redacted)
	if string(host) != "93.184.216.34" {
		t.Errorf("escalated correlated_host = %q, want %q", host, "93.184.216.34")
	}
}

func TestTrifecta_OutsideWindowDoesNotEscalate(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithTrifectaWindow(30*time.Second))

	if err := eng.Observe(sensitiveReadEvent("sess-1", 0, 0, 42, "/home/user/.ssh/id_ed25519", "ssh-key"), 0); err != nil {
		t.Fatalf("Observe sensitive_read: %v", err)
	}
	clk.Advance(31 * time.Second) // just past the window
	daddr := mustParseV4Mapped(t, "93.184.216.34")
	if err := eng.Observe(connectEvent("sess-1", 0, 1, 42, daddr), 0); err != nil {
		t.Fatalf("Observe new_domain trigger: %v", err)
	}

	reads := filterType(sk.events, schema.EventTypeAlertSensitiveRead)
	if len(reads) != 1 {
		t.Fatalf("got %d alert.sensitive_read events, want 1 (no escalation outside the window)", len(reads))
	}
}

func TestTrifecta_ExactlyAtWindowBoundaryEscalates(t *testing.T) {
	// Boundary semantics: "within window" is inclusive of the exact edge.
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithTrifectaWindow(30*time.Second))

	if err := eng.Observe(sensitiveReadEvent("sess-1", 0, 0, 42, "/home/user/.ssh/id_ed25519", "ssh-key"), 0); err != nil {
		t.Fatalf("Observe sensitive_read: %v", err)
	}
	clk.Advance(30 * time.Second) // exactly at the window edge
	daddr := mustParseV4Mapped(t, "93.184.216.34")
	if err := eng.Observe(connectEvent("sess-1", 0, 1, 42, daddr), 0); err != nil {
		t.Fatalf("Observe new_domain trigger: %v", err)
	}

	reads := filterType(sk.events, schema.EventTypeAlertSensitiveRead)
	if len(reads) != 2 {
		t.Fatalf("got %d alert.sensitive_read events, want 2 (exactly-at-boundary must still escalate)", len(reads))
	}
}

func TestTrifecta_DifferentSessionsDoNotCorrelate(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithTrifectaWindow(30*time.Second))

	if err := eng.Observe(sensitiveReadEvent("sess-A", 0, 0, 42, "/home/user/.ssh/id_ed25519", "ssh-key"), 0); err != nil {
		t.Fatalf("Observe sensitive_read: %v", err)
	}
	daddr := mustParseV4Mapped(t, "93.184.216.34")
	if err := eng.Observe(connectEvent("sess-B", 0, 0, 42, daddr), 0); err != nil {
		t.Fatalf("Observe new_domain trigger: %v", err)
	}

	reads := filterType(sk.events, schema.EventTypeAlertSensitiveRead)
	if len(reads) != 1 {
		t.Fatalf("got %d alert.sensitive_read events, want 1 (different sessions must not correlate)", len(reads))
	}
}

func TestTrifecta_OnlySensitiveReadNoNewDomainNoEscalation(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithTrifectaWindow(30*time.Second))

	if err := eng.Observe(sensitiveReadEvent("sess-1", 0, 0, 42, "/home/user/.ssh/id_ed25519", "ssh-key"), 0); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	reads := filterType(sk.events, schema.EventTypeAlertSensitiveRead)
	if len(reads) != 1 {
		t.Fatalf("got %d alert.sensitive_read events, want 1 (no new_domain observed, no escalation)", len(reads))
	}
}

func TestTrifecta_EachNewDomainEscalatesOnlyOnce(t *testing.T) {
	// A single sensitive_read paired with two distinct new_domain firings
	// within the window escalates once per distinct correlation, not
	// unboundedly — each (sensitive_read, new_domain) pairing is a distinct,
	// independently newsworthy correlation, but the same new_domain must not
	// re-trigger escalation repeatedly for the same already-correlated pair.
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithTrifectaWindow(30*time.Second))

	if err := eng.Observe(sensitiveReadEvent("sess-1", 0, 0, 42, "/home/user/.ssh/id_ed25519", "ssh-key"), 0); err != nil {
		t.Fatalf("Observe sensitive_read: %v", err)
	}
	daddr1 := mustParseV4Mapped(t, "93.184.216.34")
	if err := eng.Observe(connectEvent("sess-1", 0, 1, 42, daddr1), 0); err != nil {
		t.Fatalf("Observe new_domain 1: %v", err)
	}
	daddr2 := mustParseV4Mapped(t, "1.2.3.4")
	if err := eng.Observe(connectEvent("sess-1", 0, 2, 42, daddr2), 0); err != nil {
		t.Fatalf("Observe new_domain 2: %v", err)
	}

	reads := filterType(sk.events, schema.EventTypeAlertSensitiveRead)
	// original + escalation-for-daddr1 + escalation-for-daddr2 = 3
	if len(reads) != 3 {
		t.Fatalf("got %d alert.sensitive_read events, want 3 (original + one escalation per distinct new_domain)", len(reads))
	}
}

func TestTrifecta_CrossSideCorrelationDoesNotCorruptOppositeList(t *testing.T) {
	// Regression test (white-box, package-internal): correlateTrifecta's
	// cross-correlation loops (iterating the *other* side's retained list
	// to find candidates) must use a non-destructive filter
	// (inWindowTrifecta), not pruneTrifecta. pruneTrifecta reuses its
	// input slice's backing array (evs[:0]) to compact in place; calling
	// it and discarding the result still leaves the caller's stored slice
	// (never reassigned) pointing at a silently corrupted backing array —
	// evicted entries get overwritten with duplicates of the surviving
	// tail entries, even though the map's slice header (length) is
	// unchanged.
	//
	// This corruption does NOT reliably surface as a wrong escalation
	// *count* (emitTrifectaEscalation's own (readIdx, domainIdx) dedup
	// absorbs a duplicate iteration, since a phantom duplicate carries the
	// same idx as its original) — so this test inspects Engine's retained
	// state directly rather than relying on emitted-alert counts, which
	// would not have caught this defect.
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	window := 5 * time.Second
	eng := newTestEngine(t, clk, sk, fn, WithTrifectaWindow(window))

	// domain0 at t=0 (will be evicted), domain1 and domain2 at t=4
	// (survive) — three entries so an eviction forces the in-place
	// compaction to shift surviving elements down a slot (with only one
	// surviving entry, compaction is a same-slot no-op and the bug is
	// invisible).
	daddr0 := mustParseV4Mapped(t, "93.184.216.34")
	if err := eng.Observe(connectEvent("sess-1", 0, 0, 42, daddr0), 0); err != nil {
		t.Fatalf("Observe domain0: %v", err)
	}
	clk.Advance(4 * time.Second) // t=4
	daddr1 := mustParseV4Mapped(t, "1.2.3.4")
	if err := eng.Observe(connectEvent("sess-1", 0, 1, 42, daddr1), 0); err != nil {
		t.Fatalf("Observe domain1: %v", err)
	}
	daddr2 := mustParseV4Mapped(t, "5.6.7.8")
	if err := eng.Observe(connectEvent("sess-1", 0, 2, 42, daddr2), 0); err != nil {
		t.Fatalf("Observe domain2: %v", err)
	}

	// A sensitive_read at t=5.5s: cutoff=0.5s evicts domain0 (t=0), keeps
	// domain1/domain2 (t=4). This call's cross-correlation loop over
	// recentNewDomains (iterate-only, no writeback owned here) is exactly
	// the discard-after-prune site under test: it must not mutate
	// e.recentNewDomains["sess-1"]'s backing array.
	clk.Advance(1500 * time.Millisecond) // t=5.5
	if err := eng.Observe(sensitiveReadEvent("sess-1", 0, 3, 42, "/home/user/.ssh/id_ed25519", "ssh-key"), 0); err != nil {
		t.Fatalf("Observe read1: %v", err)
	}

	stored := eng.recentNewDomains["sess-1"]
	if len(stored) != 3 {
		t.Fatalf("len(recentNewDomains[sess-1]) = %d, want 3 (the map's own writeback only happens when a new_domain fires, not when a sensitive_read merely reads it)", len(stored))
	}
	// stored[0] must still be domain0's original entry (host
	// 93.184.216.34, idx 0) — the discarded correlate-only prune call must
	// not have overwritten it with a duplicate of a later surviving entry.
	if got := string(stored[0].host); got != "93.184.216.34" {
		t.Errorf("recentNewDomains[sess-1][0].host corrupted: got %q, want %q (a live cross-correlation read overwrote an entry it does not own)", got, "93.184.216.34")
	}
	if stored[0].idx != 0 {
		t.Errorf("recentNewDomains[sess-1][0].idx corrupted: got %d, want 0", stored[0].idx)
	}
	if got := string(stored[1].host); got != "1.2.3.4" {
		t.Errorf("recentNewDomains[sess-1][1].host corrupted: got %q, want %q", got, "1.2.3.4")
	}
	if got := string(stored[2].host); got != "5.6.7.8" {
		t.Errorf("recentNewDomains[sess-1][2].host corrupted: got %q, want %q", got, "5.6.7.8")
	}
}

func TestTrifecta_EscalatedEventIsWellFormed(t *testing.T) {
	clk := newFakeClock()
	sk := &sink{}
	fn := &FakeNotifier{}
	eng := newTestEngine(t, clk, sk, fn, WithTrifectaWindow(30*time.Second))

	if err := eng.Observe(sensitiveReadEvent("sess-1", 2, 0, 42, "/home/user/.ssh/id_ed25519", "ssh-key"), 2); err != nil {
		t.Fatalf("Observe sensitive_read: %v", err)
	}
	daddr := mustParseV4Mapped(t, "93.184.216.34")
	if err := eng.Observe(connectEvent("sess-1", 2, 1, 42, daddr), 2); err != nil {
		t.Fatalf("Observe new_domain trigger: %v", err)
	}

	for _, ev := range sk.events {
		if err := schema.Validate(ev); err != nil {
			t.Errorf("event failed schema.Validate: %v (event: %+v)", err, ev)
		}
	}
}

// ---- helpers ----

func filterType(evs []schema.Event, t schema.EventType) []schema.Event {
	var out []schema.Event
	for _, ev := range evs {
		if ev.Type == t {
			out = append(out, ev)
		}
	}
	return out
}
