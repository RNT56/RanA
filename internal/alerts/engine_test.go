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
			t.Errorf("event.Origin = %q, want svc (alert.* is svc-emitted per plan §4.3)", ev.Origin)
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
