package collector

import (
	"testing"
	"time"
)

// fakeClock is a deterministic, manually-advanced Clock for governor tests
// (CONTRACTS testing bar: injectable clocks everywhere time matters).
type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func newTestGovernor(t *testing.T, clk Clock, ratePerSec float64, burst int) *Governor {
	t.Helper()
	g, err := NewGovernor(GovernorConfig{
		Clock:        clk,
		RatePerSec:   ratePerSec,
		BurstSize:    burst,
		ShedInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("NewGovernor: %v", err)
	}
	return g
}

// ---- class priority classification ----

func TestClassPriorityNeverShedSet(t *testing.T) {
	neverShed := []EventClass{
		ClassExec, ClassConnect, ClassSensitiveRead, ClassSession, ClassGap,
	}
	for _, c := range neverShed {
		if !c.NeverShed() {
			t.Errorf("class %v: NeverShed() = false, want true", c)
		}
	}
}

func TestClassPriorityShedOrder(t *testing.T) {
	// Lowest value (shed first) to highest value (shed last, among
	// sheddable classes): fork/exit -> fs metadata -> fs.write_open ->
	// flow_close/dns (CONTRACTS §internal/collector).
	order := []EventClass{
		ClassForkExit,
		ClassFsMeta,
		ClassFsWriteOpen,
		ClassFlowDNS,
	}
	for i := 0; i < len(order)-1; i++ {
		if order[i].shedPriority() >= order[i+1].shedPriority() {
			t.Errorf("%v.shedPriority()=%d should be < %v.shedPriority()=%d",
				order[i], order[i].shedPriority(), order[i+1], order[i+1].shedPriority())
		}
	}
	for _, c := range order {
		if c.NeverShed() {
			t.Errorf("class %v unexpectedly in never-shed set", c)
		}
	}
}

// ---- basic admit/shed behavior ----

func TestGovernorAdmitsWithinBudget(t *testing.T) {
	clk := newFakeClock()
	g := newTestGovernor(t, clk, 100, 100) // 100 tokens available immediately
	for i := 0; i < 100; i++ {
		if !g.Admit("sess-1", ClassFsMeta) {
			t.Fatalf("event %d: expected admit within initial burst", i)
		}
	}
}

func TestGovernorNeverShedsExecEvenWhenBucketEmpty(t *testing.T) {
	clk := newFakeClock()
	g := newTestGovernor(t, clk, 1, 1) // tiny budget
	g.Admit("sess-1", ClassFsMeta)     // drain the one token
	for i := 0; i < 1000; i++ {
		if !g.Admit("sess-1", ClassExec) {
			t.Fatalf("exec event %d was shed; never-shed classes must always pass", i)
		}
		if !g.Admit("sess-1", ClassConnect) {
			t.Fatalf("connect event %d was shed", i)
		}
		if !g.Admit("sess-1", ClassSensitiveRead) {
			t.Fatalf("sensitive_read event %d was shed", i)
		}
		if !g.Admit("sess-1", ClassSession) {
			t.Fatalf("session event %d was shed", i)
		}
		if !g.Admit("sess-1", ClassGap) {
			t.Fatalf("gap event %d was shed", i)
		}
	}
}

func TestGovernorShedsWhenBucketEmpty(t *testing.T) {
	clk := newFakeClock()
	g := newTestGovernor(t, clk, 1, 1)
	if !g.Admit("sess-1", ClassFsMeta) {
		t.Fatal("first event should be admitted (burst=1)")
	}
	if g.Admit("sess-1", ClassFsMeta) {
		t.Fatal("second event should be shed (bucket empty, no time passed)")
	}
}

func TestGovernorRefillsOverTime(t *testing.T) {
	clk := newFakeClock()
	g := newTestGovernor(t, clk, 10, 1) // 10 tokens/sec, burst 1
	if !g.Admit("sess-1", ClassFsMeta) {
		t.Fatal("first event should be admitted")
	}
	if g.Admit("sess-1", ClassFsMeta) {
		t.Fatal("second event should be shed immediately")
	}
	clk.Advance(200 * time.Millisecond) // 10/sec * 0.2s = 2 tokens, capped at burst 1
	if !g.Admit("sess-1", ClassFsMeta) {
		t.Fatal("event after refill should be admitted")
	}
}

func TestGovernorPerSessionBucketsIndependent(t *testing.T) {
	clk := newFakeClock()
	g := newTestGovernor(t, clk, 1, 1)
	if !g.Admit("sess-a", ClassFsMeta) {
		t.Fatal("sess-a first event should be admitted")
	}
	if !g.Admit("sess-b", ClassFsMeta) {
		t.Fatal("sess-b first event should be admitted independent of sess-a")
	}
	if g.Admit("sess-a", ClassFsMeta) {
		t.Fatal("sess-a second event should be shed")
	}
}

// ---- shed-order under burst ----

func TestGovernorBurst50kPerSecShedsLowestClassFirst(t *testing.T) {
	clk := newFakeClock()
	// Sustained refill rate (30k/s) below total burst demand (50k/s) but
	// above any single tier's individual demand (12.5k/s), so the
	// priority waterfall's cascade is actually exercised: the two
	// highest-priority sheddable tiers (write_open, flow/dns) end up
	// fully served while fork/exit and fs-meta are visibly starved in a
	// strictly graded way.
	g := newTestGovernor(t, clk, 30000, 500)

	const burstSize = 50000
	classes := []EventClass{ClassForkExit, ClassFsMeta, ClassFsWriteOpen, ClassFlowDNS}
	admitted := map[EventClass]int{}
	shed := map[EventClass]int{}

	// Simulate the burst arriving at 50k events/sec of wall-clock time (not
	// instantaneously), so the token bucket's rate-based refill is actually
	// exercised across the burst — a purely instantaneous burst only drains
	// each tier's initial capacity and never observes the priority-aware
	// waterfall refill this test is meant to exercise.
	perEvent := time.Second / burstSize
	for i := 0; i < burstSize; i++ {
		c := classes[i%len(classes)]
		if g.Admit("sess-1", c) {
			admitted[c]++
		} else {
			shed[c]++
		}
		clk.Advance(perEvent)
	}

	// Never-shed classes interleaved in the same burst must all be admitted.
	for i := 0; i < 1000; i++ {
		if !g.Admit("sess-1", ClassExec) {
			t.Fatalf("exec shed during burst at iteration %d", i)
		}
	}

	total := admitted[ClassForkExit] + shed[ClassForkExit]
	if total != burstSize/len(classes) {
		t.Fatalf("ClassForkExit total = %d, want %d", total, burstSize/len(classes))
	}

	rate := func(c EventClass) float64 {
		a, s := admitted[c], shed[c]
		if a+s == 0 {
			return 0
		}
		return float64(a) / float64(a+s)
	}
	forkExitRate := rate(ClassForkExit)
	fsMetaRate := rate(ClassFsMeta)
	writeOpenRate := rate(ClassFsWriteOpen)
	flowDNSRate := rate(ClassFlowDNS)

	// Strict priority order: each tier's admit rate must be no better than
	// the next-higher tier's, with at least one strict inequality proving
	// the priority waterfall actually differentiates tiers (the two
	// best-served tiers may legitimately tie at 100% admitted).
	if forkExitRate > fsMetaRate {
		t.Errorf("fork/exit admit rate %.4f should be <= fs-meta admit rate %.4f (shed first)", forkExitRate, fsMetaRate)
	}
	if fsMetaRate > writeOpenRate {
		t.Errorf("fs-meta admit rate %.4f should be <= write_open admit rate %.4f", fsMetaRate, writeOpenRate)
	}
	if writeOpenRate > flowDNSRate {
		t.Errorf("write_open admit rate %.4f should be <= flow/dns admit rate %.4f", writeOpenRate, flowDNSRate)
	}
	if forkExitRate >= fsMetaRate || fsMetaRate >= writeOpenRate {
		t.Errorf("expected strict gradation somewhere in the shed order; got forkExit=%.4f fsMeta=%.4f writeOpen=%.4f flowDNS=%.4f",
			forkExitRate, fsMetaRate, writeOpenRate, flowDNSRate)
	}

	if shed[ClassForkExit] == 0 {
		t.Error("expected some fork/exit events to be shed under this burst/budget")
	}

	// Exact counts: with a fake clock and a deterministic per-event advance,
	// the priority-waterfall admission is fully reproducible. Pinning the
	// precise admitted/shed numbers (not just their relative order) is what
	// "gap counts are exact under deterministic burst" (CONTRACTS EXTRA)
	// actually requires — an ordering-only assertion could pass even if the
	// waterfall silently mis-accounted a handful of events per tier.
	wantAdmitted := map[EventClass]int{
		ClassForkExit:    500,
		ClassFsMeta:      5499,
		ClassFsWriteOpen: 12500,
		ClassFlowDNS:     12500,
	}
	wantShed := map[EventClass]int{
		ClassForkExit:    12000,
		ClassFsMeta:      7001,
		ClassFsWriteOpen: 0,
		ClassFlowDNS:     0,
	}
	for _, c := range classes {
		if admitted[c] != wantAdmitted[c] {
			t.Errorf("admitted[%v] = %d, want %d", c, admitted[c], wantAdmitted[c])
		}
		if shed[c] != wantShed[c] {
			t.Errorf("shed[%v] = %d, want %d", c, shed[c], wantShed[c])
		}
	}

	clk.Advance(time.Second) // close the shed interval so FlushGaps reports it
	gaps := g.FlushGaps()
	var governorGap *GapRecord
	for i := range gaps {
		if gaps[i].Reason == "governor" {
			governorGap = &gaps[i]
		}
	}
	if governorGap == nil {
		t.Fatal("expected a governor-reason gap after the burst")
	}
	wantCounts := map[string]uint64{
		"fork_exit":     uint64(wantShed[ClassForkExit]),
		"fs.meta":       uint64(wantShed[ClassFsMeta]),
		"fs.write_open": uint64(wantShed[ClassFsWriteOpen]),
		"flow_dns":      uint64(wantShed[ClassFlowDNS]),
	}
	for k, want := range wantCounts {
		if want == 0 {
			continue // FlushGaps/record only tracks nonzero shed classes
		}
		if got := governorGap.Counts[k]; got != want {
			t.Errorf("gap Counts[%q] = %d, want %d (exact count under deterministic burst)", k, got, want)
		}
	}
}

// ---- gap emission ----

func TestGovernorEmitsGapWithExactShedCounts(t *testing.T) {
	clk := newFakeClock()
	g := newTestGovernor(t, clk, 1, 1)

	g.Admit("sess-1", ClassFsMeta) // admitted (tier capacity=1)
	for i := 0; i < 5; i++ {
		g.Admit("sess-1", ClassFsMeta) // all shed, this tier now empty
	}
	g.Admit("sess-1", ClassForkExit) // admitted (its own tier capacity=1)
	for i := 0; i < 3; i++ {
		g.Admit("sess-1", ClassForkExit) // all shed, this tier now empty
	}

	clk.Advance(time.Second) // end of shed interval
	gaps := g.FlushGaps()

	if len(gaps) != 1 {
		t.Fatalf("FlushGaps() returned %d gaps, want 1", len(gaps))
	}
	gp := gaps[0]
	if gp.Session != "sess-1" {
		t.Errorf("Session = %q, want sess-1", gp.Session)
	}
	if gp.Reason != "governor" {
		t.Errorf("Reason = %q, want governor", gp.Reason)
	}
	if gp.Counts["fs.meta"] != 5 {
		t.Errorf(`Counts["fs.meta"] = %d, want 5`, gp.Counts["fs.meta"])
	}
	if gp.Counts["fork_exit"] != 3 {
		t.Errorf(`Counts["fork_exit"] = %d, want 3`, gp.Counts["fork_exit"])
	}
	if gp.FromNs >= gp.ToNs {
		t.Errorf("FromNs=%d must be < ToNs=%d", gp.FromNs, gp.ToNs)
	}
}

func TestGovernorNoGapWhenNothingShed(t *testing.T) {
	clk := newFakeClock()
	g := newTestGovernor(t, clk, 1000, 1000)
	g.Admit("sess-1", ClassFsMeta)
	clk.Advance(time.Second)
	gaps := g.FlushGaps()
	if len(gaps) != 0 {
		t.Fatalf("FlushGaps() returned %d gaps, want 0 when nothing was shed", len(gaps))
	}
}

func TestGovernorFlushGapsResetsCounts(t *testing.T) {
	clk := newFakeClock()
	g := newTestGovernor(t, clk, 1, 1)
	g.Admit("sess-1", ClassFsMeta)
	g.Admit("sess-1", ClassFsMeta) // shed

	clk.Advance(time.Second)
	gaps1 := g.FlushGaps()
	if len(gaps1) != 1 {
		t.Fatalf("first flush: got %d gaps, want 1", len(gaps1))
	}

	clk.Advance(time.Second)
	gaps2 := g.FlushGaps()
	if len(gaps2) != 0 {
		t.Fatalf("second flush (no new sheds): got %d gaps, want 0", len(gaps2))
	}
}

func TestGovernorMultiSessionGapsIndependent(t *testing.T) {
	clk := newFakeClock()
	g := newTestGovernor(t, clk, 1, 1)
	g.Admit("sess-a", ClassFsMeta)
	g.Admit("sess-a", ClassFsMeta) // shed for sess-a
	g.Admit("sess-b", ClassFsMeta)
	// sess-b has no shed events

	clk.Advance(time.Second)
	gaps := g.FlushGaps()
	if len(gaps) != 1 {
		t.Fatalf("got %d gaps, want 1 (only sess-a shed)", len(gaps))
	}
	if gaps[0].Session != "sess-a" {
		t.Errorf("Session = %q, want sess-a", gaps[0].Session)
	}
}

// ---- RingbufFull path ----

func TestGovernorRecordRingbufDropEmitsGapReasonRingbufFull(t *testing.T) {
	clk := newFakeClock()
	g := newTestGovernor(t, clk, 1000, 1000)
	g.RecordRingbufDrop("sess-1", ClassFsWriteOpen, 7)

	clk.Advance(time.Second)
	gaps := g.FlushGaps()
	if len(gaps) != 1 {
		t.Fatalf("got %d gaps, want 1", len(gaps))
	}
	if gaps[0].Reason != "ringbuf_full" {
		t.Errorf("Reason = %q, want ringbuf_full", gaps[0].Reason)
	}
	if gaps[0].Counts["fs.write_open"] != 7 {
		t.Errorf(`Counts["fs.write_open"] = %d, want 7`, gaps[0].Counts["fs.write_open"])
	}
}

func TestGovernorRingbufAndGovernorGapsAreSeparateEvents(t *testing.T) {
	clk := newFakeClock()
	g := newTestGovernor(t, clk, 1, 1)
	g.Admit("sess-1", ClassFsMeta)
	g.Admit("sess-1", ClassFsMeta) // shed by governor
	g.RecordRingbufDrop("sess-1", ClassFsWriteOpen, 2)

	clk.Advance(time.Second)
	gaps := g.FlushGaps()
	if len(gaps) != 2 {
		t.Fatalf("got %d gaps, want 2 (one per reason)", len(gaps))
	}
	reasons := map[string]bool{}
	for _, gp := range gaps {
		reasons[gp.Reason] = true
	}
	if !reasons["governor"] || !reasons["ringbuf_full"] {
		t.Errorf("reasons = %v, want both governor and ringbuf_full", reasons)
	}
}

// ---- config validation ----

func TestNewGovernorRejectsInvalidConfig(t *testing.T) {
	clk := newFakeClock()
	tests := []struct {
		name string
		cfg  GovernorConfig
	}{
		{"nil clock", GovernorConfig{Clock: nil, RatePerSec: 1, BurstSize: 1, ShedInterval: time.Second}},
		{"zero rate", GovernorConfig{Clock: clk, RatePerSec: 0, BurstSize: 1, ShedInterval: time.Second}},
		{"negative rate", GovernorConfig{Clock: clk, RatePerSec: -1, BurstSize: 1, ShedInterval: time.Second}},
		{"zero burst", GovernorConfig{Clock: clk, RatePerSec: 1, BurstSize: 0, ShedInterval: time.Second}},
		{"zero shed interval", GovernorConfig{Clock: clk, RatePerSec: 1, BurstSize: 1, ShedInterval: 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewGovernor(tt.cfg)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// TestEndSessionReleasesStateAndFlushesPendingGap verifies that ending a
// session frees its per-session governor state (so a long-lived ranad does
// not leak a bucket per session forever) and returns any not-yet-surfaced
// shed counts as a final gap so nothing is silently dropped (P5).
func TestEndSessionReleasesStateAndFlushesPendingGap(t *testing.T) {
	clk := newFakeClock()
	// rate 1/sec, burst 1: the first low-value event passes, the rest shed.
	g := newTestGovernor(t, clk, 1, 1)
	const sess = "rana-x"

	// Prime the bucket for this session, then force sheds without crossing a
	// ShedInterval boundary so the counts are still pending in shedState.
	g.Admit(sess, ClassForkExit) // consumes the single token
	for i := 0; i < 5; i++ {
		if g.Admit(sess, ClassForkExit) {
			t.Fatalf("expected shed on event %d", i)
		}
	}

	final := g.EndSession(sess)
	if final == nil {
		t.Fatal("EndSession returned nil; expected a final gap for pending sheds")
	}
	var total uint64
	for _, v := range final.Counts {
		total += v
	}
	if total != 5 {
		t.Fatalf("final gap total = %d, want 5", total)
	}

	// State must be gone: a second EndSession is a no-op, and FlushGaps must
	// not resurrect the ended session.
	if again := g.EndSession(sess); again != nil {
		t.Fatalf("second EndSession returned %+v, want nil", again)
	}
	for _, gp := range g.FlushGaps() {
		if gp.Session == sess {
			t.Fatalf("FlushGaps surfaced ended session %q", sess)
		}
	}
}
