package collector

import (
	"errors"
	"sync"
	"time"
)

// Clock supplies the current time, injectable for deterministic governor
// tests (CONTRACTS testing bar: injectable clocks everywhere time matters).
// Distinct from schema.Clock (which supplies Unix-ms for session ID
// generation) — this Clock deals in time.Time/time.Duration because the
// governor's token-bucket math needs sub-millisecond precision under a
// synthetic burst test.
type Clock interface {
	Now() time.Time
}

// systemClock is the real wall-clock Clock used outside tests.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// SystemClock is the production Clock backed by time.Now().
var SystemClock Clock = systemClock{}

// EventClass names a governor accounting/shedding class. Every record kind
// decoded by this package maps to exactly one EventClass (see the Enricher).
type EventClass uint8

// EventClass values. The never-shed set and shed order are frozen by
// CONTRACTS §internal/collector:
//
//	never-shed: exec, connect, sensitive_read, session.*, gap
//	shed order (lowest value / shed-first, to highest / shed-last):
//	  fork/exit -> fs metadata -> fs.write_open -> flow_close/dns
const (
	ClassExec          EventClass = iota // proc.exec — never shed
	ClassConnect                         // net.connect — never shed
	ClassSensitiveRead                   // fs.sensitive_read — never shed
	ClassSession                         // session.start/session.end — never shed
	ClassGap                             // gap events themselves — never shed (P5: losses must never be lost)

	ClassForkExit    // proc.fork / proc.exit — shed first
	ClassFsMeta      // fs.unlink/rename/mkdir/chmod/truncate — shed second
	ClassFsWriteOpen // fs.write_open — shed third
	ClassFlowDNS     // net.flow_close / net.dns — shed last (highest sheddable priority)
)

// String returns a short label used for diagnostics; classKey (below) is
// what actually appears in a gap event's counts map.
func (c EventClass) String() string {
	switch c {
	case ClassExec:
		return "exec"
	case ClassConnect:
		return "connect"
	case ClassSensitiveRead:
		return "sensitive_read"
	case ClassSession:
		return "session"
	case ClassGap:
		return "gap"
	case ClassForkExit:
		return "fork_exit"
	case ClassFsMeta:
		return "fs.meta"
	case ClassFsWriteOpen:
		return "fs.write_open"
	case ClassFlowDNS:
		return "flow_dns"
	default:
		return "unknown"
	}
}

// classKey is the string used as a key in a gap event's per-class counts
// map (schema.NewGap's counts map[string]uint64). Kept distinct from
// String() only for future flexibility; today they're identical.
func (c EventClass) classKey() string { return c.String() }

// NeverShed reports whether events of class c are in the frozen never-shed
// set (P5 / D14): the governor MUST always admit these regardless of
// bucket state.
func (c EventClass) NeverShed() bool {
	switch c {
	case ClassExec, ClassConnect, ClassSensitiveRead, ClassSession, ClassGap:
		return true
	default:
		return false
	}
}

// shedPriority returns a sheddable class's position in the frozen shed
// order: lower value sheds first. Only meaningful when NeverShed() is
// false; never-shed classes return -1 (they never reach the comparison).
func (c EventClass) shedPriority() int {
	switch c {
	case ClassForkExit:
		return 0
	case ClassFsMeta:
		return 1
	case ClassFsWriteOpen:
		return 2
	case ClassFlowDNS:
		return 3
	default:
		return -1
	}
}

// GovernorConfig configures a Governor. All fields are required;
// NewGovernor validates them.
type GovernorConfig struct {
	// Clock supplies time for token-bucket refill and shed-interval
	// boundaries. Injectable for deterministic tests.
	Clock Clock
	// RatePerSec is the sustained token-bucket refill rate, per session,
	// in tokens/sec (one token == one admitted event, regardless of
	// class — class only decides shed order once the bucket is empty).
	RatePerSec float64
	// BurstSize is the token bucket's capacity (and its starting level)
	// per session.
	BurstSize int
	// ShedInterval is the accounting window a FlushGaps() call closes:
	// shed/drop counts accumulated since the last flush are packaged into
	// gap events and the counters reset (CONTRACTS: "on shed interval end
	// emit gap event with per-class counts").
	ShedInterval time.Duration
}

// GapRecord is the governor's portable representation of a gap event,
// ready for a caller (svc/ranad) to turn into schema.NewGap without this
// package needing to depend on internal/schema's redact.Redacted plumbing
// for a plain reason string. reason values are exactly the frozen
// schema.GapReason strings ("governor", "ringbuf_full") — CONTRACTS forbids
// inventing new reasons.
type GapRecord struct {
	Session string
	Reason  string
	Counts  map[string]uint64
	FromNs  uint64
	ToNs    uint64
}

// shedTierCount is the number of distinct sheddable shedPriority() tiers
// (ClassForkExit..ClassFlowDNS): fork/exit, fs metadata, fs.write_open,
// flow/dns.
const shedTierCount = 4

// tieredBucket implements the frozen shed order (D14, CONTRACTS
// §internal/collector) as a strict-priority waterfall over ONE shared
// token pool: every refill tick tops up the highest-priority sheddable
// tier (tier 3, flow/dns — shed LAST, so refilled FIRST) to full burst
// capacity before tier 2 (fs.write_open) gets anything, tops up tier 2
// before tier 1 (fs metadata), and so on down to tier 0 (fork/exit — shed
// FIRST, so refilled LAST). Each tier's own cap is the full burst size,
// but a lower-priority tier only ever sees tokens after every
// higher-priority tier is completely full — so under sustained admission
// pressure spread evenly across tiers (as in a round-robin burst), the
// shed-first tier drains to zero and stays there while shed-last tiers
// keep draining and refilling, giving a strictly better admit rate to
// every higher-priority tier.
type tieredBucket struct {
	tiers      [shedTierCount]float64 // tokens available per tier, index = shedPriority()
	capacity   float64                // each tier's cap == the full per-session burst size
	lastRefill time.Time
}

func newTieredBucket(burstSize float64, now time.Time) *tieredBucket {
	tb := &tieredBucket{capacity: burstSize, lastRefill: now}
	for i := range tb.tiers {
		tb.tiers[i] = burstSize
	}
	return tb
}

// refill adds elapsed*ratePerSec tokens to the waterfall: the
// highest-index tier (shed last) is topped up to capacity first, then any
// remainder spills downward through lower-index tiers, ending at tier 0
// (shed first) — which is why tier 0 is the first to run dry and stay dry
// under sustained pressure.
func (tb *tieredBucket) refill(ratePerSec float64, now time.Time) {
	elapsed := now.Sub(tb.lastRefill).Seconds()
	if elapsed <= 0 {
		return
	}
	remaining := elapsed * ratePerSec
	tb.lastRefill = now
	for i := shedTierCount - 1; i >= 0 && remaining > 0; i-- {
		room := tb.capacity - tb.tiers[i]
		if room <= 0 {
			continue
		}
		take := remaining
		if take > room {
			take = room
		}
		tb.tiers[i] += take
		remaining -= take
	}
}

// take consumes one token from the given tier, returning true if admitted.
func (tb *tieredBucket) take(tier int) bool {
	if tb.tiers[tier] >= 1 {
		tb.tiers[tier]--
		return true
	}
	return false
}

// sessionShedState accumulates per-class shed/drop counts for one session
// across the current shed interval, keyed by gap reason so a governor-shed
// interval and a ringbuf-drop report never merge into one gap event
// (CONTRACTS: reasons are a frozen, distinct set).
type sessionShedState struct {
	counts map[string]map[string]uint64 // reason -> class key -> count
}

func newSessionShedState() *sessionShedState {
	return &sessionShedState{counts: make(map[string]map[string]uint64)}
}

func (s *sessionShedState) record(reason, classKey string, n uint64) {
	m, ok := s.counts[reason]
	if !ok {
		m = make(map[string]uint64)
		s.counts[reason] = m
	}
	m[classKey] += n
}

// Governor is a per-session token-bucket admission controller
// (CONTRACTS §internal/collector). It sheds low-value event classes first
// under sustained load while never shedding the never-shed set, and it
// accounts every shed/drop so FlushGaps can emit an exact, honest gap
// event per session per reason (P5 — losses are loud, never silent).
//
// Governor is safe for concurrent use.
type Governor struct {
	mu sync.Mutex

	clock        Clock
	ratePerSec   float64
	burstSize    float64
	shedInterval time.Duration

	buckets       map[string]*tieredBucket
	shedState     map[string]*sessionShedState
	intervalStart map[string]time.Time
}

// ErrInvalidGovernorConfig is returned by NewGovernor when a required
// GovernorConfig field is missing or out of range.
var ErrInvalidGovernorConfig = errors.New("collector: invalid governor config")

// NewGovernor constructs a Governor from cfg, validating every field.
func NewGovernor(cfg GovernorConfig) (*Governor, error) {
	if cfg.Clock == nil {
		return nil, errors.Join(ErrInvalidGovernorConfig, errors.New("clock must not be nil"))
	}
	if cfg.RatePerSec <= 0 {
		return nil, errors.Join(ErrInvalidGovernorConfig, errors.New("rate per sec must be > 0"))
	}
	if cfg.BurstSize <= 0 {
		return nil, errors.Join(ErrInvalidGovernorConfig, errors.New("burst size must be > 0"))
	}
	if cfg.ShedInterval <= 0 {
		return nil, errors.Join(ErrInvalidGovernorConfig, errors.New("shed interval must be > 0"))
	}
	return &Governor{
		clock:         cfg.Clock,
		ratePerSec:    cfg.RatePerSec,
		burstSize:     float64(cfg.BurstSize),
		shedInterval:  cfg.ShedInterval,
		buckets:       make(map[string]*tieredBucket),
		shedState:     make(map[string]*sessionShedState),
		intervalStart: make(map[string]time.Time),
	}, nil
}

// bucketFor returns (creating if needed) session's tiered token bucket,
// refilled (waterfall order, tier 0 first) up to now.
func (g *Governor) bucketFor(session string, now time.Time) *tieredBucket {
	b, ok := g.buckets[session]
	if !ok {
		b = newTieredBucket(g.burstSize, now)
		g.buckets[session] = b
		if _, seen := g.intervalStart[session]; !seen {
			g.intervalStart[session] = now
		}
		return b
	}
	b.refill(g.ratePerSec, now)
	return b
}

func (g *Governor) shedStateFor(session string) *sessionShedState {
	s, ok := g.shedState[session]
	if !ok {
		s = newSessionShedState()
		g.shedState[session] = s
	}
	return s
}

// Admit decides whether an event of class c for session should be admitted
// right now. Never-shed classes always return true and do not consume a
// token (P5, D14: exec/connect/sensitive_read/session/gap can never be
// shed). Sheddable classes consume one token if available; otherwise the
// event is shed and accounted under reason "governor" for the next
// FlushGaps call.
func (g *Governor) Admit(session string, c EventClass) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if c.NeverShed() {
		return true
	}

	now := g.clock.Now()
	b := g.bucketFor(session, now)
	if b.take(c.shedPriority()) {
		return true
	}

	g.shedStateFor(session).record("governor", c.classKey(), 1)
	return false
}

// RecordRingbufDrop accounts n events of class c for session that were
// dropped upstream of the governor (kernel ring-buffer full — reason
// "ringbuf_full"), so the next FlushGaps call reports them honestly even
// though the governor itself never saw them as individual Admit calls.
func (g *Governor) RecordRingbufDrop(session string, c EventClass, n uint64) {
	if n == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, seen := g.intervalStart[session]; !seen {
		g.intervalStart[session] = g.clock.Now()
	}
	g.shedStateFor(session).record("ringbuf_full", c.classKey(), n)
}

// FlushGaps closes the current shed interval for every session with
// nonzero accumulated shed/drop counts, returning one GapRecord per
// (session, reason) pair with exact counts, and resets those counters.
// Sessions with nothing shed since the last flush produce no GapRecord —
// FlushGaps never fabricates a gap where nothing was lost.
//
// FromNs/ToNs bound the flushed interval using the injected Clock,
// converted to Unix nanoseconds.
func (g *Governor) FlushGaps() []GapRecord {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.clock.Now()
	var out []GapRecord

	for session, state := range g.shedState {
		start, ok := g.intervalStart[session]
		if !ok {
			start = now
		}
		for reason, counts := range state.counts {
			if len(counts) == 0 {
				continue
			}
			// Copy so callers can't mutate governor-internal state.
			countsCopy := make(map[string]uint64, len(counts))
			var total uint64
			for k, v := range counts {
				countsCopy[k] = v
				total += v
			}
			if total == 0 {
				continue
			}
			out = append(out, GapRecord{
				Session: session,
				Reason:  reason,
				Counts:  countsCopy,
				FromNs:  uint64(start.UnixNano()),
				ToNs:    uint64(now.UnixNano()),
			})
		}
	}

	// Reset all accumulated state for the next interval.
	g.shedState = make(map[string]*sessionShedState)
	for session := range g.buckets {
		g.intervalStart[session] = now
	}
	for _, gp := range out {
		g.intervalStart[gp.Session] = now
	}

	return out
}

// EndSession drops all per-session governor state (token bucket, shed
// accumulators, interval clock) for a session that has ended. Without this a
// long-lived ranad would retain one bucket per session it has ever seen,
// growing unboundedly across a machine's lifetime. Any shed counts not yet
// surfaced are returned as a final GapRecord so an ending session never
// silently discards a pending gap (P5). Safe to call for an unknown session
// (returns nil).
func (g *Governor) EndSession(session string) *GapRecord {
	g.mu.Lock()
	defer g.mu.Unlock()

	var final *GapRecord
	if state, ok := g.shedState[session]; ok {
		start, ok := g.intervalStart[session]
		if !ok {
			start = g.clock.Now()
		}
		now := g.clock.Now()
		merged := make(map[string]uint64)
		var reason string
		var total uint64
		for r, counts := range state.counts {
			for k, v := range counts {
				merged[k] += v
				total += v
			}
			if reason == "" {
				reason = r
			}
		}
		if total > 0 {
			final = &GapRecord{
				Session: session,
				Reason:  reason,
				Counts:  merged,
				FromNs:  uint64(start.UnixNano()),
				ToNs:    uint64(now.UnixNano()),
			}
		}
	}

	delete(g.buckets, session)
	delete(g.shedState, session)
	delete(g.intervalStart, session)
	return final
}
