package alerts

import (
	"errors"
	"fmt"
	"time"

	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// Clock supplies the current time, injectable for deterministic tests
// (CONTRACTS testing bar: injectable clocks everywhere time matters).
// Mirrors internal/collector.Clock's shape deliberately — both the
// governor and the burst rule do sliding-window token-bucket-shaped math
// and both need the same fake-clock ergonomics in tests.
type Clock interface {
	Now() time.Time
}

// systemClock is the real wall-clock Clock used outside tests.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// SystemClock is the production Clock backed by time.Now().
var SystemClock Clock = systemClock{}

// Sink receives every schema.Event a rule synthesizes (e.g. alert.new_domain,
// alert.burst). The caller (svc) wires this to the ledger writer's Append —
// alerts are ordinary events once emitted: persisted, chained, verified
// like anything else. A Sink error is NOT swallowed: it propagates out of
// Observe, because a failure to persist an alert is a real loss the caller
// needs to know about (unlike a failed desktop notification, which is
// best-effort by design — see Notifier).
type Sink func(ev schema.Event) error

// Config configures an Engine. Clock and Sink are required; Notifier is
// optional (a nil Notifier behaves like NopNotifier).
type Config struct {
	// Clock is used for the burst rule's sliding window. Required.
	Clock Clock
	// Sink receives every synthesized alert.* event. Required.
	Sink Sink
	// Notifier delivers a best-effort desktop notification for every rule
	// firing (synthesized alerts and passthrough alerts alike). Optional;
	// defaults to NopNotifier.
	Notifier Notifier
}

// ErrNilClock is returned by NewEngine when Config.Clock is nil.
var ErrNilClock = errors.New("alerts: Config.Clock must not be nil")

// ErrNilSink is returned by NewEngine when Config.Sink is nil.
var ErrNilSink = errors.New("alerts: Config.Sink must not be nil")

// Option configures optional Engine behavior at construction time.
type Option func(*Engine)

// WithBurstThreshold overrides the burst rule's default threshold/window
// (see newBurstRule for the default). count is the number of same-class,
// same-session events that must occur within window for alert.burst to
// fire.
func WithBurstThreshold(count uint64, window time.Duration) Option {
	return func(e *Engine) {
		e.burst = newBurstRule(count, window)
	}
}

// WithTrifectaWindow overrides the default window within which a
// sensitive_read and a new_domain firing in the same session correlate into
// an escalated alert.sensitive_read (see defaultTrifectaWindow).
func WithTrifectaWindow(window time.Duration) Option {
	return func(e *Engine) {
		e.trifectaWindow = window
	}
}

// Engine is RanA's alert rules engine (the alert.* event taxonomy,
// CONTRACTS §internal/alerts): a fixed set of deterministic rules driven by
// a single entry point, Observe, called once per schema.Event AFTER that
// event has already been durably persisted by the ledger (svc wires this
// as a post-persist callback — CONTRACTS: "Rules engine consuming schema
// events post-persist").
//
// Engine holds only small, bounded in-memory state per session (a seen-set
// for new_domain, a sliding window for burst) — it never re-reads the
// ledger and never blocks the persist path it is a callback from.
type Engine struct {
	clock    Clock
	sink     Sink
	notifier Notifier

	newDomain     *newDomainRule
	sensitiveRead *sensitiveReadRule
	escape        *escapePassthroughRule
	burst         *burstRule

	nextIdx map[string]uint64

	// trifectaWindow bounds the sensitive-read/new-domain correlation below
	// (D9 "trifecta precursor"). See WithTrifectaWindow / defaultTrifectaWindow.
	trifectaWindow time.Duration
	// recentSensitiveReads[session] holds every sensitive_read firing within
	// trifectaWindow of "now", retained so a later new_domain in the same
	// session can correlate against it (the "sensitive_read then new_domain"
	// order).
	recentSensitiveReads map[string][]trifectaEvent
	// recentNewDomains[session] holds every new_domain firing within
	// trifectaWindow of "now", retained so a later sensitive_read in the
	// same session can correlate against it (the "new_domain then
	// sensitive_read" order).
	recentNewDomains map[string][]trifectaEvent
	// correlated[session] records which (readIdx, domainKey) pairs have
	// already produced an escalation, so the same pairing is never
	// escalated twice regardless of which side triggers the correlation.
	correlated map[string]map[string]bool
}

// trifectaEvent is one retained sensitive_read or new_domain firing, kept
// for a bounded window so a firing on the *other* side of the trifecta, in
// either temporal order, can correlate against it (D9).
type trifectaEvent struct {
	idx uint64 // triggering event's Idx; used as a stable per-firing key
	at  time.Time
	// key is the correlation key: for a sensitive_read it's a synthetic
	// "path|rule" identity that appears in the escalation as path/rule; for
	// a new_domain it's the first-contact host string (qname or dotted IP)
	// that appears in the escalation as correlated_host.
	key  string
	path redact.Redacted // sensitive_read only
	rule redact.Redacted // sensitive_read only
	host redact.Redacted // new_domain only: the redacted qname/IP value
	pid  uint32
}

// defaultTrifectaWindow is the window within which a sensitive_read and a
// new_domain firing in the same session, in either order, correlate into an
// escalated alert.sensitive_read (D9: "the trifecta precursor made
// actionable"). 60s is chosen to comfortably span the read-then-exfiltrate
// (or stage-then-read) latency of a scripted exfil chain without correlating
// across unrelated activity separated by minutes.
const defaultTrifectaWindow = 60 * time.Second

// NewEngine constructs an Engine from cfg, applying any Options. Clock and
// Sink are required (ErrNilClock / ErrNilSink); Notifier defaults to
// NopNotifier when nil.
func NewEngine(cfg Config, opts ...Option) (*Engine, error) {
	if cfg.Clock == nil {
		return nil, ErrNilClock
	}
	if cfg.Sink == nil {
		return nil, ErrNilSink
	}
	notifier := cfg.Notifier
	if notifier == nil {
		notifier = NopNotifier{}
	}

	e := &Engine{
		clock:    cfg.Clock,
		sink:     cfg.Sink,
		notifier: notifier,

		newDomain:     newNewDomainRule(),
		sensitiveRead: newSensitiveReadRule(),
		escape:        newEscapePassthroughRule(),
		burst:         newBurstRule(defaultBurstThreshold, defaultBurstWindow),

		nextIdx: make(map[string]uint64),

		trifectaWindow:       defaultTrifectaWindow,
		recentSensitiveReads: make(map[string][]trifectaEvent),
		recentNewDomains:     make(map[string][]trifectaEvent),
		correlated:           make(map[string]map[string]bool),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
}

// Observe feeds one already-persisted schema.Event through every rule. seg
// is the segment index to stamp on any alert.* event this call synthesizes
// — mirroring internal/collector.Enricher's EnrichXxx(rec, seg) shape,
// Engine does not decide segment assignment itself (that's the ledger
// writer's concern); callers pass through whatever segment was open for
// the triggering event.
//
// Observe returns an error only if the Sink fails to accept a synthesized
// alert (a real persistence failure the caller must know about). A
// Notifier failure is always best-effort and never returned from Observe —
// see Notifier's doc comment.
func (e *Engine) Observe(ev schema.Event, seg uint64) error {
	var fires []firing

	if f, ok := e.newDomain.check(ev); ok {
		fires = append(fires, f)
	}
	if f, ok := e.sensitiveRead.check(ev); ok {
		fires = append(fires, f)
	}
	if f, ok := e.escape.check(ev); ok {
		fires = append(fires, f)
	}
	if f, ok := e.burst.check(ev, e.clock.Now()); ok {
		fires = append(fires, f)
	}

	for _, f := range fires {
		if f.synth != nil {
			alertEv := f.synth(ev.Session, seg, e.nextIdxFor(ev.Session), ev.TsMono, ev.TsWall, ev.Pid)
			if err := e.sink(alertEv); err != nil {
				return fmt.Errorf("alerts: sink rejected %s event: %w", alertEv.Type, err)
			}
			if err := e.correlateTrifecta(alertEv, seg); err != nil {
				return err
			}
		}
		// Best-effort notification: never propagated, never blocks, never
		// retried (Notifier contract + P2-adjacent discipline — alerting is
		// enrichment, not a gate, and must not be able to wedge the
		// pipeline it observes).
		_ = e.notifier.Notify(f.title, f.body)
	}

	return nil
}

// correlateTrifecta implements the D9 "trifecta precursor" correlation:
// when a sensitive_read and a new_domain (first-contact egress) occur in
// the same session within e.trifectaWindow, in either order, it synthesizes
// an escalated alert.sensitive_read carrying additive Data
// (exfil_precursor=true, correlated_host, severity=high) alongside — never
// instead of — the original, unmodified alert already sunk by the caller
// (the ledger is append-only; there is no in-place annotation, P4/CLAUDE.md
// §3.4). alertEv is the alert.* event Observe just emitted; only
// alert.sensitive_read and alert.new_domain are relevant here.
func (e *Engine) correlateTrifecta(alertEv schema.Event, seg uint64) error {
	now := e.clock.Now()
	cutoff := now.Add(-e.trifectaWindow)

	switch alertEv.Type {
	case schema.EventTypeAlertSensitiveRead:
		path, _ := alertEv.Data["path"].(redact.Redacted)
		rule, _ := alertEv.Data["rule"].(redact.Redacted)
		read := trifectaEvent{
			idx:  alertEv.Idx,
			at:   now,
			key:  fmt.Sprintf("%s|%s", path, rule),
			path: path,
			rule: rule,
			pid:  alertEv.Pid,
		}
		e.recentSensitiveReads[alertEv.Session] = pruneTrifecta(append(e.recentSensitiveReads[alertEv.Session], read), cutoff)

		// Correlate against every still-in-window new_domain already seen
		// in this session (handles "new_domain then sensitive_read").
		// inWindowTrifecta (not pruneTrifecta): this is a read-only look at
		// the *other* side's list — correlateTrifecta does not own its
		// eviction bookkeeping here, so it must not compact in place.
		for _, domain := range inWindowTrifecta(e.recentNewDomains[alertEv.Session], cutoff) {
			if err := e.emitTrifectaEscalation(alertEv.Session, seg, alertEv.TsMono, alertEv.TsWall, read, domain); err != nil {
				return err
			}
		}

	case schema.EventTypeAlertNewDomain:
		qname, _ := alertEv.Data["qname"].(redact.Redacted)
		domain := trifectaEvent{
			idx:  alertEv.Idx,
			at:   now,
			key:  string(qname),
			host: qname,
			pid:  alertEv.Pid,
		}
		e.recentNewDomains[alertEv.Session] = pruneTrifecta(append(e.recentNewDomains[alertEv.Session], domain), cutoff)

		// Correlate against every still-in-window sensitive_read already
		// seen in this session (handles "sensitive_read then new_domain").
		// inWindowTrifecta (not pruneTrifecta): read-only look at the other
		// side's list, see the comment on the mirror-image loop above.
		for _, read := range inWindowTrifecta(e.recentSensitiveReads[alertEv.Session], cutoff) {
			if err := e.emitTrifectaEscalation(alertEv.Session, seg, alertEv.TsMono, alertEv.TsWall, read, domain); err != nil {
				return err
			}
		}
	}
	return nil
}

// pruneTrifecta returns events from evs whose retained timestamp is at or
// after cutoff (inclusive — the trifecta window boundary is closed, matching
// how burstRule's sliding window treats its own edge via time.After on the
// complement). It filters in place (reusing evs's backing array) and is
// safe ONLY when the caller immediately writes the returned slice back to
// wherever evs came from (as correlateTrifecta's own-side writeback calls
// do) — see inWindowTrifecta for the non-destructive alternative used by
// read-only callers.
func pruneTrifecta(evs []trifectaEvent, cutoff time.Time) []trifectaEvent {
	kept := evs[:0]
	for _, e := range evs {
		if !e.at.Before(cutoff) {
			kept = append(kept, e)
		}
	}
	return kept
}

// inWindowTrifecta returns a NEW slice containing the events from evs whose
// retained timestamp is at or after cutoff, without mutating evs's backing
// array. Unlike pruneTrifecta, this is safe to call when the result is
// merely iterated and not written back — correlateTrifecta's
// cross-correlation loops read the *other* side's retained list purely to
// find candidates and never own that side's eviction bookkeeping, so they
// must not reuse pruneTrifecta's in-place compaction: doing so on a
// discarded result still corrupts the caller's stored slice in place
// (evs[:0] shares evs's backing array), silently duplicating tail entries
// into slots the owning map still considers live.
func inWindowTrifecta(evs []trifectaEvent, cutoff time.Time) []trifectaEvent {
	var kept []trifectaEvent
	for _, e := range evs {
		if !e.at.Before(cutoff) {
			kept = append(kept, e)
		}
	}
	return kept
}

// emitTrifectaEscalation synthesizes and sinks one escalated
// alert.sensitive_read for the (read, domain) pairing, unless that exact
// pairing has already been escalated for this session.
func (e *Engine) emitTrifectaEscalation(session string, seg uint64, tsMono, tsWall uint64, read, domain trifectaEvent) error {
	sessionPairs := e.correlated[session]
	if sessionPairs == nil {
		sessionPairs = make(map[string]bool)
		e.correlated[session] = sessionPairs
	}
	pairKey := fmt.Sprintf("%d|%d", read.idx, domain.idx)
	if sessionPairs[pairKey] {
		return nil
	}
	sessionPairs[pairKey] = true

	idx := e.nextIdxFor(session)
	escalated := schema.NewAlertSensitiveRead(session, seg, idx, tsMono, tsWall, read.pid, read.path, read.rule)
	escalated.Data["exfil_precursor"] = true
	escalated.Data["correlated_host"] = domain.host
	escalated.Data["severity"] = redact.Literal("high")

	if err := e.sink(escalated); err != nil {
		return fmt.Errorf("alerts: sink rejected escalated %s event: %w", escalated.Type, err)
	}
	_ = e.notifier.Notify(
		"RanA: possible exfiltration precursor",
		fmt.Sprintf("sensitive read %s correlated with new destination %s", read.path, domain.host),
	)
	return nil
}

// nextIdxFor returns and advances the next monotonic Idx for session, for
// synthesized alert events. Independent of whatever Idx sequence the
// triggering events themselves use — alert events are a distinct append
// stream from the svc's point of view (CONTRACTS: Engine only consumes
// events, it does not own the ledger's idx allocation for non-alert
// types).
func (e *Engine) nextIdxFor(session string) uint64 {
	idx := e.nextIdx[session]
	e.nextIdx[session] = idx + 1
	return idx
}

// firing is what a rule's check returns when it decides to fire: enough
// information for Observe to (optionally) synthesize an alert.* event and
// always deliver a best-effort notification.
type firing struct {
	// synth builds the alert.* event, if this rule synthesizes a new event
	// (new_domain, sensitive_read, burst). nil for passthrough rules
	// (cgroup_escape, escape_precursor) whose triggering event already IS
	// the alert.* event.
	synth func(session string, seg, idx, tsMono, tsWall uint64, pid uint32) schema.Event
	title string
	body  string
}
