package alerts

import (
	"errors"
	"fmt"
	"time"

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

// Engine is RanA's alert rules engine (plan §4.3 alert.*, plan Phase 5,
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
}

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
		}
		// Best-effort notification: never propagated, never blocks, never
		// retried (Notifier contract + P2-adjacent discipline — alerting is
		// enrichment, not a gate, and must not be able to wedge the
		// pipeline it observes).
		_ = e.notifier.Notify(f.title, f.body)
	}

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
