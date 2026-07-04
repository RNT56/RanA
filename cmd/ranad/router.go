package main

import "sync"

// EventRouter selects which svc FrameSink an event (or a session-scoped gap)
// is delivered to, keyed by the uid that owns the event's session. It is the
// seam that makes ranad multi-user-capable without the per-event send path
// hard-coding a single connection:
//
//   - A per-user deployment (one ranad, one svc, the D10 default) uses
//     SingleUserRouter, which returns the one sink for every uid.
//   - A system-wide root ranad feeding several users' session services uses
//     MultiUserRouter, which maps each owner uid to that user's svc
//     connection, so one user's events are NEVER delivered to another user's
//     svc. An event whose uid has no registered sink is dropped by the caller
//     and accounted as a gap — misdelivery to the wrong user is not possible
//     by construction (SinkFor returns ok=false rather than a fallback sink).
//
// The routing DECISION is pure and unit-tested here; the system-wide daemon
// wiring that registers one sink per connected user's svc (per-uid socket
// discovery + SO_PEERCRED validation, the multi-connection connect/inbound
// loop) is documented in docs/MULTIUSER.md.
type EventRouter interface {
	// SinkFor returns the sink for the given owner uid and whether one is
	// registered. A false ok means "no svc for this uid" — the caller drops
	// the frame and accounts a gap; it must never fall back to another uid's
	// sink.
	SinkFor(uid uint32) (FrameSink, bool)
}

// SingleUserRouter routes every event to one sink regardless of uid — the
// per-user deployment where ranad talks to exactly one svc. A nil Sink yields
// ok=false (no destination), matching the multi-user "unknown uid" contract.
type SingleUserRouter struct{ Sink FrameSink }

// SinkFor returns the single sink for any uid.
func (r SingleUserRouter) SinkFor(uint32) (FrameSink, bool) {
	return r.Sink, r.Sink != nil
}

// MultiUserRouter maps an owner uid to that user's svc sink. It is safe for
// concurrent registration and lookup: a root ranad registers a sink when it
// connects a user's svc and unregisters it when that connection drops, while
// the pump goroutine looks sinks up on the hot path.
type MultiUserRouter struct {
	mu    sync.RWMutex
	sinks map[uint32]FrameSink
}

// NewMultiUserRouter returns an empty MultiUserRouter.
func NewMultiUserRouter() *MultiUserRouter {
	return &MultiUserRouter{sinks: make(map[uint32]FrameSink)}
}

// Register associates uid with sink. A second Register for the same uid
// replaces the prior sink (a user's svc reconnected). A nil sink is treated as
// Unregister, so callers can't accidentally register a dead destination.
func (r *MultiUserRouter) Register(uid uint32, sink FrameSink) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sink == nil {
		delete(r.sinks, uid)
		return
	}
	r.sinks[uid] = sink
}

// Unregister removes uid's sink (its svc disconnected). Idempotent.
func (r *MultiUserRouter) Unregister(uid uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sinks, uid)
}

// SinkFor returns uid's registered sink, or ok=false if that user has no svc
// connected. It never returns another uid's sink.
func (r *MultiUserRouter) SinkFor(uid uint32) (FrameSink, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sinks[uid]
	return s, ok
}

// UIDs returns the uids with a registered sink (for fan-out of a daemon-wide
// frame such as a restart gap that every connected svc should see). The order
// is unspecified.
func (r *MultiUserRouter) UIDs() []uint32 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]uint32, 0, len(r.sinks))
	for uid := range r.sinks {
		out = append(out, uid)
	}
	return out
}

// compile-time assertions that both routers satisfy EventRouter.
var (
	_ EventRouter = SingleUserRouter{}
	_ EventRouter = (*MultiUserRouter)(nil)
)
