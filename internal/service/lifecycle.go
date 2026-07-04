package service

import (
	"fmt"

	"github.com/RNT56/RanA/internal/profile"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// StartMarkerListener binds and serves the profile's marker socket, if
// cfg.Profile.Markers.Enabled. It is a caller error to call this when the
// profile does not enable markers (ErrMarkersDisabled) or when
// cfg.MarkerSocket/cfg.MarkerToken were not supplied. Every accepted,
// validated marker event is appended, published to the live tail, and
// observed by the alert engine — the same post-persist path kernel events
// take.
func (s *Service) StartMarkerListener() error {
	if !s.cfg.Profile.Markers.Enabled {
		return ErrMarkersDisabled
	}

	ln, err := NewMarkerListener(MarkerListenerConfig{
		SocketPath: s.cfg.MarkerSocket,
		Token:      s.cfg.MarkerToken,
		Profile:    s.cfg.Profile.Markers,
		Pipeline:   s.pipeline,
		Session:    s.cfg.Session,
		Clock:      s.clock,
		Emit:       s.emitMarker,
	})
	if err != nil {
		return fmt.Errorf("service: starting marker listener: %w", err)
	}
	s.markerLn = ln

	go func() {
		_ = ln.Serve()
	}()
	return nil
}

// emitMarker is MarkerListener's Emit callback: it re-stamps the event
// with svc's own idx sequence (the MarkerListener's internal counter is
// per-connection and starts at 1 each time, which is fine for building the
// event but not authoritative for ledger ordering — svc owns Idx
// allocation for every event it originates, see idx.go) and runs it
// through the same appendKernelEvent-shaped path (persist, publish,
// observe) markers share with kernel events for alerting purposes, even
// though markers are never load-bearing (P1) — a marker CAN still be the
// trigger for e.g. a future marker-aware alert rule.
func (s *Service) emitMarker(ev schema.Event) error {
	ev.Idx = s.nextIdx(ev.Session)
	if err := s.appendAndPublish(ev); err != nil {
		return s.reportFault(err)
	}
	return s.reportFault(s.alertEngine.Observe(ev, ev.Seg))
}

// reportFault surfaces err (if non-nil) to cfg.OnFault before returning it, so
// a failure on the marker or digest ingress is loud (P5) even though those
// callers (the marker listener, the digest worker) intentionally discard the
// returned error to keep going. Mirrors the kernel-event path, which reaches
// OnFault via RanadServer.OnDecodeError. Returns err unchanged.
func (s *Service) reportFault(err error) error {
	if err != nil && s.cfg.OnFault != nil {
		s.cfg.OnFault(err)
	}
	return err
}

// StartDigestWorker builds and runs a DigestWorker over the profile's
// [digest] scopes (with $SESSION_CWD already expanded against
// cfg.SessionCWD) until stop (returned) is closed via Service.Close. A
// profile with no digest scopes configured still starts a worker — it will
// simply never match anything, which is cheap and keeps the code path
// uniform rather than special-casing "no scopes" as "no worker" (a caller
// who wants to skip it entirely for a session with SessionCWD == "" and an
// empty [digest] table is free to simply not call this).
func (s *Service) StartDigestWorker() error {
	scopes := profile.ExpandSessionCWDAll(s.cfg.Profile.Digest.Scopes, s.cfg.SessionCWD)
	exclude := profile.ExpandSessionCWDAll(s.cfg.Profile.Digest.Exclude, s.cfg.SessionCWD)

	w, err := NewDigestWorker(DigestWorkerConfig{
		Scopes:           scopes,
		Exclude:          exclude,
		Session:          s.cfg.Session,
		Pipeline:         s.pipeline,
		Clock:            s.clock,
		DebounceInterval: s.cfg.DigestDebounceInterval,
		Emit:             s.emitDigest,
	})
	if err != nil {
		return fmt.Errorf("service: starting digest worker: %w", err)
	}
	s.digest = w
	s.digestStop = make(chan struct{})

	// Register the first tick synchronously, BEFORE the goroutine starts, then
	// hand it to RunFrom. If we used `go w.Run(...)` the first Clock.After call
	// would run inside the goroutine, so a test that advances a fakeClock
	// immediately after StartDigestWorker returns could fire before any timer
	// is armed and silently lose the wakeup (see DigestWorker.Run's doc
	// comment; this mirrors internal/ledger.Writer's constructor).
	firstTick := s.clock.After(w.cfg.DebounceInterval)
	go w.RunFrom(s.digestStop, firstTick)
	return nil
}

// emitDigest is DigestWorker's Emit callback: stamps svc's own Idx and
// runs the same persist+publish+observe path as emitMarker.
func (s *Service) emitDigest(ev schema.Event) error {
	ev.Idx = s.nextIdx(ev.Session)
	if err := s.appendAndPublish(ev); err != nil {
		return s.reportFault(err)
	}
	return s.reportFault(s.alertEngine.Observe(ev, ev.Seg))
}

// EmitSessionStart appends a session.start event (svc-origin,
// docs/ARCHITECTURE.md §3: "Write session.start (profile, host
// fingerprint..., adopt caveats)"). Callers supply already-redacted
// argv/profile-name/adopt-caveat values (svc's own process-launch argv is
// captured data like any other, per P3).
func (s *Service) EmitSessionStart(profileName redact.Redacted, argv []redact.Redacted, host map[string]any, adoptCaveats []redact.Redacted) error {
	idx := s.nextIdx(s.cfg.Session)
	now := s.clock.Now()
	ev := schema.NewSessionStart(s.cfg.Session, 0, idx, uint64(now.UnixNano()), uint64(now.UnixNano()), 0,
		profileName, argv, host, adoptCaveats)
	return s.appendAndPublish(ev)
}

// EmitSessionEnd appends a session.end event and forces a final seal
// (docs/ARCHITECTURE.md §3: "End on scope-empty or `rana stop`;
// session.end seals the final segment and writes a checkpoint").
func (s *Service) EmitSessionEnd() error {
	idx := s.nextIdx(s.cfg.Session)
	now := s.clock.Now()
	ev := schema.NewSessionEnd(s.cfg.Session, 0, idx, uint64(now.UnixNano()), uint64(now.UnixNano()), 0)
	if err := s.appendAndPublish(ev); err != nil {
		return err
	}
	if err := s.writer.SealSession(s.cfg.Session); err != nil {
		return err
	}
	// Tell ranad the session is over so it releases that session's per-session
	// collector state (governor/segment/exe-provenance maps). Best-effort and
	// after the seal, so a dropped signal never affects the persisted record —
	// only how promptly ranad reclaims memory (BroadcastSessionEnd's contract).
	s.ranadServer.BroadcastSessionEnd(s.cfg.Session)
	return nil
}
