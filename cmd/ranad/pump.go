// Package main implements ranad, RanA's privileged Linux collector daemon
// (CONTRACTS §cmd/ranad, docs/ARCHITECTURE.md §2).
//
// This file (pump.go) holds the orchestration logic — decode a raw kernel
// record, enrich it into a schema.Event, redact every captured string
// (already done inside Enricher, which only ever hands back
// redact.Redacted-shaped Data), pass it through the governor, and frame it
// for the svc unix socket — as a PORTABLE core with no build tag. It talks
// only to a RecordSource and a FrameSink interface, both fakeable, so the
// whole pump is unit-testable on darwin (CONTRACTS: "Structure so the
// orchestration logic... is in a PORTABLE function tested on darwin with a
// fake ringbuf source and a fake socket; the bpf attach is the only
// linux-gated part").
//
// P2 (observation is inert) applies here too: nothing in this file can
// block, delay meaningfully, or modify a syscall — it only ever reads
// already-captured kernel records handed to it by a RecordSource and moves
// bytes onward. If ranad dies, nothing here was in the syscall path to
// begin with.
package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/collector"
	"github.com/RNT56/RanA/internal/schema"
	"github.com/RNT56/RanA/internal/wire"
)

// RecordSource yields raw, undecoded kernel records one at a time. Next
// returns (nil, false, nil) when no record is currently available (the
// caller should stop draining for now, not treat it as an error) and
// (nil, false, err) when the source itself has failed (e.g. the ring buffer
// reader errored or the source was closed) — Drain propagates that error to
// its caller, which is expected to trigger a reconnect/gap sequence.
//
// The real linux-gated implementation wraps a cilium/ebpf ringbuf.Reader;
// tests use fakeSource, a scripted in-memory implementation.
type RecordSource interface {
	Next() (raw []byte, ok bool, err error)
}

// FrameSink sends frames to (and receives frames from) the svc unix socket.
// Send/Recv are the only two operations the pump needs; connection setup
// (Hello handshake, SO_PEERCRED check) happens once, outside this interface,
// before a Pump is handed a FrameSink.
type FrameSink interface {
	Send(wire.Frame) error
	Recv() (wire.Frame, error)
	Close() error
}

// recordClass maps a decoded record's Go type to the collector.EventClass
// the governor should account it under (CONTRACTS §internal/collector /
// the D14 frozen never-shed set and shed order). Session-lifecycle and
// gap events are constructed directly by ranad (not decoded from a kernel
// record) and are stamped with their classes at the call site instead of
// through this table.
func recordClass(rec any) (collector.EventClass, error) {
	switch rec.(type) {
	case collector.ExecRecord:
		return collector.ClassExec, nil
	case collector.ForkRecord, collector.ExitRecord:
		return collector.ClassForkExit, nil
	case collector.FsOpRecord:
		fsRec := rec.(collector.FsOpRecord)
		if fsRec.Op == collector.FsOpWriteOpen {
			return collector.ClassFsWriteOpen, nil
		}
		return collector.ClassFsMeta, nil
	case collector.ConnectRecord, collector.SendmsgRecord, collector.UnixConnectRecord:
		return collector.ClassConnect, nil
	case collector.FlowCloseRecord, collector.DNSRecord:
		return collector.ClassFlowDNS, nil
	case collector.MigrationRecord:
		// cgroup escape is a security-relevant alert; treat it as never-shed
		// like the rest of the never-shed set rather than folding it into an
		// arbitrary sheddable tier (D14 doesn't name migration explicitly,
		// but "session.*"-adjacent security signals belong with the
		// never-shed class in spirit — see final report for this
		// interpretation flagged as a contract ambiguity).
		return collector.ClassSession, nil
	default:
		return 0, fmt.Errorf("ranad: unrecognized decoded record type %T", rec)
	}
}

// segTracker assigns a monotonically increasing, per-session segment index
// to every event this pump enriches, mirroring the sealing policy in
// docs/TRUST.md §3 (4096 events or 60s after the segment's first event,
// whichever first). ev.Seg is part of the canonical, already-hashed event
// bytes by the time it reaches internal/ledger's writer (writer_loop.go:
// "ev.Seg (part of the canonical, already-hashed event bytes)... " is
// treated as authoritative, never recomputed downstream) — so whichever
// process stamps Seg first owns getting this policy right. Since ranad is
// the first process to build a schema.Event from kernel data (the v1 event
// schema; docs/ARCHITECTURE.md §2's decode->enrich->redact->govern step happens in
// ranad, upstream of svc's ledger writer), it must track sealing here.
//
// This does not duplicate internal/ledger's own segment *sealing* (Merkle
// root computation, chain hashing, checkpoint signing all still happen
// exactly once, in the ledger writer) — it only decides which seg index a
// given event belongs to, the same way a sequence generator hands out
// ticket numbers without owning what happens at each ticket.
type segTracker struct {
	mu         sync.Mutex
	clock      collector.Clock
	maxEvents  uint64
	maxAge     time.Duration
	perSession map[string]*segState
}

type segState struct {
	seg       uint64
	count     uint64
	firstEvAt time.Time
}

func newSegTracker(clock collector.Clock) *segTracker {
	return &segTracker{
		clock:      clock,
		maxEvents:  4096,
		maxAge:     60 * time.Second,
		perSession: make(map[string]*segState),
	}
}

// Current returns the seg index the next event for session should be
// stamped with, advancing to a new segment first if the current one has
// reached its event/age bound.
func (t *segTracker) Current(session string) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.clock.Now()
	st, ok := t.perSession[session]
	if !ok {
		st = &segState{seg: 0, count: 0, firstEvAt: now}
		t.perSession[session] = st
	}
	if st.count == 0 {
		st.firstEvAt = now
	}
	if st.count >= t.maxEvents || (st.count > 0 && now.Sub(st.firstEvAt) >= t.maxAge) {
		st.seg++
		st.count = 0
		st.firstEvAt = now
	}
	st.count++
	return st.seg
}

// EndSession drops per-session segment-tracking state (session end /
// cgroup teardown), mirroring Governor.EndSession's cleanup so a long-lived
// ranad does not retain unbounded per-session state.
func (t *segTracker) EndSession(session string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.perSession, session)
}

// PumpConfig configures a Pump. All fields are required.
type PumpConfig struct {
	// Source yields raw kernel records (real: ringbuf; test: fakeSource).
	Source RecordSource
	// Sink sends/receives wire frames to/from the svc unix socket (real: a
	// net.UnixConn-backed adapter; test: fakeSink).
	Sink FrameSink
	// Enricher turns decoded records into redacted schema.Event values.
	Enricher *collector.Enricher
	// Governor admits/sheds events per the frozen never-shed/shed-order
	// policy and accounts every shed for FlushGaps.
	Governor *collector.Governor
	// Clock supplies "now" for segment tracking and gap timestamps.
	// Injectable for deterministic tests.
	Clock collector.Clock
	// HeadsLogDir is the directory (must already exist — ranad's setup
	// creates the root-owned data dir before constructing a Pump) that
	// heads.log lives under (docs/TRUST.md §5: "root-owned,
	// append-only heads.log").
	HeadsLogDir string
	// DNSJoinWindow bounds how recently a net.dns answer must have been
	// observed to be joined into a net.connect event (the v1 event schema). Defaults
	// to 30s if zero.
	DNSJoinWindow time.Duration
}

// Pump wires one RecordSource to one FrameSink through decode -> enrich ->
// (redact, inside Enricher) -> govern -> frame (CONTRACTS §cmd/ranad). It
// also owns the reverse direction: receiving Head frames from svc and
// mirroring them into the root-owned heads.log (the D27 mirror write).
type Pump struct {
	source   RecordSource
	sink     FrameSink
	enricher *collector.Enricher
	governor *collector.Governor
	clock    collector.Clock
	seg      *segTracker

	headsLogDir   string
	dnsJoinWindow time.Duration

	// endedMu guards endedSessions: session ids received via a
	// wire.SessionEnd frame on the inbound goroutine (PumpInbound) but drained
	// and acted on by the outbound goroutine (DrainEndedSessions), so the
	// governor's final-gap frame is built and sent from the same goroutine
	// that owns Sink.Send (never racing the inbound reader).
	endedMu       sync.Mutex
	endedSessions []string
}

// NewPump constructs a Pump from cfg.
func NewPump(cfg PumpConfig) *Pump {
	window := cfg.DNSJoinWindow
	if window == 0 {
		window = 30 * time.Second
	}
	return &Pump{
		source:        cfg.Source,
		sink:          cfg.Sink,
		enricher:      cfg.Enricher,
		governor:      cfg.Governor,
		clock:         cfg.Clock,
		seg:           newSegTracker(cfg.Clock),
		headsLogDir:   cfg.HeadsLogDir,
		dnsJoinWindow: window,
	}
}

// Sink exposes the underlying FrameSink (used by ranad's reconnect path to
// send a daemon_restart gap frame built by ReconnectGap).
func (p *Pump) Sink() FrameSink { return p.sink }

// HeadsLogPath returns the path AppendHead/ReadHeads operate on.
func (p *Pump) HeadsLogPath() string {
	return filepath.Join(p.headsLogDir, "heads.log")
}

// ErrNoMoreFrames is the sentinel a FrameSink.Recv implementation returns
// to signal "nothing available right now" (as opposed to a genuine
// connection failure). The production adapter over a real net.UnixConn
// wraps this around a non-blocking read that found nothing pending;
// PumpInbound treats any error wrapping ErrNoMoreFrames as a clean stop
// rather than a fatal error.
var ErrNoMoreFrames = errors.New("ranad: no more frames available")

// ErrUnrecognizedRecord is returned (wrapped) when DecodeRecord succeeds
// but recordClass doesn't know the decoded type — should be unreachable in
// practice since every collector.RecordKindXxx maps to exactly one class,
// but guarded rather than panicking (a malformed/future record kind must
// never crash the daemon over one bad record).
var ErrUnrecognizedRecord = errors.New("ranad: record decoded to an unrecognized type")

// Drain pulls every record currently available from Source and pushes each
// one through decode -> enrich -> govern -> Sink.Send, returning the number
// of records read from Source (including ones skipped due to a decode
// error, an unknown-cgid record, or a governor shed — all of which are
// non-fatal and simply produce no frame) and stopping either when Source
// reports no more records available right now (ok=false, err=nil) or when
// Source/Sink return a genuine error, which Drain propagates unwrapped-ish
// (via %w) so callers can decide on reconnect policy.
//
// A malformed record (DecodeRecord error) or a record for a cgid this
// ranad has no session binding for (collector.ErrUnknownCgid — expected
// only defensively, since D6's in-kernel filtering should prevent foreign
// cgroups from reaching the ring buffer at all) is skipped, not fatal:
// P2/P5 require ranad to keep recording everything it can even when one
// record is bad, and to never let one malformed record take down the whole
// pump.
func (p *Pump) Drain() (int, error) {
	n := 0
	for {
		raw, ok, err := p.source.Next()
		if err != nil {
			return n, fmt.Errorf("ranad: record source: %w", err)
		}
		if !ok {
			return n, nil
		}
		n++

		if err := p.processRecord(raw); err != nil {
			// Only a Sink.Send failure is fatal to the drain loop (the
			// connection is presumed broken; the caller reconnects and
			// emits a daemon_restart gap). A decode failure, an
			// unknown-cgid record, or an unrecognized record type is
			// swallowed here: P2/P5 require ranad to keep recording
			// everything it can even when one record is bad, and never let
			// one malformed record take down the whole pump.
			if errors.Is(err, errSinkSendFailed) {
				return n, err
			}
		}
	}
}

// errSinkSendFailed marks a processRecord error as originating from
// Sink.Send (fatal to Drain), distinguishing it from every other
// processRecord error (decode/enrich failures, swallowed by Drain).
var errSinkSendFailed = errors.New("ranad: sink send failed")

// processRecord decodes one raw record, enriches it, governs it, and sends
// it. Returns a non-nil error for decode/enrich failures (swallowed by
// Drain) or an error wrapping errSinkSendFailed for a Send failure
// (propagated by Drain).
func (p *Pump) processRecord(raw []byte) error {
	decoded, err := collector.DecodeRecord(raw)
	if err != nil {
		return fmt.Errorf("ranad: decode record: %w", err)
	}

	class, err := recordClass(decoded)
	if err != nil {
		return err
	}

	ev, session, err := p.enrich(decoded)
	if err != nil {
		return fmt.Errorf("ranad: enrich record: %w", err)
	}

	if !p.governor.Admit(session, class) {
		return nil // shed: accounted by the governor, no error, no frame
	}

	return p.frameAndSend(ev)
}

// enrich dispatches decoded to the matching Enricher.EnrichXxx call,
// stamping Seg from this Pump's segTracker. Returns the session id
// alongside the event so processRecord can pass it to Governor.Admit
// without re-deriving it.
func (p *Pump) enrich(decoded any) (schema.Event, string, error) {
	switch rec := decoded.(type) {
	case collector.ExecRecord:
		session, ok := p.enricher.SessionForCgid(rec.Cgid)
		if !ok {
			return schema.Event{}, "", collector.ErrUnknownCgid
		}
		ev, err := p.enricher.EnrichExec(rec, p.seg.Current(session))
		return ev, session, err
	case collector.ForkRecord:
		session, ok := p.enricher.SessionForCgid(rec.Cgid)
		if !ok {
			return schema.Event{}, "", collector.ErrUnknownCgid
		}
		ev, err := p.enricher.EnrichFork(rec, p.seg.Current(session))
		return ev, session, err
	case collector.ExitRecord:
		session, ok := p.enricher.SessionForCgid(rec.Cgid)
		if !ok {
			return schema.Event{}, "", collector.ErrUnknownCgid
		}
		ev, err := p.enricher.EnrichExit(rec, p.seg.Current(session))
		return ev, session, err
	case collector.FsOpRecord:
		session, ok := p.enricher.SessionForCgid(rec.Cgid)
		if !ok {
			return schema.Event{}, "", collector.ErrUnknownCgid
		}
		ev, err := p.enricher.EnrichFsOp(rec, p.seg.Current(session))
		return ev, session, err
	case collector.ConnectRecord:
		session, ok := p.enricher.SessionForCgid(rec.Cgid)
		if !ok {
			return schema.Event{}, "", collector.ErrUnknownCgid
		}
		ev, err := p.enricher.EnrichConnect(rec, p.seg.Current(session), p.dnsJoinWindow)
		return ev, session, err
	case collector.SendmsgRecord:
		session, ok := p.enricher.SessionForCgid(rec.Cgid)
		if !ok {
			return schema.Event{}, "", collector.ErrUnknownCgid
		}
		ev, err := p.enricher.EnrichSendmsg(rec, p.seg.Current(session), p.dnsJoinWindow)
		return ev, session, err
	case collector.UnixConnectRecord:
		session, ok := p.enricher.SessionForCgid(rec.Cgid)
		if !ok {
			return schema.Event{}, "", collector.ErrUnknownCgid
		}
		ev, err := p.enricher.EnrichUnixConnect(rec, p.seg.Current(session))
		return ev, session, err
	case collector.FlowCloseRecord:
		session, ok := p.enricher.SessionForCgid(rec.Cgid)
		if !ok {
			return schema.Event{}, "", collector.ErrUnknownCgid
		}
		ev, err := p.enricher.EnrichFlowClose(rec, p.seg.Current(session))
		return ev, session, err
	case collector.DNSRecord:
		session, ok := p.enricher.SessionForCgid(rec.Cgid)
		if !ok {
			return schema.Event{}, "", collector.ErrUnknownCgid
		}
		ev, err := p.enricher.EnrichDNS(rec, p.seg.Current(session))
		return ev, session, err
	case collector.MigrationRecord:
		// EnrichMigration resolves its own session attribution (from- or
		// to-side, whichever is known); seg is stamped against whichever
		// session ends up attributed, which EnrichMigration doesn't expose
		// ahead of time. We resolve it the same way it does, defensively.
		fromSession, fromOK := p.enricher.SessionForCgid(rec.FromCgid)
		toSession, toOK := p.enricher.SessionForCgid(rec.ToCgid)
		if !fromOK && !toOK {
			return schema.Event{}, "", collector.ErrUnknownCgid
		}
		attributed := fromSession
		if !fromOK {
			attributed = toSession
		}
		ev, err := p.enricher.EnrichMigration(rec, p.seg.Current(attributed))
		return ev, attributed, err
	default:
		return schema.Event{}, "", fmt.Errorf("%w: %T", ErrUnrecognizedRecord, decoded)
	}
}

// frameAndSend canonically encodes ev and sends it as a wire.Ev frame,
// wrapping a Send failure so it carries errSinkSendFailed and Drain treats
// it as fatal.
func (p *Pump) frameAndSend(ev schema.Event) error {
	body, err := cborcanon.EncodeEvent(ev)
	if err != nil {
		return fmt.Errorf("ranad: encode event: %w", err)
	}
	if err := p.sink.Send(&wire.Ev{Event: body}); err != nil {
		return fmt.Errorf("%w: %w", errSinkSendFailed, err)
	}
	return nil
}

// FlushGaps closes the governor's current shed interval and returns one
// wire.Ev frame per resulting gap (P5: "Ring-buffer drops, governor sheds,
// daemon restarts MUST each produce a first-class gap event inside the
// chain, with counts and reason"). It does not send the frames — the
// caller decides when/how (ranad's main loop calls this on a ticker and
// sends each frame through the same Sink used by Drain).
func (p *Pump) FlushGaps() []wire.Frame {
	records := p.governor.FlushGaps()
	if len(records) == 0 {
		return nil
	}
	frames := make([]wire.Frame, 0, len(records))
	for _, r := range records {
		idx := p.seg.Current(r.Session)
		ev := schema.NewGap(r.Session, idx, idx, r.FromNs, r.ToNs, 0, r.Reason, r.Counts, r.FromNs, r.ToNs)
		body, err := cborcanon.EncodeEvent(ev)
		if err != nil {
			// A gap event that fails to encode must still be surfaced
			// somehow rather than silently vanishing (P5) — but
			// cborcanon.EncodeEvent can only fail here on a programmer
			// error in schema.NewGap's Data shape, which a test would
			// catch; there is no meaningful fallback frame to send instead,
			// so we skip this one gap record and continue with the rest
			// rather than losing all of them over one encode failure.
			continue
		}
		frames = append(frames, &wire.Ev{Event: body})
	}
	return frames
}

// DrainEndedSessions releases the per-session collector state for every
// session ranad has been told (via a wire.SessionEnd frame) has ended:
// governor rate-limit buckets, the segment tracker, and the Enricher's
// exe-provenance seen-map. Without this, a long-lived ranad accumulates one
// such set of state per session it ever observed (an unbounded, if slow,
// memory growth). It is called by ranad's outbound loop — the goroutine that
// owns Sink.Send — so that any final gap the governor surfaces on eviction
// (un-flushed sheds from the session's last interval, P5) is returned here as
// a wire.Ev frame for that same loop to send, never lost and never written
// from the inbound goroutine. Returns nil frames when nothing was pending.
func (p *Pump) DrainEndedSessions() []wire.Frame {
	p.endedMu.Lock()
	ended := p.endedSessions
	p.endedSessions = nil
	p.endedMu.Unlock()
	if len(ended) == 0 {
		return nil
	}

	var frames []wire.Frame
	for _, session := range ended {
		if final := p.governor.EndSession(session); final != nil {
			idx := p.seg.Current(session)
			ev := schema.NewGap(session, idx, idx, final.FromNs, final.ToNs, 0, final.Reason, final.Counts, final.FromNs, final.ToNs)
			if body, err := cborcanon.EncodeEvent(ev); err == nil {
				frames = append(frames, &wire.Ev{Event: body})
			}
		}
		// Evict the remaining per-session state (safe map deletes). Order
		// matters only in that the governor's final gap uses seg.Current
		// above, so seg is evicted after.
		p.seg.EndSession(session)
		p.enricher.EndSession(session)
	}
	return frames
}

// ReconnectGap builds (but does not send) a gap{daemon_restart} frame for
// session, using this Pump's Clock for the "resumed at" timestamp
// (CONTRACTS §cmd/ranad: "on reconnect emit gap{daemon_restart}"). fromNs
// is left as the caller's last-known-good timestamp if they have one;
// ReconnectGap itself only knows "now", so callers that track a better
// fromNs (e.g. the last successfully processed record's ts_mono) should
// build the schema.Event directly via schema.NewGap instead — this helper
// covers the common case where ranad has no better information at process
// start than "recording resumed now".
func (p *Pump) ReconnectGap(session string) (wire.Frame, error) {
	now := uint64(p.clock.Now().UnixNano())
	idx := p.seg.Current(session)
	ev := schema.NewGap(session, idx, idx, now, now, 0, string(schema.GapReasonDaemonRestart), map[string]uint64{}, now, now)
	body, err := cborcanon.EncodeEvent(ev)
	if err != nil {
		return nil, fmt.Errorf("ranad: encode daemon_restart gap: %w", err)
	}
	return &wire.Ev{Event: body}, nil
}

// PumpInbound drains every frame currently available from Sink.Recv,
// dispatching Head frames to the root-owned heads.log via
// chain.AppendHead ("this IS the D27 mirror write, the one
// root-privileged write") and ignoring other frame kinds (Hello/Bye are
// handled by the connection-setup code that constructs the Sink, not by
// the steady-state pump). Returns the number of frames read, stopping when
// Sink.Recv reports errNoMoreFrames-equivalent (no frame currently
// available) — real implementations signal this the same way Drain's
// RecordSource does, via a (nil, err) that the caller's reconnect loop
// interprets, so PumpInbound simply propagates whatever error Recv
// returns once it has nothing left to report; callers distinguish "drained
// cleanly for now" from "connection broken" the same way they already must
// for Drain.
func (p *Pump) PumpInbound() (int, error) {
	n := 0
	for {
		f, err := p.sink.Recv()
		if err != nil {
			if isNoMoreFrames(err) {
				return n, nil
			}
			return n, err
		}
		n++
		if se, ok := f.(*wire.SessionEnd); ok {
			// Queue for the outbound goroutine to act on (see endedSessions'
			// doc comment): evicting the governor there lets its final gap be
			// sent on the goroutine that owns Sink.Send.
			p.endedMu.Lock()
			p.endedSessions = append(p.endedSessions, se.Session)
			p.endedMu.Unlock()
			continue
		}
		head, ok := f.(*wire.Head)
		if !ok {
			continue
		}
		report := chain.HeadReport{
			SessionID: head.Report.SessionID,
			SegLast:   head.Report.SegLast,
			ChainHead: head.Report.ChainHead,
			CkptHash:  head.Report.CkptHash,
			At:        head.Report.At,
		}
		if err := chain.AppendHead(p.HeadsLogPath(), report); err != nil {
			return n, fmt.Errorf("ranad: appending head report to heads.log: %w", err)
		}
	}
}

// isNoMoreFrames reports whether err is the sentinel a FrameSink.Recv
// implementation uses to signal "nothing available right now" rather than
// a genuine connection failure. The production adapter over a real
// net.UnixConn distinguishes these the same way wire.ReadFrame does (a
// clean io.EOF vs a torn-frame/other error); PumpInbound treats any
// errNoMoreFrames-wrapping error as the clean case.
func isNoMoreFrames(err error) bool {
	return errors.Is(err, ErrNoMoreFrames)
}
