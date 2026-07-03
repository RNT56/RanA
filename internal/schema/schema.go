// Package schema defines RanA's frozen event envelope and the typed
// constructors for every event type in the v1 taxonomy (RANA-plan-v1.md
// §4.3, docs/TRUST.md §1). It has no dependency on internal/cborcanon —
// cborcanon depends on schema (for EncodeEvent), not the reverse.
//
// Every captured string that ends up in an Event's Data payload must
// already be a redact.Redacted value by the time it reaches a constructor
// here — schema does not redact, it only shapes and validates (P3 is
// enforced downstream in cborcanon.EncodeEvent, which rejects any plain
// Go string it finds in Data).
package schema

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/RNT56/RanA/internal/redact"
)

// EventType names one of RanA's event kinds. marker.* is an open,
// freeform-suffixed family (plan §4.3); every other value is a fixed,
// frozen constant.
type EventType string

// Event type constants, per CONTRACTS §internal/schema / plan §4.3.
const (
	EventTypeSessionStart EventType = "session.start"
	EventTypeSessionEnd   EventType = "session.end"

	EventTypeProcExec EventType = "proc.exec"
	EventTypeProcFork EventType = "proc.fork"
	EventTypeProcExit EventType = "proc.exit"

	EventTypeFsWriteOpen     EventType = "fs.write_open"
	EventTypeFsUnlink        EventType = "fs.unlink"
	EventTypeFsRename        EventType = "fs.rename"
	EventTypeFsMkdir         EventType = "fs.mkdir"
	EventTypeFsChmod         EventType = "fs.chmod"
	EventTypeFsTruncate      EventType = "fs.truncate"
	EventTypeFsSettle        EventType = "fs.settle"
	EventTypeFsSensitiveRead EventType = "fs.sensitive_read"

	EventTypeNetConnect   EventType = "net.connect"
	EventTypeNetDNS       EventType = "net.dns"
	EventTypeNetFlowClose EventType = "net.flow_close"
	EventTypeUnixConnect  EventType = "unix.connect"

	EventTypeAlertNewDomain       EventType = "alert.new_domain"
	EventTypeAlertSensitiveRead   EventType = "alert.sensitive_read"
	EventTypeAlertCgroupEscape    EventType = "alert.cgroup_escape"
	EventTypeAlertEscapePrecursor EventType = "alert.escape_precursor"
	EventTypeAlertBurst           EventType = "alert.burst"

	EventTypeGap EventType = "gap"

	markerPrefix = "marker."
)

// EventTypeMarker builds the EventType for a marker event given its
// freeform suffix (e.g. EventTypeMarker("openclaw.run") ==
// "marker.openclaw.run"). See also NewMarker.
func EventTypeMarker(suffix string) EventType {
	return EventType(markerPrefix + suffix)
}

// MarkerEventType is an alias of EventTypeMarker kept for readability at
// call sites that build a marker type without constructing the event yet.
func MarkerEventType(suffix string) EventType { return EventTypeMarker(suffix) }

// IsMarkerType reports whether t is in the marker.* family.
func IsMarkerType(t EventType) bool {
	return strings.HasPrefix(string(t), markerPrefix)
}

// knownNonMarkerTypes is the frozen, closed set of non-marker event types.
var knownNonMarkerTypes = map[EventType]bool{
	EventTypeSessionStart: true,
	EventTypeSessionEnd:   true,

	EventTypeProcExec: true,
	EventTypeProcFork: true,
	EventTypeProcExit: true,

	EventTypeFsWriteOpen:     true,
	EventTypeFsUnlink:        true,
	EventTypeFsRename:        true,
	EventTypeFsMkdir:         true,
	EventTypeFsChmod:         true,
	EventTypeFsTruncate:      true,
	EventTypeFsSettle:        true,
	EventTypeFsSensitiveRead: true,

	EventTypeNetConnect:   true,
	EventTypeNetDNS:       true,
	EventTypeNetFlowClose: true,
	EventTypeUnixConnect:  true,

	EventTypeAlertNewDomain:       true,
	EventTypeAlertSensitiveRead:   true,
	EventTypeAlertCgroupEscape:    true,
	EventTypeAlertEscapePrecursor: true,
	EventTypeAlertBurst:           true,

	EventTypeGap: true,
}

// Origin identifies who produced an event: the kernel (eBPF, load-bearing
// truth per P1), the session service (svc, also load-bearing for
// session/lifecycle bookkeeping it alone can see), or enrichment (agent-
// or profile-provided markers — never authoritative, P1).
type Origin string

// Origin constants.
const (
	OriginKernel     Origin = "kernel"
	OriginSVC        Origin = "svc"
	OriginEnrichment Origin = "enrichment"
)

var knownOrigins = map[Origin]bool{
	OriginKernel:     true,
	OriginSVC:        true,
	OriginEnrichment: true,
}

// State is the event lifecycle state. v1 only ever produces "observed";
// Phase G (gated/transactional mode, post-1.0) introduces
// proposed -> committed|discarded without a schema migration (plan D1).
type State string

// StateObserved is the only State value produced in v1.
const StateObserved State = "observed"

var knownStates = map[State]bool{
	StateObserved: true,
}

// PathSource records whether a filesystem event's path was resolved by the
// kernel hook itself (ground truth) or merely claimed by an enrichment
// source (never treated as kernel-equivalent — invariant 9, CLAUDE.md §6).
type PathSource string

// PathSource constants.
const (
	PathSourceResolved PathSource = "resolved"
	PathSourceClaimed  PathSource = "claimed"
)

var knownPathSources = map[PathSource]bool{
	PathSourceResolved: true,
	PathSourceClaimed:  true,
}

// GapReason is the frozen, closed set of reasons a gap event may carry
// (docs/TRUST.md §4, CONTRACTS §internal/ledger — the set is explicitly
// frozen and MUST NOT grow with ad hoc values).
type GapReason string

// GapReason constants — the complete, frozen set.
const (
	GapReasonRingbufFull   GapReason = "ringbuf_full"
	GapReasonGovernor      GapReason = "governor"
	GapReasonDaemonRestart GapReason = "daemon_restart"
)

var knownGapReasons = map[GapReason]bool{
	GapReasonRingbufFull:   true,
	GapReasonGovernor:      true,
	GapReasonDaemonRestart: true,
}

// Event is RanA's canonical event envelope (plan §4.3, docs/TRUST.md §1).
// CBOR map keys at encode time (bytewise-sorted by the encoder, listed here
// in field order for readability): v, type, session, seg, idx, ts_mono,
// ts_wall, pid, origin, state, data.
type Event struct {
	V       uint8 // schema version; 1 in v1
	Type    EventType
	Session string // session id (ULID-format string; generator injectable, see NewSessionID)
	Seg     uint64 // segment index within the session
	Idx     uint64 // monotonic index within the session
	TsMono  uint64 // CLOCK_MONOTONIC ns, captured in-kernel where applicable
	TsWall  uint64 // CLOCK_REALTIME ns, captured in-kernel where applicable
	Pid     uint32
	Origin  Origin
	State   State
	Data    map[string]any // per-type payload; string values MUST be redact.Redacted (or a typed enum constant)
}

// ---- envelope-construction helper ----

func newEnvelope(session string, seg, idx, tsMono, tsWall uint64, pid uint32, t EventType, origin Origin, data map[string]any) Event {
	return Event{
		V:       1,
		Type:    t,
		Session: session,
		Seg:     seg,
		Idx:     idx,
		TsMono:  tsMono,
		TsWall:  tsWall,
		Pid:     pid,
		Origin:  origin,
		State:   StateObserved,
		Data:    data,
	}
}

// ---- typed constructors, one per event type (CONTRACTS §internal/schema) ----

// NewSessionStart builds a session.start event (emitted by svc).
func NewSessionStart(session string, seg, idx, tsMono, tsWall uint64, pid uint32,
	profile redact.Redacted, argv []redact.Redacted, host map[string]any, adoptCaveats []redact.Redacted,
) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeSessionStart, OriginSVC, map[string]any{
		"profile":       profile,
		"argv":          argv,
		"host":          host,
		"adopt_caveats": adoptCaveats,
	})
}

// NewSessionEnd builds a session.end event (emitted by svc).
func NewSessionEnd(session string, seg, idx, tsMono, tsWall uint64, pid uint32) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeSessionEnd, OriginSVC, map[string]any{})
}

// NewProcExec builds a proc.exec event (emitted by eBPF; kernel truth, P1).
func NewProcExec(session string, seg, idx, tsMono, tsWall uint64, pid uint32,
	argv []redact.Redacted, comm, cwd, exePath redact.Redacted, ppid uint32, uid uint32,
) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeProcExec, OriginKernel, map[string]any{
		"argv":     argv,
		"comm":     comm,
		"cwd":      cwd,
		"exe_path": exePath,
		"ppid":     uint64(ppid),
		"uid":      uint64(uid),
	})
}

// NewProcFork builds a proc.fork event (emitted by eBPF).
func NewProcFork(session string, seg, idx, tsMono, tsWall uint64, pid uint32, ppid uint32) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeProcFork, OriginKernel, map[string]any{
		"ppid": uint64(ppid),
	})
}

// NewProcExit builds a proc.exit event (emitted by eBPF): exit code plus a
// rusage summary (user/system CPU time in ns).
func NewProcExit(session string, seg, idx, tsMono, tsWall uint64, pid uint32, exitCode int32, utimeNs, stimeNs uint64) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeProcExit, OriginKernel, map[string]any{
		"exit_code": int64(exitCode),
		"utime_ns":  utimeNs,
		"stime_ns":  stimeNs,
	})
}

// NewFsWriteOpen builds an fs.write_open event (emitted by eBPF).
func NewFsWriteOpen(session string, seg, idx, tsMono, tsWall uint64, pid uint32,
	path redact.Redacted, pathSource PathSource, flags uint64, mode uint64,
) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeFsWriteOpen, OriginKernel, map[string]any{
		"path":        path,
		"path_source": pathSource,
		"flags":       flags,
		"mode":        mode,
	})
}

// NewFsUnlink builds an fs.unlink event (emitted by eBPF).
func NewFsUnlink(session string, seg, idx, tsMono, tsWall uint64, pid uint32, path redact.Redacted, pathSource PathSource) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeFsUnlink, OriginKernel, map[string]any{
		"path":        path,
		"path_source": pathSource,
	})
}

// NewFsRename builds an fs.rename event (emitted by eBPF); path2 is the
// destination.
func NewFsRename(session string, seg, idx, tsMono, tsWall uint64, pid uint32, path, path2 redact.Redacted, pathSource PathSource) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeFsRename, OriginKernel, map[string]any{
		"path":        path,
		"path2":       path2,
		"path_source": pathSource,
	})
}

// NewFsMkdir builds an fs.mkdir event (emitted by eBPF).
func NewFsMkdir(session string, seg, idx, tsMono, tsWall uint64, pid uint32, path redact.Redacted, pathSource PathSource, mode uint64) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeFsMkdir, OriginKernel, map[string]any{
		"path":        path,
		"path_source": pathSource,
		"mode":        mode,
	})
}

// NewFsChmod builds an fs.chmod event (emitted by eBPF).
func NewFsChmod(session string, seg, idx, tsMono, tsWall uint64, pid uint32, path redact.Redacted, pathSource PathSource, mode uint64) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeFsChmod, OriginKernel, map[string]any{
		"path":        path,
		"path_source": pathSource,
		"mode":        mode,
	})
}

// NewFsTruncate builds an fs.truncate event (emitted by eBPF).
func NewFsTruncate(session string, seg, idx, tsMono, tsWall uint64, pid uint32, path redact.Redacted, pathSource PathSource, size uint64) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeFsTruncate, OriginKernel, map[string]any{
		"path":        path,
		"path_source": pathSource,
		"size":        size,
	})
}

// NewFsSettle builds an fs.settle event (emitted by svc's digest worker,
// profile scopes only — plan D8). prevDigest may be nil for a newly
// created file.
func NewFsSettle(session string, seg, idx, tsMono, tsWall uint64, pid uint32,
	path redact.Redacted, prevDigest, newDigest []byte, sizeDelta int64, mtimeNs uint64,
) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeFsSettle, OriginSVC, map[string]any{
		"path":        path,
		"prev_digest": prevDigest,
		"new_digest":  newDigest,
		"size_delta":  sizeDelta,
		"mtime_ns":    mtimeNs,
	})
}

// NewFsSensitiveRead builds an fs.sensitive_read event (emitted by eBPF).
func NewFsSensitiveRead(session string, seg, idx, tsMono, tsWall uint64, pid uint32, path, rule redact.Redacted) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeFsSensitiveRead, OriginKernel, map[string]any{
		"path": path,
		"rule": rule,
	})
}

// NewNetConnect builds a net.connect event (emitted by eBPF). daddr MUST be
// 16 bytes (v4-mapped for IPv4, per plan §4.3 / CONTRACTS); proto is "tcp"
// or "udp".
func NewNetConnect(session string, seg, idx, tsMono, tsWall uint64, pid uint32, proto string, daddr []byte, dport uint16, family string) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeNetConnect, OriginKernel, map[string]any{
		"proto":  redact.Literal(proto),
		"daddr":  daddr,
		"dport":  uint64(dport),
		"family": redact.Literal(family),
	})
}

// NewNetDNS builds a net.dns event (emitted by ranad's DNS observer).
func NewNetDNS(session string, seg, idx, tsMono, tsWall uint64, pid uint32, qname redact.Redacted, answers []redact.Redacted, ttl uint32) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeNetDNS, OriginKernel, map[string]any{
		"qname":   qname,
		"answers": answers,
		"ttl":     uint64(ttl),
	})
}

// NewNetFlowClose builds a net.flow_close event (emitted by eBPF via
// inet_sock_set_state).
func NewNetFlowClose(session string, seg, idx, tsMono, tsWall uint64, pid uint32, bytesTx, bytesRx, durNs uint64, daddr []byte, dport uint16) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeNetFlowClose, OriginKernel, map[string]any{
		"bytes_tx": bytesTx,
		"bytes_rx": bytesRx,
		"dur_ns":   durNs,
		"daddr":    daddr,
		"dport":    uint64(dport),
	})
}

// NewUnixConnect builds a unix.connect event (emitted by eBPF fentry).
func NewUnixConnect(session string, seg, idx, tsMono, tsWall uint64, pid uint32, path redact.Redacted) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeUnixConnect, OriginKernel, map[string]any{
		"path": path,
	})
}

// NewMarker builds a marker.<suffix> event. Markers are always
// origin=enrichment (P1, P7): they carry identifiers and lifecycle only,
// never message content — callers MUST NOT put prompt/completion text in
// data; that is a P7 violation this package cannot detect structurally,
// only by review.
func NewMarker(session string, seg, idx, tsMono, tsWall uint64, pid uint32, suffix string, data map[string]any) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeMarker(suffix), OriginEnrichment, data)
}

// NewAlertNewDomain builds an alert.new_domain event (emitted by svc rules).
func NewAlertNewDomain(session string, seg, idx, tsMono, tsWall uint64, pid uint32, qname redact.Redacted) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeAlertNewDomain, OriginSVC, map[string]any{
		"qname": qname,
	})
}

// NewAlertSensitiveRead builds an alert.sensitive_read event (emitted by svc rules).
func NewAlertSensitiveRead(session string, seg, idx, tsMono, tsWall uint64, pid uint32, path, rule redact.Redacted) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeAlertSensitiveRead, OriginSVC, map[string]any{
		"path": path,
		"rule": rule,
	})
}

// NewAlertCgroupEscape builds an alert.cgroup_escape event (emitted by svc rules).
func NewAlertCgroupEscape(session string, seg, idx, tsMono, tsWall uint64, pid uint32, escapedPid uint32, from, to redact.Redacted) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeAlertCgroupEscape, OriginSVC, map[string]any{
		"pid":  uint64(escapedPid),
		"from": from,
		"to":   to,
	})
}

// NewAlertEscapePrecursor builds an alert.escape_precursor event (emitted
// by svc rules) — an observable precursor to an unattributable escape
// (plan §6.4), e.g. in-session exec of a delegation tool.
func NewAlertEscapePrecursor(session string, seg, idx, tsMono, tsWall uint64, pid uint32, precursor redact.Redacted) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeAlertEscapePrecursor, OriginSVC, map[string]any{
		"precursor": precursor,
	})
}

// NewAlertBurst builds an alert.burst event (emitted by svc rules): a rate
// over threshold for eventClass within windowNs.
func NewAlertBurst(session string, seg, idx, tsMono, tsWall uint64, pid uint32, eventClass redact.Redacted, count uint64, windowNs uint64) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeAlertBurst, OriginSVC, map[string]any{
		"class":     eventClass,
		"count":     count,
		"window_ns": windowNs,
	})
}

// NewGap builds a gap event (emitted by the ranad governor / writer). reason
// MUST be one of the frozen GapReason values; counts is per-class shed
// counts (P5, invariant 5).
func NewGap(session string, seg, idx, tsMono, tsWall uint64, pid uint32, reason string, counts map[string]uint64, fromNs, toNs uint64) Event {
	return newEnvelope(session, seg, idx, tsMono, tsWall, pid, EventTypeGap, OriginSVC, map[string]any{
		"reason":  redact.Literal(reason),
		"counts":  counts,
		"from_ns": fromNs,
		"to_ns":   toNs,
	})
}

// ---- Validate ----

// ErrMarkerOriginMustBeEnrichment is returned by Validate when a marker.*
// event does not carry Origin == OriginEnrichment (P1, invariant 6).
var ErrMarkerOriginMustBeEnrichment = errors.New("schema: marker.* events must carry origin=enrichment")

// Validate checks envelope completeness, that Type is a known event type,
// and origin/state legality — most importantly that marker.* events always
// carry origin=enrichment (P1, invariant 6, CLAUDE.md §6).
func Validate(ev Event) error {
	if ev.V != 1 {
		return fmt.Errorf("schema: unsupported envelope version %d (want 1)", ev.V)
	}
	if ev.Session == "" {
		return errors.New("schema: session id must not be empty")
	}
	if ev.Type == "" {
		return errors.New("schema: event type must not be empty")
	}
	if !knownOrigins[ev.Origin] {
		return fmt.Errorf("schema: unknown origin %q", ev.Origin)
	}
	if !knownStates[ev.State] {
		return fmt.Errorf("schema: unknown state %q", ev.State)
	}

	isMarker := IsMarkerType(ev.Type)
	if !isMarker && !knownNonMarkerTypes[ev.Type] {
		return fmt.Errorf("schema: unknown event type %q", ev.Type)
	}

	if isMarker {
		if ev.Origin != OriginEnrichment {
			return fmt.Errorf("%w: got origin=%q for type %q", ErrMarkerOriginMustBeEnrichment, ev.Origin, ev.Type)
		}
	} else if ev.Origin == OriginEnrichment {
		// Non-marker types are kernel- or svc-emitted load-bearing facts
		// (P1); enrichment is reserved for the marker.* family.
		return fmt.Errorf("schema: origin=enrichment is only legal for marker.* events, got type %q", ev.Type)
	}

	if err := validateTypeSpecific(ev); err != nil {
		return err
	}

	return nil
}

func validateTypeSpecific(ev Event) error {
	switch ev.Type {
	case EventTypeNetConnect:
		daddr, _ := ev.Data["daddr"].([]byte)
		if len(daddr) != 16 {
			return fmt.Errorf("schema: net.connect daddr must be 16 bytes (v4-mapped), got %d", len(daddr))
		}
	case EventTypeNetFlowClose:
		daddr, _ := ev.Data["daddr"].([]byte)
		if len(daddr) != 16 {
			return fmt.Errorf("schema: net.flow_close daddr must be 16 bytes (v4-mapped), got %d", len(daddr))
		}
	case EventTypeGap:
		reason, _ := ev.Data["reason"].(redact.Redacted)
		if !knownGapReasons[GapReason(reason)] {
			return fmt.Errorf("schema: unknown gap reason %q (frozen set: ringbuf_full, governor, daemon_restart)", reason)
		}
	case EventTypeFsWriteOpen, EventTypeFsUnlink, EventTypeFsRename, EventTypeFsMkdir, EventTypeFsChmod, EventTypeFsTruncate:
		ps, ok := ev.Data["path_source"].(PathSource)
		if ok && !knownPathSources[ps] {
			return fmt.Errorf("schema: unknown path_source %q", ps)
		}
	}
	return nil
}

// ---- session id generation (ULID, 26-char Crockford base32) ----

// Clock supplies the current time in Unix milliseconds, injectable for
// deterministic tests (CONTRACTS testing bar: injectable clocks
// everywhere time matters).
type Clock interface {
	Now() int64 // Unix epoch milliseconds
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewSessionID generates a 26-character Crockford-base32 ULID-format
// session id: a 48-bit millisecond timestamp (from clk) followed by 80
// bits of crypto/rand randomness. It never reads envp (P3 does not apply
// here, but the same discipline: no external entropy sources other than
// crypto/rand).
func NewSessionID(clk Clock) string {
	ms := clk.Now()
	if ms < 0 {
		ms = 0
	}

	var ts [6]byte
	for i := 5; i >= 0; i-- {
		ts[i] = byte(ms & 0xff)
		ms >>= 8
	}

	var randBytes [10]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		// crypto/rand.Read practically never fails on supported platforms;
		// if it does, we still must return a well-formed 26-char id rather
		// than panic mid-record. Zero randomness degrades uniqueness but
		// never correctness of the record itself.
		for i := range randBytes {
			randBytes[i] = 0
		}
	}

	var full [16]byte
	copy(full[0:6], ts[:])
	copy(full[6:16], randBytes[:])

	return encodeCrockford(full)
}

// encodeCrockford encodes 16 bytes (128 bits) as 26 Crockford-base32
// characters (5 bits each = 130 bits capacity; the top 2 bits of the first
// character are always 0 for a 128-bit payload), matching the standard
// ULID text encoding.
func encodeCrockford(data [16]byte) string {
	var out [26]byte
	// Treat data as a 128-bit big-endian integer and emit 26 base-32 digits
	// most-significant first.
	var bits [128]byte // one bit per element for simplicity/clarity over perf; session id gen is not hot path
	for i := 0; i < 16; i++ {
		b := data[i]
		for j := 0; j < 8; j++ {
			bits[i*8+j] = (b >> (7 - j)) & 1
		}
	}
	// 26*5 = 130 bits; left-pad our 128 bits with 2 leading zero bits.
	var padded [130]byte
	copy(padded[2:], bits[:])

	for i := 0; i < 26; i++ {
		var v byte
		for j := 0; j < 5; j++ {
			v = (v << 1) | padded[i*5+j]
		}
		out[i] = crockford[v]
	}
	return string(out[:])
}
