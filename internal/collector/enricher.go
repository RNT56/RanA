package collector

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// ipToString renders a 16-byte address (v4-mapped for IPv4, per
// internal/bpf/records.md) as dotted-quad or colon-hex text so it can pass
// through the redaction Pipeline (which operates on strings) before
// becoming part of a net.dns event's answers list.
func ipToString(addr [16]byte) string {
	isV4Mapped := true
	for i := 0; i < 10; i++ {
		if addr[i] != 0 {
			isV4Mapped = false
			break
		}
	}
	if isV4Mapped && addr[10] == 0xff && addr[11] == 0xff {
		return fmt.Sprintf("%d.%d.%d.%d", addr[12], addr[13], addr[14], addr[15])
	}
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		uint16(addr[0])<<8|uint16(addr[1]), uint16(addr[2])<<8|uint16(addr[3]),
		uint16(addr[4])<<8|uint16(addr[5]), uint16(addr[6])<<8|uint16(addr[7]),
		uint16(addr[8])<<8|uint16(addr[9]), uint16(addr[10])<<8|uint16(addr[11]),
		uint16(addr[12])<<8|uint16(addr[13]), uint16(addr[14])<<8|uint16(addr[15]))
}

// ErrUnknownCgid is returned by an EnrichXxx method when a record's Cgid
// (or, for EnrichMigration, both FromCgid and ToCgid) has no known
// cgid->session binding. Kernel events for a cgroup RanA never pinned into
// the session filter map should not reach userspace at all (D6: in-kernel
// filtering), so this is a defensive error path, not an expected one.
var ErrUnknownCgid = errors.New("collector: unknown cgid (no session binding)")

// EnricherConfig configures an Enricher. Pipeline and DNSCache and Clock
// are all required.
type EnricherConfig struct {
	// Pipeline redacts every captured string (argv, paths, qnames) before
	// it can reach a schema.Event's Data map (P3 by construction — schema
	// events only accept redact.Redacted for string-shaped data).
	Pipeline *redact.Pipeline
	// DNSCache joins net.connect destination addresses to a recently
	// observed qname. Enrich* methods that decode a DNSRecord
	// call DNSCache.Observe; EnrichConnect/EnrichSendmsg call
	// DNSCache.Join.
	DNSCache *DNSCache
	// Clock supplies "now" for DNS join-window arithmetic. Injectable.
	Clock Clock
}

// Enricher turns decoded wire records into schema.Event values: it resolves
// each record's Cgid to a session id, runs every captured string through
// the redaction Pipeline, joins net.connect destinations to recent DNS
// answers via the DNSCache, and assigns a monotonically increasing per-
// session Idx (CONTRACTS §internal/collector: "cgid->session map, builds
// schema events, invokes redact pipeline on argv/paths/qnames").
//
// Enricher does not decide Seg (segment index) — that's the ledger
// writer's concern (segment sealing policy lives in internal/ledger); every
// EnrichXxx method takes seg as a parameter so callers pass through
// whatever segment is currently open for the session.
//
// Enricher is safe for concurrent use.
type Enricher struct {
	mu sync.Mutex

	pipeline *redact.Pipeline
	dnsCache *DNSCache
	clock    Clock

	cgidToSession map[uint64]string
	nextIdx       map[string]uint64

	// exeProvenance is the per-session exe-provenance seen-map (Tier-2
	// exe_first_seen/exe_changed/exe_known), keyed by session id per
	// CONTRACTS ("keep an in-enricher seen-map keyed by session").
	exeProvenance map[string]*exeSeen
}

// NewEnricher constructs an Enricher from cfg.
func NewEnricher(cfg EnricherConfig) *Enricher {
	return &Enricher{
		pipeline:      cfg.Pipeline,
		dnsCache:      cfg.DNSCache,
		clock:         cfg.Clock,
		cgidToSession: make(map[uint64]string),
		nextIdx:       make(map[string]uint64),
	}
}

// BindCgid records that cgid belongs to session. Called by the session
// lifecycle path when a session's cgroup is created/adopted, and
// for every subsequent cgid RanA's eBPF programs pin into the filter map
// for that session's tree.
func (e *Enricher) BindCgid(cgid uint64, session string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cgidToSession[cgid] = session
}

// UnbindCgid removes a cgid->session binding (session end / cgroup
// teardown).
func (e *Enricher) UnbindCgid(cgid uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.cgidToSession, cgid)
}

// EndSession releases all per-session Enricher state for a session that has
// ended: its monotonic-Idx counter and its exe-provenance seen-map (the
// latter grows with the number of distinct executables a session runs, so it
// is the largest per-session footprint). It mirrors Governor.EndSession and
// segTracker.EndSession so a single session-end signal can evict all three
// together. Any cgids still bound to the session are unbound too, so a
// finished session leaves no residue.
//
// Wired via Pump.DrainEndedSessions, called from ranad's outbound loop on
// each inbound wire.SessionEnd frame (cmd/ranad/pump.go). It is deliberately
// safe to call for an unknown session (a no-op) and MUST only be called once
// a session is truly over — never for a live session, since dropping
// nextIdx mid-session would restart Idx at 0 and duplicate identifiers.
func (e *Enricher) EndSession(session string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.nextIdx, session)
	delete(e.exeProvenance, session)
	for cgid, s := range e.cgidToSession {
		if s == session {
			delete(e.cgidToSession, cgid)
		}
	}
}

// SessionForCgid returns the session id bound to cgid, if any.
func (e *Enricher) SessionForCgid(cgid uint64) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.cgidToSession[cgid]
	return s, ok
}

// nextIdxFor returns and advances the next monotonic Idx for session.
func (e *Enricher) nextIdxFor(session string) uint64 {
	idx := e.nextIdx[session]
	e.nextIdx[session] = idx + 1
	return idx
}

// sessionFor resolves cgid to a session id under the Enricher's lock,
// returning ErrUnknownCgid if unbound.
func (e *Enricher) sessionFor(cgid uint64) (string, error) {
	session, ok := e.cgidToSession[cgid]
	if !ok {
		return "", ErrUnknownCgid
	}
	return session, nil
}

// ---- proc.* ----

// EnrichExec builds a proc.exec event from a decoded ExecRecord.
func (e *Enricher) EnrichExec(rec ExecRecord, seg uint64) (schema.Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	session, err := e.sessionFor(rec.Cgid)
	if err != nil {
		return schema.Event{}, err
	}
	idx := e.nextIdxFor(session)

	argv := e.pipeline.RedactArgv(rec.Argv)
	comm := e.pipeline.Redact(rec.Comm)
	// cwd and the exe path are kernel-resolved (the task's fs->pwd and
	// mm->exe_file walks), so the content-addressed allowlist may apply.
	cwd := e.pipeline.RedactPath(rec.Cwd, redact.PathResolved)
	exePath := e.pipeline.RedactPath(rec.ExePath, redact.PathResolved)

	ev := schema.NewProcExec(session, seg, idx, rec.TsMono, rec.TsWall, rec.Pid,
		argv, comm, cwd, exePath, rec.Ppid, rec.Uid)

	// Exe-provenance (Tier-2, additive, P1-safe): only runs when the
	// caller supplied a digest (ExeDigestSet) — an unset digest leaves
	// proc.exec exactly as it was before this feature existed.
	if rec.ExeDigestSet {
		seen := e.exeSeenFor(session)
		firstSeen, changed := seen.observe(rec.ExePath, rec.ExeDigest)
		ev.Data["exe_first_seen"] = firstSeen
		ev.Data["exe_changed"] = changed
		ev.Data["exe_known"] = e.pipeline.Redact(ClassifyExePath(rec.ExePath))
	}

	return ev, nil
}

// EnrichFork builds a proc.fork event from a decoded ForkRecord.
func (e *Enricher) EnrichFork(rec ForkRecord, seg uint64) (schema.Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	session, err := e.sessionFor(rec.Cgid)
	if err != nil {
		return schema.Event{}, err
	}
	idx := e.nextIdxFor(session)
	return schema.NewProcFork(session, seg, idx, rec.TsMono, rec.TsWall, rec.Pid, rec.Ppid), nil
}

// EnrichExit builds a proc.exit event from a decoded ExitRecord.
func (e *Enricher) EnrichExit(rec ExitRecord, seg uint64) (schema.Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	session, err := e.sessionFor(rec.Cgid)
	if err != nil {
		return schema.Event{}, err
	}
	idx := e.nextIdxFor(session)
	return schema.NewProcExit(session, seg, idx, rec.TsMono, rec.TsWall, rec.Pid, rec.ExitCode, rec.UtimeNs, rec.StimeNs), nil
}

// ---- fs.* ----

// fsOpEventType maps a decoded FsOp to its schema.EventType.
func fsOpEventType(op FsOp) (schema.EventType, error) {
	switch op {
	case FsOpWriteOpen:
		return schema.EventTypeFsWriteOpen, nil
	case FsOpUnlink:
		return schema.EventTypeFsUnlink, nil
	case FsOpRename:
		return schema.EventTypeFsRename, nil
	case FsOpMkdir:
		return schema.EventTypeFsMkdir, nil
	case FsOpChmod:
		return schema.EventTypeFsChmod, nil
	case FsOpTruncate:
		return schema.EventTypeFsTruncate, nil
	case FsOpSensitiveRead:
		return schema.EventTypeFsSensitiveRead, nil
	default:
		return "", errors.New("collector: unknown FsOp")
	}
}

func fsPathSource(ps PathSourceKind) schema.PathSource {
	if ps == PathSourceKindClaimed {
		return schema.PathSourceClaimed
	}
	return schema.PathSourceResolved
}

// pathTrust maps a record's kernel path-provenance to the redaction pipeline's
// PathTrust, which decides whether the content-addressed allowlist may apply.
// Only a kernel-resolved path is trusted; anything else (claimed, or an
// unrecognized value) defaults to the safe PathClaimed (no allowlist).
func pathTrust(ps PathSourceKind) redact.PathTrust {
	if ps == PathSourceKindResolved {
		return redact.PathResolved
	}
	return redact.PathClaimed
}

// EnrichFsOp builds the matching fs.* event from a decoded FsOpRecord,
// dispatching on rec.Op.
func (e *Enricher) EnrichFsOp(rec FsOpRecord, seg uint64) (schema.Event, error) {
	if _, err := fsOpEventType(rec.Op); err != nil {
		return schema.Event{}, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	session, err := e.sessionFor(rec.Cgid)
	if err != nil {
		return schema.Event{}, err
	}
	idx := e.nextIdxFor(session)

	// The allowlist that spares content-hash-shaped segments is trusted only
	// when the kernel RESOLVED this path; a claimed (agent-influenced) path
	// gets no allowlist, so a crafted …/objects/<hex-secret> segment is
	// redacted. path_source is the same kernel-truth signal stamped on the
	// event itself.
	path := e.pipeline.RedactPath(rec.Path, pathTrust(rec.PathSource))
	pathSource := fsPathSource(rec.PathSource)

	switch rec.Op {
	case FsOpWriteOpen:
		return schema.NewFsWriteOpen(session, seg, idx, rec.TsMono, rec.TsWall, rec.Pid, path, pathSource, rec.Flags, rec.Mode), nil
	case FsOpUnlink:
		return schema.NewFsUnlink(session, seg, idx, rec.TsMono, rec.TsWall, rec.Pid, path, pathSource), nil
	case FsOpRename:
		path2 := e.pipeline.RedactPath(rec.Path2, pathTrust(rec.PathSource))
		return schema.NewFsRename(session, seg, idx, rec.TsMono, rec.TsWall, rec.Pid, path, path2, pathSource), nil
	case FsOpMkdir:
		return schema.NewFsMkdir(session, seg, idx, rec.TsMono, rec.TsWall, rec.Pid, path, pathSource, rec.Mode), nil
	case FsOpChmod:
		return schema.NewFsChmod(session, seg, idx, rec.TsMono, rec.TsWall, rec.Pid, path, pathSource, rec.Mode), nil
	case FsOpTruncate:
		return schema.NewFsTruncate(session, seg, idx, rec.TsMono, rec.TsWall, rec.Pid, path, pathSource, rec.Mode), nil
	case FsOpSensitiveRead:
		// D9's highest-signal event: a watchlisted open. The eBPF program
		// carries the matched rule id in Mode (no dedicated wire field). Both
		// path and rule pass through the redaction pipeline (uniform P3 —
		// a rule id is not a secret, but the writer only accepts Redacted).
		rule := e.pipeline.Redact(fmt.Sprintf("rule-%d", rec.Mode))
		return schema.NewFsSensitiveRead(session, seg, idx, rec.TsMono, rec.TsWall, rec.Pid, path, rule), nil
	default:
		// Unreachable: fsOpEventType already validated rec.Op above.
		return schema.Event{}, errors.New("collector: unknown FsOp")
	}
}

// (fs.sensitive_read is produced by EnrichFsOp's FsOpSensitiveRead case —
// the eBPF sensitive-watchlist branch emits a kind=4 FsOpRecord with that op
// and the matched rule id in Mode, so it flows through the same decode →
// EnrichFsOp → event path as every other fs.* record.)

// ---- net.* ----

// EnrichConnect builds a net.connect event from a decoded ConnectRecord,
// joining a recent DNS answer for rec.Daddr (if any, within window) into
// Data["qname"].
func (e *Enricher) EnrichConnect(rec ConnectRecord, seg uint64, dnsJoinWindow time.Duration) (schema.Event, error) {
	return e.enrichConnectLike(rec.Proto, rec.Family, rec.Pid, rec.Cgid, rec.TsMono, rec.TsWall, rec.Daddr, rec.Dport, seg, dnsJoinWindow)
}

// EnrichSendmsg builds a net.connect event from a decoded SendmsgRecord
// (unconnected-UDP sendto path, D7) — identical enrichment to
// EnrichConnect, kept as a separate method so callers can account
// governor/ledger metrics per wire-kind if desired while still producing
// the same schema.EventTypeNetConnect shape (both hook families feed the
// same event type).
func (e *Enricher) EnrichSendmsg(rec SendmsgRecord, seg uint64, dnsJoinWindow time.Duration) (schema.Event, error) {
	return e.enrichConnectLike(rec.Proto, rec.Family, rec.Pid, rec.Cgid, rec.TsMono, rec.TsWall, rec.Daddr, rec.Dport, seg, dnsJoinWindow)
}

func (e *Enricher) enrichConnectLike(proto, family uint8, pid uint32, cgid uint64, tsMono, tsWall uint64, daddr [16]byte, dport uint16, seg uint64, dnsJoinWindow time.Duration) (schema.Event, error) {
	e.mu.Lock()
	session, err := e.sessionFor(cgid)
	if err != nil {
		e.mu.Unlock()
		return schema.Event{}, err
	}
	idx := e.nextIdxFor(session)
	e.mu.Unlock()

	protoStr := "tcp"
	if proto == 17 {
		protoStr = "udp"
	}
	familyStr := "4"
	if family == 6 {
		familyStr = "6"
	}

	ev := schema.NewNetConnect(session, seg, idx, tsMono, tsWall, pid, protoStr, daddr[:], dport, familyStr)

	if qname, ok := e.dnsCache.Join(daddr, e.clock.Now(), dnsJoinWindow); ok {
		ev.Data["qname"] = e.pipeline.Redact(qname)
	}

	return ev, nil
}

// EnrichDNS builds a net.dns event from a decoded DNSRecord and records the
// answer set into the shared DNSCache so a subsequent EnrichConnect/
// EnrichSendmsg call for one of these addresses can join it.
func (e *Enricher) EnrichDNS(rec DNSRecord, seg uint64) (schema.Event, error) {
	e.mu.Lock()
	session, err := e.sessionFor(rec.Cgid)
	if err != nil {
		e.mu.Unlock()
		return schema.Event{}, err
	}
	idx := e.nextIdxFor(session)
	e.mu.Unlock()

	qname := e.pipeline.Redact(rec.Qname)
	answers := make([]redact.Redacted, 0, len(rec.Answers))
	for _, a := range rec.Answers {
		answers = append(answers, e.pipeline.Redact(ipToString(a)))
	}

	e.dnsCache.Observe(rec.Qname, rec.Answers, rec.TTL, e.clock.Now())

	return schema.NewNetDNS(session, seg, idx, rec.TsMono, rec.TsWall, rec.Pid, qname, answers, rec.TTL), nil
}

// EnrichFlowClose builds a net.flow_close event from a decoded
// FlowCloseRecord.
func (e *Enricher) EnrichFlowClose(rec FlowCloseRecord, seg uint64) (schema.Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	session, err := e.sessionFor(rec.Cgid)
	if err != nil {
		return schema.Event{}, err
	}
	idx := e.nextIdxFor(session)
	return schema.NewNetFlowClose(session, seg, idx, rec.TsMono, rec.TsWall, rec.Pid, rec.BytesTx, rec.BytesRx, rec.DurNs, rec.Daddr[:], rec.Dport), nil
}

// EnrichUnixConnect builds a unix.connect event from a decoded
// UnixConnectRecord.
func (e *Enricher) EnrichUnixConnect(rec UnixConnectRecord, seg uint64) (schema.Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	session, err := e.sessionFor(rec.Cgid)
	if err != nil {
		return schema.Event{}, err
	}
	idx := e.nextIdxFor(session)
	// A unix-socket connect address is the sockaddr_un the agent asked to
	// connect to — syscall-argument-derived, i.e. claimed. No allowlist.
	path := e.pipeline.RedactPath(rec.Path, redact.PathClaimed)
	return schema.NewUnixConnect(session, seg, idx, rec.TsMono, rec.TsWall, rec.Pid, path), nil
}

// ---- migration / escape ----

const unknownSessionLabel = "unknown"

// EnrichMigration builds an alert.cgroup_escape event from a decoded
// MigrationRecord (cgroup_attach_task filtered by the session
// pid-map). The event is attributed to the FROM session when it is known
// (the session we can actually charge this migration against); if only
// TO is known the event is attributed there instead. If neither cgid is
// bound to a session, the migration is not attributable to any RanA
// session and ErrUnknownCgid is returned — callers should not fabricate
// alerts for cgroups RanA never observed.
func (e *Enricher) EnrichMigration(rec MigrationRecord, seg uint64) (schema.Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	fromSession, fromOK := e.cgidToSession[rec.FromCgid]
	toSession, toOK := e.cgidToSession[rec.ToCgid]
	if !fromOK && !toOK {
		return schema.Event{}, ErrUnknownCgid
	}

	attributedSession := fromSession
	if !fromOK {
		attributedSession = toSession
	}
	if !fromOK {
		fromSession = unknownSessionLabel
	}
	if !toOK {
		toSession = unknownSessionLabel
	}

	idx := e.nextIdxFor(attributedSession)
	from := e.pipeline.Redact(fromSession)
	to := e.pipeline.Redact(toSession)
	return schema.NewAlertCgroupEscape(attributedSession, seg, idx, rec.TsMono, rec.TsWall, rec.Pid, rec.Pid, from, to), nil
}
