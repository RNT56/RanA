package collector

import (
	"testing"
	"time"

	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

func testPipeline(t *testing.T) *redact.Pipeline {
	t.Helper()
	p, err := redact.NewPipeline([]byte("enricher-test-salt"))
	if err != nil {
		t.Fatalf("redact.NewPipeline: %v", err)
	}
	return p
}

func newTestEnricher(t *testing.T, clk Clock) *Enricher {
	t.Helper()
	e := NewEnricher(EnricherConfig{
		Pipeline: testPipeline(t),
		DNSCache: NewDNSCache(clk),
		Clock:    clk,
	})
	return e
}

// ---- cgid -> session mapping ----

func TestEnricherSessionForCgidUnknown(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	_, ok := e.SessionForCgid(0xDEAD)
	if ok {
		t.Fatal("expected no session for an unmapped cgid")
	}
}

func TestEnricherBindCgidThenLookup(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(0xCAFE, "sess-1")
	sess, ok := e.SessionForCgid(0xCAFE)
	if !ok || sess != "sess-1" {
		t.Errorf("SessionForCgid = (%q, %v), want (sess-1, true)", sess, ok)
	}
}

func TestEnricherUnbindCgid(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")
	e.UnbindCgid(1)
	if _, ok := e.SessionForCgid(1); ok {
		t.Fatal("expected no session after UnbindCgid")
	}
}

// ---- EnrichExec ----

func TestEnrichExecBuildsRedactedEvent(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(7, "sess-1")

	rec := ExecRecord{
		Pid: 100, Ppid: 1, Uid: 501, Cgid: 7,
		TsMono: 10, TsWall: 20,
		Comm: "node", ExePath: "/usr/bin/node", Cwd: "/home/user",
		Argv: []string{"/usr/bin/node", "--token=sk-ant-abcdefghijklmnopqrstuvwx1234"},
	}

	ev, err := e.EnrichExec(rec, 0)
	if err != nil {
		t.Fatalf("EnrichExec: %v", err)
	}
	if ev.Type != schema.EventTypeProcExec {
		t.Errorf("Type = %v", ev.Type)
	}
	if ev.Session != "sess-1" {
		t.Errorf("Session = %q, want sess-1", ev.Session)
	}
	if ev.Origin != schema.OriginKernel {
		t.Errorf("Origin = %v, want kernel", ev.Origin)
	}
	argv, ok := ev.Data["argv"].([]redact.Redacted)
	if !ok || len(argv) != 2 {
		t.Fatalf("Data[argv] = %#v", ev.Data["argv"])
	}
	if string(argv[1]) == rec.Argv[1] {
		t.Errorf("argv[1] was not redacted: %q", argv[1])
	}
	if err := schema.Validate(ev); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestEnrichExecUnknownCgidReturnsError(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	rec := ExecRecord{Pid: 1, Cgid: 999, Comm: "x", ExePath: "/x", Cwd: "/", Argv: nil}
	_, err := e.EnrichExec(rec, 0)
	if err != ErrUnknownCgid {
		t.Errorf("err = %v, want ErrUnknownCgid", err)
	}
}

func TestEnrichExecIdxMonotonicPerSession(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")
	rec := ExecRecord{Pid: 1, Cgid: 1, Comm: "x", ExePath: "/x", Cwd: "/"}

	ev1, err := e.EnrichExec(rec, 0)
	if err != nil {
		t.Fatalf("EnrichExec: %v", err)
	}
	ev2, err := e.EnrichExec(rec, 0)
	if err != nil {
		t.Fatalf("EnrichExec: %v", err)
	}
	if ev2.Idx != ev1.Idx+1 {
		t.Errorf("Idx did not advance monotonically: %d -> %d", ev1.Idx, ev2.Idx)
	}
}

func TestEnrichExecIdxIndependentPerSession(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")
	e.BindCgid(2, "sess-2")

	rec1 := ExecRecord{Pid: 1, Cgid: 1, Comm: "x", ExePath: "/x", Cwd: "/"}
	rec2 := ExecRecord{Pid: 2, Cgid: 2, Comm: "y", ExePath: "/y", Cwd: "/"}

	evA1, _ := e.EnrichExec(rec1, 0)
	evB1, _ := e.EnrichExec(rec2, 0)
	evA2, _ := e.EnrichExec(rec1, 0)

	if evA1.Idx != 0 || evB1.Idx != 0 {
		t.Errorf("first event per session should start at idx 0: got %d, %d", evA1.Idx, evB1.Idx)
	}
	if evA2.Idx != 1 {
		t.Errorf("sess-1 second event Idx = %d, want 1", evA2.Idx)
	}
}

// ---- EnrichFork / EnrichExit ----

func TestEnrichForkAndExit(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")

	fork := ForkRecord{Pid: 5, Ppid: 1, Cgid: 1, TsMono: 1, TsWall: 2}
	ev, err := e.EnrichFork(fork, 0)
	if err != nil {
		t.Fatalf("EnrichFork: %v", err)
	}
	if ev.Type != schema.EventTypeProcFork {
		t.Errorf("Type = %v", ev.Type)
	}

	exit := ExitRecord{Pid: 5, Cgid: 1, TsMono: 3, TsWall: 4, ExitCode: 0, UtimeNs: 10, StimeNs: 20}
	ev2, err := e.EnrichExit(exit, 0)
	if err != nil {
		t.Fatalf("EnrichExit: %v", err)
	}
	if ev2.Type != schema.EventTypeProcExit {
		t.Errorf("Type = %v", ev2.Type)
	}
}

// ---- EnrichFsOp ----

func TestEnrichFsOpWriteOpen(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")

	rec := FsOpRecord{
		Op: FsOpWriteOpen, PathSource: PathSourceKindResolved,
		Pid: 1, Cgid: 1, TsMono: 1, TsWall: 2,
		Flags: 0x241, Mode: 0o644,
		Path: "/home/user/.ssh/id_rsa",
	}
	ev, err := e.EnrichFsOp(rec, 0)
	if err != nil {
		t.Fatalf("EnrichFsOp: %v", err)
	}
	if ev.Type != schema.EventTypeFsWriteOpen {
		t.Errorf("Type = %v", ev.Type)
	}
	path, ok := ev.Data["path"].(redact.Redacted)
	if !ok {
		t.Fatalf("Data[path] type = %T", ev.Data["path"])
	}
	if string(path) != rec.Path {
		// Plain paths aren't secrets by pattern, so RedactPath commonly
		// passes them through unchanged; either way the type must be
		// Redacted (P3), asserted above.
		t.Logf("path was transformed by RedactPath: %q -> %q", rec.Path, path)
	}
	if err := schema.Validate(ev); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestEnrichFsOpRenameHasPath2(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")
	rec := FsOpRecord{Op: FsOpRename, PathSource: PathSourceKindResolved, Pid: 1, Cgid: 1, Path: "/a/old", Path2: "/a/new"}
	ev, err := e.EnrichFsOp(rec, 0)
	if err != nil {
		t.Fatalf("EnrichFsOp: %v", err)
	}
	if ev.Type != schema.EventTypeFsRename {
		t.Errorf("Type = %v", ev.Type)
	}
	if _, ok := ev.Data["path2"].(redact.Redacted); !ok {
		t.Errorf("Data[path2] type = %T, want redact.Redacted", ev.Data["path2"])
	}
}

func TestEnrichFsOpUnknownOpErrors(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")
	rec := FsOpRecord{Op: FsOp(99), Pid: 1, Cgid: 1, Path: "/x"}
	_, err := e.EnrichFsOp(rec, 0)
	if err == nil {
		t.Fatal("expected error for unknown FsOp")
	}
}

// ---- fs.sensitive_read (via an FsOpRecord with FsOpSensitiveRead) ----

// TestEnrichFsOpSensitiveReadProducesSensitiveReadEvent proves the D9
// highest-signal path is wired: a kind=4 FsOpRecord with op=FsOpSensitiveRead
// (as the eBPF sensitive-watchlist branch emits) becomes an
// fs.sensitive_read event — NOT an fs.write_open — carrying the matched rule
// (from Mode) as a redacted field. This is what the Tier-2 trifecta alert
// keys on.
func TestEnrichFsOpSensitiveReadProducesSensitiveReadEvent(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")
	rec := FsOpRecord{
		Op: FsOpSensitiveRead, PathSource: PathSourceKindResolved,
		Pid: 42, Cgid: 1, TsMono: 5, TsWall: 6,
		Path: "/home/user/.ssh/id_ed25519", Mode: 3, // Mode = matched rule id
	}
	ev, err := e.EnrichFsOp(rec, 0)
	if err != nil {
		t.Fatalf("EnrichFsOp: %v", err)
	}
	if ev.Type != schema.EventTypeFsSensitiveRead {
		t.Fatalf("Type = %v, want fs.sensitive_read (a watchlisted read must NOT be fs.write_open)", ev.Type)
	}
	if _, ok := ev.Data["rule"].(redact.Redacted); !ok {
		t.Errorf("Data[rule] type = %T, want redact.Redacted", ev.Data["rule"])
	}
	if _, ok := ev.Data["path"].(redact.Redacted); !ok {
		t.Errorf("Data[path] type = %T, want redact.Redacted", ev.Data["path"])
	}
}

// ---- EnrichConnect / EnrichSendmsg, with DNS join ----

func TestEnrichConnectJoinsRecentDNS(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")

	addr := v4Mapped(93, 184, 216, 34)
	e.dnsCache.Observe("example.com", [][16]byte{addr}, 300, clk.Now())

	rec := ConnectRecord{Proto: 6, Family: 4, Pid: 1, Cgid: 1, TsMono: 1, TsWall: 2, Daddr: addr, Dport: 443}
	ev, err := e.EnrichConnect(rec, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("EnrichConnect: %v", err)
	}
	if ev.Type != schema.EventTypeNetConnect {
		t.Errorf("Type = %v", ev.Type)
	}
	qname, ok := ev.Data["qname"]
	if !ok {
		t.Fatal("expected Data[qname] to be set from DNS join")
	}
	rq, ok := qname.(redact.Redacted)
	if !ok {
		t.Fatalf("Data[qname] type = %T, want redact.Redacted", qname)
	}
	if string(rq) != "example.com" && !containsRedactionMarker(string(rq)) {
		t.Errorf("qname = %q, want example.com or a redaction marker", rq)
	}
}

func containsRedactionMarker(s string) bool {
	for _, r := range s {
		if r == '⟦' {
			return true
		}
	}
	return false
}

func TestEnrichConnectNoDNSJoinLeavesQnameAbsent(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")
	addr := v4Mapped(1, 1, 1, 1)
	rec := ConnectRecord{Proto: 17, Family: 4, Pid: 1, Cgid: 1, Daddr: addr, Dport: 53}
	ev, err := e.EnrichConnect(rec, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("EnrichConnect: %v", err)
	}
	if _, ok := ev.Data["qname"]; ok {
		t.Error("did not expect Data[qname] when no DNS answer was observed")
	}
}

func TestEnrichSendmsgBuildsNetConnect(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")
	addr := v4Mapped(8, 8, 8, 8)
	rec := SendmsgRecord{Proto: 17, Family: 4, Pid: 1, Cgid: 1, Daddr: addr, Dport: 53}
	ev, err := e.EnrichSendmsg(rec, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("EnrichSendmsg: %v", err)
	}
	if ev.Type != schema.EventTypeNetConnect {
		t.Errorf("Type = %v", ev.Type)
	}
}

// ---- EnrichDNS ----

func TestEnrichDNSObservesIntoCache(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")
	addr := v4Mapped(93, 184, 216, 34)
	rec := DNSRecord{Pid: 1, Cgid: 1, TsMono: 1, TsWall: 2, TTL: 300, Qname: "example.com", Answers: [][16]byte{addr}}

	ev, err := e.EnrichDNS(rec, 0)
	if err != nil {
		t.Fatalf("EnrichDNS: %v", err)
	}
	if ev.Type != schema.EventTypeNetDNS {
		t.Errorf("Type = %v", ev.Type)
	}
	if _, ok := e.dnsCache.Join(addr, clk.Now(), time.Second); !ok {
		t.Error("EnrichDNS should have populated the shared DNSCache via Observe")
	}
}

// ---- EnrichFlowClose ----

func TestEnrichFlowClose(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")
	addr := v4Mapped(1, 2, 3, 4)
	rec := FlowCloseRecord{Proto: 6, Family: 4, Pid: 1, Cgid: 1, Daddr: addr, Dport: 443, BytesTx: 10, BytesRx: 20, DurNs: 30}
	ev, err := e.EnrichFlowClose(rec, 0)
	if err != nil {
		t.Fatalf("EnrichFlowClose: %v", err)
	}
	if ev.Type != schema.EventTypeNetFlowClose {
		t.Errorf("Type = %v", ev.Type)
	}
}

// ---- EnrichUnixConnect ----

func TestEnrichUnixConnect(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")
	rec := UnixConnectRecord{Pid: 1, Cgid: 1, Path: "/var/run/docker.sock"}
	ev, err := e.EnrichUnixConnect(rec, 0)
	if err != nil {
		t.Fatalf("EnrichUnixConnect: %v", err)
	}
	if ev.Type != schema.EventTypeUnixConnect {
		t.Errorf("Type = %v", ev.Type)
	}
}

// ---- EnrichMigration ----

func TestEnrichMigrationResolvesKnownCgids(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-a")
	e.BindCgid(2, "sess-b")
	rec := MigrationRecord{Pid: 9, FromCgid: 1, ToCgid: 2, TsMono: 1, TsWall: 2}
	ev, err := e.EnrichMigration(rec, 0)
	if err != nil {
		t.Fatalf("EnrichMigration: %v", err)
	}
	if ev.Type != schema.EventTypeAlertCgroupEscape {
		t.Errorf("Type = %v", ev.Type)
	}
	from, ok := ev.Data["from"].(redact.Redacted)
	if !ok || string(from) != "sess-a" {
		t.Errorf("Data[from] = %v, want sess-a", ev.Data["from"])
	}
	to, ok := ev.Data["to"].(redact.Redacted)
	if !ok || string(to) != "sess-b" {
		t.Errorf("Data[to] = %v, want sess-b", ev.Data["to"])
	}
}

func TestEnrichMigrationUnknownCgidReportsUnknown(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-a")
	rec := MigrationRecord{Pid: 9, FromCgid: 1, ToCgid: 0xBEEF, TsMono: 1, TsWall: 2}
	ev, err := e.EnrichMigration(rec, 0)
	if err != nil {
		t.Fatalf("EnrichMigration: %v", err)
	}
	to, ok := ev.Data["to"].(redact.Redacted)
	if !ok || string(to) != "unknown" {
		t.Errorf("Data[to] = %v, want unknown", ev.Data["to"])
	}
	// Migration events are emitted against the FROM session (the one we
	// can attribute) even when the destination is unattributable.
	if ev.Session != "sess-a" {
		t.Errorf("Session = %q, want sess-a", ev.Session)
	}
}

func TestEnrichMigrationBothCgidsUnknownErrors(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	rec := MigrationRecord{Pid: 9, FromCgid: 0xDEAD, ToCgid: 0xBEEF}
	_, err := e.EnrichMigration(rec, 0)
	if err != ErrUnknownCgid {
		t.Errorf("err = %v, want ErrUnknownCgid", err)
	}
}

// TestEnricherEndSessionReleasesPerSessionState verifies that EndSession
// drops a finished session's Idx counter, exe-provenance seen-map, and any
// still-bound cgids, so a long-lived daemon does not accumulate per-session
// state forever (the cleanup path the ranad↔svc session-end signal will call;
// LIMITS.md §8).
func TestEnricherEndSessionReleasesPerSessionState(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(9, "sess-x")

	// Exec twice to populate nextIdx and the exe-provenance seen-map.
	rec := ExecRecord{
		Pid: 100, Ppid: 1, Uid: 501, Cgid: 9, TsMono: 10, TsWall: 20,
		Comm: "node", ExePath: "/usr/bin/node", Cwd: "/home/u",
		Argv:         []string{"/usr/bin/node"},
		ExeDigest:    [32]byte{1, 2, 3},
		ExeDigestSet: true, // populate the exe-provenance seen-map
	}
	if _, err := e.EnrichExec(rec, 0); err != nil {
		t.Fatalf("EnrichExec: %v", err)
	}
	if _, err := e.EnrichExec(rec, 0); err != nil {
		t.Fatalf("EnrichExec: %v", err)
	}

	// Precondition: per-session state exists.
	e.mu.Lock()
	haveIdx := e.nextIdx["sess-x"] != 0
	_, haveProv := e.exeProvenance["sess-x"]
	_, haveCgid := e.cgidToSession[9]
	e.mu.Unlock()
	if !haveIdx || !haveProv || !haveCgid {
		t.Fatalf("precondition: idx=%v prov=%v cgid=%v", haveIdx, haveProv, haveCgid)
	}

	e.EndSession("sess-x")

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.nextIdx["sess-x"]; ok {
		t.Error("nextIdx not released")
	}
	if _, ok := e.exeProvenance["sess-x"]; ok {
		t.Error("exeProvenance not released")
	}
	if _, ok := e.cgidToSession[9]; ok {
		t.Error("cgid binding not released")
	}
	// EndSession on an unknown session is a safe no-op.
	e.mu.Unlock()
	e.EndSession("never-existed")
	e.mu.Lock()
}
