package schema_test

import (
	"errors"
	"testing"

	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

const testSession = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

// canonicalEncodable is a helper asserting a constructed event survives
// cborcanon.EncodeEvent (i.e. contains no raw strings and encodes to
// canonical CBOR).
func canonicalEncodable(t *testing.T, ev schema.Event) []byte {
	t.Helper()
	if err := schema.Validate(ev); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	b, err := cborcanon.EncodeEvent(ev)
	if err != nil {
		t.Fatalf("EncodeEvent() unexpected error: %v", err)
	}
	ok, err := cborcanon.IsCanonical(b)
	if err != nil {
		t.Fatalf("IsCanonical() error: %v", err)
	}
	if !ok {
		t.Fatalf("event did not encode canonically")
	}
	return b
}

func baseFields() (session string, seg, idx uint64, tsMono, tsWall uint64, pid uint32) {
	return testSession, 1, 1, 1000, 2000, 4242
}

// --- envelope basics ---

func TestEvent_EnvelopeFieldsRoundTrip(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewSessionStart(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("generic"),
		[]redact.Redacted{redact.Literal("run")},
		map[string]any{
			"os":      redact.Literal("linux"),
			"kernel":  redact.Literal("6.6.0"),
			"version": redact.Literal("1.0.0"),
			"boot_id": redact.Literal("abc123"),
		},
		[]redact.Redacted{},
	)
	if ev.V != 1 {
		t.Fatalf("expected V=1, got %d", ev.V)
	}
	if ev.Session != session || ev.Seg != seg || ev.Idx != idx {
		t.Fatalf("envelope fields not populated correctly: %+v", ev)
	}
	if ev.TsMono != tsMono || ev.TsWall != tsWall {
		t.Fatalf("timestamps not populated: %+v", ev)
	}
	if ev.Pid != pid {
		t.Fatalf("pid not populated: %+v", ev)
	}
	canonicalEncodable(t, ev)
}

// --- constants ---

func TestEventTypeConstants(t *testing.T) {
	want := []schema.EventType{
		schema.EventTypeSessionStart,
		schema.EventTypeSessionEnd,
		schema.EventTypeProcExec,
		schema.EventTypeProcFork,
		schema.EventTypeProcExit,
		schema.EventTypeFsWriteOpen,
		schema.EventTypeFsUnlink,
		schema.EventTypeFsRename,
		schema.EventTypeFsMkdir,
		schema.EventTypeFsChmod,
		schema.EventTypeFsTruncate,
		schema.EventTypeFsSettle,
		schema.EventTypeFsSensitiveRead,
		schema.EventTypeNetConnect,
		schema.EventTypeNetDNS,
		schema.EventTypeNetFlowClose,
		schema.EventTypeUnixConnect,
		schema.EventTypeAlertNewDomain,
		schema.EventTypeAlertSensitiveRead,
		schema.EventTypeAlertCgroupEscape,
		schema.EventTypeAlertEscapePrecursor,
		schema.EventTypeAlertBurst,
		schema.EventTypeGap,
	}
	seen := map[schema.EventType]bool{}
	for _, w := range want {
		if w == "" {
			t.Fatalf("empty constant found")
		}
		if seen[w] {
			t.Fatalf("duplicate constant value: %s", w)
		}
		seen[w] = true
	}
}

func TestOriginConstants(t *testing.T) {
	if schema.OriginKernel == "" || schema.OriginSVC == "" || schema.OriginEnrichment == "" {
		t.Fatalf("origin constants must be non-empty")
	}
	if schema.OriginKernel == schema.OriginSVC || schema.OriginSVC == schema.OriginEnrichment {
		t.Fatalf("origin constants must be distinct")
	}
}

func TestStateConstant(t *testing.T) {
	if schema.StateObserved == "" {
		t.Fatalf("StateObserved must be non-empty")
	}
}

func TestPathSourceConstants(t *testing.T) {
	if schema.PathSourceResolved == "" || schema.PathSourceClaimed == "" {
		t.Fatalf("path source constants must be non-empty")
	}
	if schema.PathSourceResolved == schema.PathSourceClaimed {
		t.Fatalf("path source constants must be distinct")
	}
}

func TestMarkerEventType_FreeformAfterPrefix(t *testing.T) {
	et := schema.MarkerEventType("openclaw.run")
	if et != "marker.openclaw.run" {
		t.Fatalf("expected marker.openclaw.run, got %s", et)
	}
	if !schema.IsMarkerType(et) {
		t.Fatalf("expected IsMarkerType true for %s", et)
	}
	if schema.IsMarkerType(schema.EventTypeProcExec) {
		t.Fatalf("proc.exec must not be classified as a marker type")
	}
}

// --- constructors: one test per event type from CONTRACTS §internal/schema ---

func TestNewSessionStart(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewSessionStart(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("claude-code"),
		[]redact.Redacted{redact.Literal("run"), redact.Literal("--flag")},
		map[string]any{
			"os":      redact.Literal("linux"),
			"kernel":  redact.Literal("6.6.0"),
			"version": redact.Literal("1.0.0"),
			"boot_id": redact.Literal("boot-xyz"),
		},
		[]redact.Redacted{redact.Literal("adopted via drop-in")},
	)
	if ev.Type != schema.EventTypeSessionStart {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	if ev.Origin != schema.OriginSVC {
		t.Fatalf("session.start must be origin=svc, got %s", ev.Origin)
	}
	for _, k := range []string{"profile", "argv", "host", "adopt_caveats"} {
		if _, ok := ev.Data[k]; !ok {
			t.Fatalf("missing data key %q", k)
		}
	}
	canonicalEncodable(t, ev)
}

func TestNewSessionEnd(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewSessionEnd(session, seg, idx, tsMono, tsWall, pid)
	if ev.Type != schema.EventTypeSessionEnd {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	if ev.Origin != schema.OriginSVC {
		t.Fatalf("session.end must be origin=svc, got %s", ev.Origin)
	}
	canonicalEncodable(t, ev)
}

func TestNewProcExec(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewProcExec(session, seg, idx, tsMono, tsWall, pid,
		[]redact.Redacted{redact.Literal("node"), redact.Literal("index.js")},
		redact.Literal("node"),
		redact.Literal("/home/user/project"),
		redact.Literal("/usr/bin/node"),
		4241,
		1000,
	)
	if ev.Type != schema.EventTypeProcExec {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	if ev.Origin != schema.OriginKernel {
		t.Fatalf("proc.exec must be origin=kernel, got %s", ev.Origin)
	}
	for _, k := range []string{"argv", "comm", "cwd", "exe_path", "ppid", "uid"} {
		if _, ok := ev.Data[k]; !ok {
			t.Fatalf("missing data key %q", k)
		}
	}
	canonicalEncodable(t, ev)
}

func TestNewProcFork(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewProcFork(session, seg, idx, tsMono, tsWall, pid, 4241)
	if ev.Type != schema.EventTypeProcFork {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	if _, ok := ev.Data["ppid"]; !ok {
		t.Fatalf("missing ppid")
	}
	canonicalEncodable(t, ev)
}

func TestNewProcExit(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewProcExit(session, seg, idx, tsMono, tsWall, pid, 0, 12345, 6789)
	if ev.Type != schema.EventTypeProcExit {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	for _, k := range []string{"exit_code", "utime_ns", "stime_ns"} {
		if _, ok := ev.Data[k]; !ok {
			t.Fatalf("missing data key %q", k)
		}
	}
	canonicalEncodable(t, ev)
}

func TestNewFsWriteOpen(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewFsWriteOpen(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("/tmp/out.txt"), schema.PathSourceResolved, 0x241, 0o644)
	if ev.Type != schema.EventTypeFsWriteOpen {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	for _, k := range []string{"path", "path_source", "flags", "mode"} {
		if _, ok := ev.Data[k]; !ok {
			t.Fatalf("missing data key %q", k)
		}
	}
	canonicalEncodable(t, ev)
}

func TestNewFsUnlink(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewFsUnlink(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("/tmp/gone.txt"), schema.PathSourceResolved)
	if ev.Type != schema.EventTypeFsUnlink {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	canonicalEncodable(t, ev)
}

func TestNewFsRename(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewFsRename(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("/tmp/a.txt"), redact.Literal("/tmp/b.txt"), schema.PathSourceResolved)
	if ev.Type != schema.EventTypeFsRename {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	for _, k := range []string{"path", "path2", "path_source"} {
		if _, ok := ev.Data[k]; !ok {
			t.Fatalf("missing data key %q", k)
		}
	}
	canonicalEncodable(t, ev)
}

func TestNewFsMkdir(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewFsMkdir(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("/tmp/newdir"), schema.PathSourceResolved, 0o755)
	if ev.Type != schema.EventTypeFsMkdir {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	canonicalEncodable(t, ev)
}

func TestNewFsChmod(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewFsChmod(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("/tmp/x"), schema.PathSourceResolved, 0o600)
	if ev.Type != schema.EventTypeFsChmod {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	canonicalEncodable(t, ev)
}

func TestNewFsTruncate(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewFsTruncate(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("/tmp/x"), schema.PathSourceClaimed, 0)
	if ev.Type != schema.EventTypeFsTruncate {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	canonicalEncodable(t, ev)
}

func TestNewFsSettle(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	prev := []byte{0x01, 0x02}
	newd := []byte{0x03, 0x04}
	ev := schema.NewFsSettle(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("/tmp/x"), prev, newd, -128, tsWall)
	if ev.Type != schema.EventTypeFsSettle {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	for _, k := range []string{"path", "prev_digest", "new_digest", "size_delta", "mtime_ns"} {
		if _, ok := ev.Data[k]; !ok {
			t.Fatalf("missing data key %q", k)
		}
	}
	canonicalEncodable(t, ev)
}

func TestNewFsSettle_NilPrevDigest(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewFsSettle(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("/tmp/new.txt"), nil, []byte{0xaa}, 10, tsWall)
	canonicalEncodable(t, ev)
}

func TestNewFsSensitiveRead(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewFsSensitiveRead(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("/home/user/.ssh/id_ed25519"), redact.Literal("ssh-key"))
	if ev.Type != schema.EventTypeFsSensitiveRead {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	for _, k := range []string{"path", "rule"} {
		if _, ok := ev.Data[k]; !ok {
			t.Fatalf("missing data key %q", k)
		}
	}
	canonicalEncodable(t, ev)
}

func TestNewNetConnect(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	daddr := make([]byte, 16)
	daddr[10], daddr[11] = 0xff, 0xff
	daddr[12], daddr[13], daddr[14], daddr[15] = 93, 184, 216, 34
	ev := schema.NewNetConnect(session, seg, idx, tsMono, tsWall, pid,
		"tcp", daddr, 443, "inet")
	if ev.Type != schema.EventTypeNetConnect {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	for _, k := range []string{"proto", "daddr", "dport", "family"} {
		if _, ok := ev.Data[k]; !ok {
			t.Fatalf("missing data key %q", k)
		}
	}
	canonicalEncodable(t, ev)
}

func TestNewNetConnect_InvalidAddrLength(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewNetConnect(session, seg, idx, tsMono, tsWall, pid,
		"tcp", []byte{1, 2, 3}, 443, "inet")
	if err := schema.Validate(ev); err == nil {
		t.Fatalf("expected Validate to reject non-16-byte daddr")
	}
}

func TestNewNetDNS(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewNetDNS(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("example.com"),
		[]redact.Redacted{redact.Literal("93.184.216.34")},
		300)
	if ev.Type != schema.EventTypeNetDNS {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	for _, k := range []string{"qname", "answers", "ttl"} {
		if _, ok := ev.Data[k]; !ok {
			t.Fatalf("missing data key %q", k)
		}
	}
	canonicalEncodable(t, ev)
}

func TestNewNetFlowClose(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	daddr := make([]byte, 16)
	ev := schema.NewNetFlowClose(session, seg, idx, tsMono, tsWall, pid,
		1024, 2048, 5_000_000, daddr, 443)
	if ev.Type != schema.EventTypeNetFlowClose {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	for _, k := range []string{"bytes_tx", "bytes_rx", "dur_ns", "daddr", "dport"} {
		if _, ok := ev.Data[k]; !ok {
			t.Fatalf("missing data key %q", k)
		}
	}
	canonicalEncodable(t, ev)
}

func TestNewUnixConnect(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewUnixConnect(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("/var/run/docker.sock"))
	if ev.Type != schema.EventTypeUnixConnect {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	if _, ok := ev.Data["path"]; !ok {
		t.Fatalf("missing path")
	}
	canonicalEncodable(t, ev)
}

func TestNewMarker(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewMarker(session, seg, idx, tsMono, tsWall, pid,
		"openclaw.run",
		map[string]any{
			"runId":   redact.Literal("run-123"),
			"agentId": redact.Literal("agent-1"),
			"channel": redact.Literal("cli"),
		},
	)
	if ev.Type != schema.EventTypeMarker("openclaw.run") {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	if ev.Origin != schema.OriginEnrichment {
		t.Fatalf("marker.* MUST be origin=enrichment, got %s", ev.Origin)
	}
	canonicalEncodable(t, ev)
}

func TestNewAlertNewDomain(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewAlertNewDomain(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("evil.example"))
	if ev.Type != schema.EventTypeAlertNewDomain {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	canonicalEncodable(t, ev)
}

func TestNewAlertSensitiveRead(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewAlertSensitiveRead(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("/home/user/.aws/credentials"), redact.Literal("aws-creds"))
	if ev.Type != schema.EventTypeAlertSensitiveRead {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	canonicalEncodable(t, ev)
}

func TestNewAlertCgroupEscape(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewAlertCgroupEscape(session, seg, idx, tsMono, tsWall, pid,
		pid, redact.Literal("rana.slice/session-1"), redact.Literal("other.slice"))
	if ev.Type != schema.EventTypeAlertCgroupEscape {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	for _, k := range []string{"pid", "from", "to"} {
		if _, ok := ev.Data[k]; !ok {
			t.Fatalf("missing data key %q", k)
		}
	}
	canonicalEncodable(t, ev)
}

func TestNewAlertEscapePrecursor(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewAlertEscapePrecursor(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("systemd-run"))
	if ev.Type != schema.EventTypeAlertEscapePrecursor {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	canonicalEncodable(t, ev)
}

func TestNewAlertBurst(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewAlertBurst(session, seg, idx, tsMono, tsWall, pid,
		redact.Literal("net.connect"), 500, 1_000_000_000)
	if ev.Type != schema.EventTypeAlertBurst {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	canonicalEncodable(t, ev)
}

func TestNewGap(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewGap(session, seg, idx, tsMono, tsWall, pid,
		"governor",
		map[string]uint64{"fork": 10, "fs.write_open": 3},
		1000, 2000,
	)
	if ev.Type != schema.EventTypeGap {
		t.Fatalf("wrong type: %s", ev.Type)
	}
	for _, k := range []string{"reason", "counts", "from_ns", "to_ns"} {
		if _, ok := ev.Data[k]; !ok {
			t.Fatalf("missing data key %q", k)
		}
	}
	canonicalEncodable(t, ev)
}

func TestNewGap_RejectsInvalidReason(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	ev := schema.NewGap(session, seg, idx, tsMono, tsWall, pid,
		"writer_backpressure", // not in the frozen set
		map[string]uint64{},
		1000, 2000,
	)
	if err := schema.Validate(ev); err == nil {
		t.Fatalf("expected Validate to reject unknown gap reason")
	}
}

// --- Validate ---

func TestValidate_RejectsUnknownEventType(t *testing.T) {
	ev := schema.Event{
		V:       1,
		Type:    schema.EventType("not.a.real.type"),
		Session: testSession,
		Origin:  schema.OriginKernel,
		State:   schema.StateObserved,
		Data:    map[string]any{},
	}
	if err := schema.Validate(ev); err == nil {
		t.Fatalf("expected error for unknown event type")
	}
}

func TestValidate_RejectsEmptySession(t *testing.T) {
	ev := schema.Event{
		V:      1,
		Type:   schema.EventTypeSessionEnd,
		Origin: schema.OriginSVC,
		State:  schema.StateObserved,
		Data:   map[string]any{},
	}
	if err := schema.Validate(ev); err == nil {
		t.Fatalf("expected error for empty session id")
	}
}

func TestValidate_RejectsWrongVersion(t *testing.T) {
	ev := schema.Event{
		V:       2,
		Type:    schema.EventTypeSessionEnd,
		Session: testSession,
		Origin:  schema.OriginSVC,
		State:   schema.StateObserved,
		Data:    map[string]any{},
	}
	if err := schema.Validate(ev); err == nil {
		t.Fatalf("expected error for V != 1")
	}
}

func TestValidate_RejectsUnknownOrigin(t *testing.T) {
	ev := schema.Event{
		V:       1,
		Type:    schema.EventTypeSessionEnd,
		Session: testSession,
		Origin:  schema.Origin("bogus"),
		State:   schema.StateObserved,
		Data:    map[string]any{},
	}
	if err := schema.Validate(ev); err == nil {
		t.Fatalf("expected error for unknown origin")
	}
}

func TestValidate_RejectsUnknownState(t *testing.T) {
	ev := schema.Event{
		V:       1,
		Type:    schema.EventTypeSessionEnd,
		Session: testSession,
		Origin:  schema.OriginSVC,
		State:   schema.State("bogus"),
		Data:    map[string]any{},
	}
	if err := schema.Validate(ev); err == nil {
		t.Fatalf("expected error for unknown state")
	}
}

func TestValidate_MarkerMustBeEnrichmentOrigin(t *testing.T) {
	ev := schema.Event{
		V:       1,
		Type:    schema.EventTypeMarker("openclaw.run"),
		Session: testSession,
		Origin:  schema.OriginKernel, // wrong: markers MUST be enrichment
		State:   schema.StateObserved,
		Data:    map[string]any{},
	}
	if err := schema.Validate(ev); !errors.Is(err, schema.ErrMarkerOriginMustBeEnrichment) {
		t.Fatalf("expected ErrMarkerOriginMustBeEnrichment, got %v", err)
	}
}

func TestValidate_MarkerWithEnrichmentOriginOK(t *testing.T) {
	ev := schema.Event{
		V:       1,
		Type:    schema.EventTypeMarker("openclaw.run"),
		Session: testSession,
		Origin:  schema.OriginEnrichment,
		State:   schema.StateObserved,
		Data:    map[string]any{},
	}
	if err := schema.Validate(ev); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_NonMarkerCannotClaimEnrichmentOriginArbitrarily(t *testing.T) {
	// proc.exec is a kernel-truth type; enrichment origin on it is nonsensical
	// and must be rejected — only kernel or svc are legal for non-marker types
	// depending on the emitter (P1).
	ev := schema.Event{
		V:       1,
		Type:    schema.EventTypeProcExec,
		Session: testSession,
		Origin:  schema.OriginEnrichment,
		State:   schema.StateObserved,
		Data: map[string]any{
			"argv":     []any{},
			"comm":     redact.Literal("x"),
			"cwd":      redact.Literal("/"),
			"exe_path": redact.Literal("/bin/x"),
			"ppid":     uint64(1),
			"uid":      uint64(0),
		},
	}
	if err := schema.Validate(ev); err == nil {
		t.Fatalf("expected error: proc.exec cannot carry origin=enrichment")
	}
}

func TestValidate_AcceptsWellFormedConstructedEvents(t *testing.T) {
	session, seg, idx, tsMono, tsWall, pid := baseFields()
	events := []schema.Event{
		schema.NewProcFork(session, seg, idx, tsMono, tsWall, pid, 1),
		schema.NewFsUnlink(session, seg, idx, tsMono, tsWall, pid, redact.Literal("/x"), schema.PathSourceClaimed),
		schema.NewUnixConnect(session, seg, idx, tsMono, tsWall, pid, redact.Literal("/run/x.sock")),
	}
	for _, ev := range events {
		if err := schema.Validate(ev); err != nil {
			t.Fatalf("Validate(%s) unexpected error: %v", ev.Type, err)
		}
	}
}

// --- ULID-format session id generator (mentioned in Session field docs) ---

func TestNewSessionID_Format(t *testing.T) {
	id := schema.NewSessionID(fixedClock{})
	if len(id) != 26 {
		t.Fatalf("expected 26-char ULID-format id, got %d chars: %q", len(id), id)
	}
}

func TestNewSessionID_Injectable(t *testing.T) {
	id1 := schema.NewSessionID(fixedClock{})
	id2 := schema.NewSessionID(fixedClock{})
	// Same clock, but randomness component should still make them extremely
	// unlikely to collide; just assert both are well-formed and the function
	// is deterministic in its clock usage (timestamp-prefix identical).
	if id1[:10] != id2[:10] {
		t.Fatalf("expected identical ULID time-prefix for identical injected clock: %s vs %s", id1[:10], id2[:10])
	}
}

type fixedClock struct{}

func (fixedClock) Now() int64 { return 1700000000000 } // ms epoch
