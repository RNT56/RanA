package service

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/profile"
	"github.com/RNT56/RanA/internal/schema"
	"github.com/RNT56/RanA/internal/wire"
)

func newTestService(t *testing.T) (*Service, ledger.Datadir) {
	t.Helper()
	dir := newTestLedgerDir(t)
	salt, err := dir.LoadOrCreateSalt()
	if err != nil {
		t.Fatalf("LoadOrCreateSalt: %v", err)
	}

	svc, err := NewService(Config{
		LedgerDir:     dir,
		Profile:       mustProfile(t, "openclaw"),
		Session:       "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Clock:         SystemClock,
		LaunchToken:   "svc-test-token",
		MarkerSocket:  shortSocketPath(t, "mk.sock"),
		MarkerToken:   "svc-marker-token",
		RedactionSalt: salt,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc, dir
}

func mustProfile(t *testing.T, name string) *profile.Profile {
	t.Helper()
	p, err := profile.Load(name)
	if err != nil {
		t.Fatalf("profile.Load(%q): %v", name, err)
	}
	return p
}

// TestService_EndToEnd_RanadFramesToVerifiedLedger simulates a fake ranad
// peer writing wire frames directly into the Service's ranad-facing
// handler, and asserts the resulting ledger verifies clean.
func TestService_EndToEnd_RanadFramesToVerifiedLedger(t *testing.T) {
	svc, dir := newTestService(t)

	client, serverSide := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() { done <- svc.RanadHandler().HandleConn(serverSide) }()

	if err := wire.WriteFrame(client, &wire.Hello{V: wire.Version, Role: wire.RoleRanad, Salt: []byte("saltsaltsaltsaltsaltsaltsaltsalt")}); err != nil {
		t.Fatalf("hello: %v", err)
	}

	session := "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	for i := uint64(1); i <= 4; i++ {
		ev := schema.NewProcFork(session, 0, i, i*1000, i*2000, 100+uint32(i), 100)
		enc, err := cborcanon.EncodeEvent(ev)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if err := wire.WriteFrame(client, &wire.Ev{Event: enc}); err != nil {
			t.Fatalf("ev %d: %v", i, err)
		}
	}
	if err := wire.WriteFrame(client, &wire.Bye{}); err != nil {
		t.Fatalf("bye: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandleConn: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}

	if err := svc.Writer().FlushForTest(); err != nil {
		t.Fatalf("FlushForTest: %v", err)
	}
	if err := svc.Writer().SealSession(session); err != nil {
		t.Fatalf("SealSession: %v", err)
	}

	result, err := ledger.Verify(dir, ledger.VerifyOptions{Session: session})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Code != ledger.CodeOK {
		t.Fatalf("verify code = %d, want OK(0); findings=%+v", result.Code, result.Findings)
	}
}

// TestService_MarkerToLedger exercises the full path: a fake agent writes
// a marker line to the service's marker socket, and it lands in the
// ledger as origin=enrichment, verifiable.
func TestService_MarkerToLedger(t *testing.T) {
	svc, dir := newTestService(t)

	if err := svc.StartMarkerListener(); err != nil {
		t.Fatalf("StartMarkerListener: %v", err)
	}

	conn := dialMarkerSocket(t, svc.cfg.MarkerSocket)
	defer conn.Close()

	line := `{"token":"svc-marker-token","event":"run.start","runId":"a9f2","agentId":"default","channel":"telegram","status":"accepted"}` + "\n"
	if _, err := conn.Write([]byte(line)); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	var found bool
	for time.Now().Before(deadline) {
		if err := svc.Writer().FlushForTest(); err != nil {
			t.Fatalf("FlushForTest: %v", err)
		}
		events, err := svc.DataSource().Events(context.Background(), svc.cfg.Session, 0, 0)
		if err != nil {
			t.Fatalf("Events: %v", err)
		}
		for _, ev := range events {
			if ev.Type == schema.EventTypeMarker("run.start") {
				found = true
				if ev.Origin != schema.OriginEnrichment {
					t.Fatalf("marker origin = %q, want enrichment", ev.Origin)
				}
			}
		}
		if found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !found {
		t.Fatal("marker.run.start never appeared in the ledger")
	}

	if err := svc.Writer().SealSession(svc.cfg.Session); err != nil {
		t.Fatalf("SealSession: %v", err)
	}
	result, err := ledger.Verify(dir, ledger.VerifyOptions{Session: svc.cfg.Session})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Code != ledger.CodeOK {
		t.Fatalf("verify code = %d, want OK; findings=%+v", result.Code, result.Findings)
	}
}

// TestService_HostileMarkerNeverPersisted proves a hostile marker (content
// field, extra field, bad token) never reaches the ledger at all.
func TestService_HostileMarkerNeverPersisted(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.StartMarkerListener(); err != nil {
		t.Fatalf("StartMarkerListener: %v", err)
	}

	conn := dialMarkerSocket(t, svc.cfg.MarkerSocket)
	defer conn.Close()

	// Bad token: must never be accepted.
	bad := `{"token":"wrong","event":"run.start","runId":"x","text":"the actual prompt"}` + "\n"
	if _, err := conn.Write([]byte(bad)); err != nil {
		t.Fatalf("write: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	if err := svc.Writer().FlushForTest(); err != nil {
		t.Fatalf("FlushForTest: %v", err)
	}
	events, err := svc.DataSource().Events(context.Background(), svc.cfg.Session, 0, 0)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	for _, ev := range events {
		if ev.Type == schema.EventTypeMarker("run.start") {
			t.Fatalf("hostile (bad-token) marker was persisted: %+v", ev)
		}
	}
}

// TestService_TimelineHTTPServesLedgerContent wires the HTTP host over a
// real listener and confirms authenticated requests see appended events.
func TestService_TimelineHTTPServesLedgerContent(t *testing.T) {
	svc, _ := newTestService(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{Handler: svc.TimelineHandler()}
	go srv.Serve(ln)
	defer srv.Close()

	session := svc.cfg.Session
	if err := svc.Writer().Append(schema.NewSessionStart(session, 0, 1, 0, 0, 1, "openclaw", nil, map[string]any{}, nil)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := svc.Writer().FlushForTest(); err != nil {
		t.Fatalf("FlushForTest: %v", err)
	}

	url := "http://" + ln.Addr().String() + "/api/sessions"
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer svc-test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// TestService_SessionLifecycleAndDigestWorker exercises EmitSessionStart,
// StartDigestWorker producing an fs.settle event through the real service
// wiring (not the isolated DigestWorker unit tests), and EmitSessionEnd
// sealing + checkpointing a verifiable ledger.
func TestService_SessionLifecycleAndDigestWorker(t *testing.T) {
	dir := newTestLedgerDir(t)
	salt, err := dir.LoadOrCreateSalt()
	if err != nil {
		t.Fatalf("LoadOrCreateSalt: %v", err)
	}

	scopeDir := t.TempDir()
	digestFile := scopeDir + "/report.md"
	if err := os.WriteFile(digestFile, []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	p := mustProfile(t, "generic")
	p.Digest.Scopes = []string{scopeDir + "/**"}

	fc := newFakeClock(time.Now())
	svc, err := NewService(Config{
		LedgerDir:              dir,
		Profile:                p,
		Session:                "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Clock:                  fc,
		LaunchToken:            "tok",
		RedactionSalt:          salt,
		DigestDebounceInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer svc.Close()

	if err := svc.EmitSessionStart("generic", nil, map[string]any{}, nil); err != nil {
		t.Fatalf("EmitSessionStart: %v", err)
	}

	if err := svc.StartDigestWorker(); err != nil {
		t.Fatalf("StartDigestWorker: %v", err)
	}
	// Drive two scan intervals so the debounce settles. advanceAndSettle
	// waits for the worker goroutine to re-arm its timer between ticks, so
	// the second tick can't be lost to the fakeClock/goroutine wakeup race.
	fc.advanceAndSettle(10 * time.Millisecond)
	fc.advanceAndSettle(10 * time.Millisecond)

	deadline := time.Now().Add(3 * time.Second)
	var sawSettle bool
	for time.Now().Before(deadline) {
		if err := svc.Writer().FlushForTest(); err != nil {
			t.Fatalf("FlushForTest: %v", err)
		}
		events, err := svc.DataSource().Events(context.Background(), svc.cfg.Session, 0, 0)
		if err != nil {
			t.Fatalf("Events: %v", err)
		}
		for _, ev := range events {
			if ev.Type == schema.EventTypeFsSettle {
				sawSettle = true
			}
		}
		if sawSettle {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sawSettle {
		t.Fatal("digest worker never produced an fs.settle event through the service wiring")
	}

	if err := svc.EmitSessionEnd(); err != nil {
		t.Fatalf("EmitSessionEnd: %v", err)
	}

	result, err := ledger.Verify(dir, ledger.VerifyOptions{Session: svc.cfg.Session})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Code != ledger.CodeOK {
		t.Fatalf("verify code = %d, want OK; findings=%+v", result.Code, result.Findings)
	}
}

// TestOnFaultReceivesMarkerDigestIngressFaults confirms P5 (losses are loud)
// holds on the marker/digest ingress paths, not just the kernel path: a
// fault surfaced by emitMarker/emitDigest reaches Config.OnFault even though
// the marker listener and digest worker discard the returned error to keep
// serving. Tests the shared reportFault mechanism those callbacks use.
func TestOnFaultReceivesMarkerDigestIngressFaults(t *testing.T) {
	dir := newTestLedgerDir(t)
	salt, err := dir.LoadOrCreateSalt()
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	var faults []error
	svc, err := NewService(Config{
		LedgerDir:     dir,
		Profile:       mustProfile(t, "generic"),
		Session:       "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Clock:         SystemClock,
		LaunchToken:   "tok",
		RedactionSalt: salt,
		OnFault:       func(e error) { faults = append(faults, e) },
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer svc.Close()

	// A non-nil fault is surfaced and returned unchanged.
	boom := errors.New("simulated ingress fault")
	if got := svc.reportFault(boom); got != boom {
		t.Fatalf("reportFault returned %v, want the original error", got)
	}
	if len(faults) != 1 || faults[0] != boom {
		t.Fatalf("OnFault received %v, want exactly [%v]", faults, boom)
	}
	// A nil fault must not invoke OnFault.
	if got := svc.reportFault(nil); got != nil {
		t.Fatalf("reportFault(nil) = %v, want nil", got)
	}
	if len(faults) != 1 {
		t.Fatalf("OnFault called on a nil error: %v", faults)
	}
}
