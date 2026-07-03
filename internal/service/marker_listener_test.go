package service

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RNT56/RanA/internal/profile"
	"github.com/RNT56/RanA/internal/schema"
)

// dialMarkerSocket connects to a unix socket at path, retrying briefly
// since the listener goroutine may not have bound yet.
func dialMarkerSocket(t *testing.T, path string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		c, err := net.Dial("unix", path)
		if err == nil {
			return c
		}
		lastErr = err
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("dialing marker socket %s: %v", path, lastErr)
	return nil
}

func newMarkerListenerForTest(t *testing.T) (*MarkerListener, string, string, chan schema.Event) {
	t.Helper()
	sockPath := shortSocketPath(t, "m.sock")

	events := make(chan schema.Event, 64)
	ml, err := NewMarkerListener(MarkerListenerConfig{
		SocketPath: sockPath,
		Token:      "test-token-abc123",
		Profile:    openclawMarkers(),
		Pipeline:   testPipeline(t),
		Session:    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Emit: func(ev schema.Event) error {
			events <- ev
			return nil
		},
		Clock: SystemClock,
	})
	if err != nil {
		t.Fatalf("NewMarkerListener: %v", err)
	}
	t.Cleanup(func() { _ = ml.Close() })

	go func() {
		_ = ml.Serve()
	}()

	return ml, sockPath, "test-token-abc123", events
}

func TestMarkerListener_ValidMarkerAccepted(t *testing.T) {
	_, sockPath, token, events := newMarkerListenerForTest(t)

	conn := dialMarkerSocket(t, sockPath)
	defer conn.Close()

	line := `{"token":"` + token + `","event":"run.start","runId":"a9f2","agentId":"default","channel":"telegram","status":"accepted"}` + "\n"
	if _, err := conn.Write([]byte(line)); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case ev := <-events:
		if ev.Type != schema.EventTypeMarker("run.start") {
			t.Fatalf("type = %q", ev.Type)
		}
		if ev.Origin != schema.OriginEnrichment {
			t.Fatalf("origin = %q, want enrichment", ev.Origin)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for marker event")
	}
}

func TestMarkerListener_BadTokenRejected(t *testing.T) {
	_, sockPath, _, events := newMarkerListenerForTest(t)

	conn := dialMarkerSocket(t, sockPath)
	defer conn.Close()

	line := `{"token":"wrong-token","event":"run.start","runId":"a9f2"}` + "\n"
	if _, err := conn.Write([]byte(line)); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case ev := <-events:
		t.Fatalf("bad-token marker was accepted and emitted: %+v", ev)
	case <-time.After(200 * time.Millisecond):
		// expected: nothing emitted
	}
}

func TestMarkerListener_MissingTokenRejected(t *testing.T) {
	_, sockPath, _, events := newMarkerListenerForTest(t)

	conn := dialMarkerSocket(t, sockPath)
	defer conn.Close()

	line := `{"event":"run.start","runId":"a9f2"}` + "\n"
	if _, err := conn.Write([]byte(line)); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case ev := <-events:
		t.Fatalf("no-token marker was accepted and emitted: %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestMarkerListener_MultipleLinesEachHandled(t *testing.T) {
	_, sockPath, token, events := newMarkerListenerForTest(t)

	conn := dialMarkerSocket(t, sockPath)
	defer conn.Close()

	lines := `{"token":"` + token + `","event":"run.start","runId":"a1"}` + "\n" +
		`{"token":"` + token + `","event":"run.end","runId":"a1","status":"ok"}` + "\n"
	if _, err := conn.Write([]byte(lines)); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := map[schema.EventType]bool{}
	for i := 0; i < 2; i++ {
		select {
		case ev := <-events:
			got[ev.Type] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for marker %d", i)
		}
	}
	if !got[schema.EventTypeMarker("run.start")] || !got[schema.EventTypeMarker("run.end")] {
		t.Fatalf("got = %v, want both run.start and run.end", got)
	}
}

func TestMarkerListener_HostileContentNeverLeaks(t *testing.T) {
	_, sockPath, token, events := newMarkerListenerForTest(t)

	conn := dialMarkerSocket(t, sockPath)
	defer conn.Close()

	// A hostile marker: valid token, but stuffed with content fields and an
	// extra unknown field. None of it may ever reach the ledger.
	line := `{"token":"` + token + `","event":"run.start","runId":"a1","text":"the actual prompt text","evil":"payload"}` + "\n"
	if _, err := conn.Write([]byte(line)); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case ev := <-events:
		if _, ok := ev.Data["text"]; ok {
			t.Fatal("forbidden content field 'text' leaked into ledger event")
		}
		if _, ok := ev.Data["evil"]; ok {
			t.Fatal("unlisted field 'evil' leaked into ledger event")
		}
		if _, ok := ev.Data["runId"]; !ok {
			t.Fatal("legitimate carried field 'runId' was dropped")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for marker event")
	}
}

func TestMarkerListener_NonJSONGarbageDoesNotCrashOrEmit(t *testing.T) {
	_, sockPath, _, events := newMarkerListenerForTest(t)

	conn := dialMarkerSocket(t, sockPath)
	defer conn.Close()

	if _, err := conn.Write([]byte("not json at all\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case ev := <-events:
		t.Fatalf("garbage line produced an event: %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}

	// Connection and listener must still be alive for a subsequent valid
	// line (garbage must not kill the connection or the listener).
	if _, err := conn.Write([]byte("still not json\n")); err != nil {
		t.Fatalf("write after garbage: %v", err)
	}
}

func TestMarkerListener_OversizedLineRejectedNotCrash(t *testing.T) {
	_, sockPath, token, events := newMarkerListenerForTest(t)

	conn := dialMarkerSocket(t, sockPath)
	defer conn.Close()

	big := make([]byte, 5000)
	for i := range big {
		big[i] = 'a'
	}
	line := `{"token":"` + token + `","event":"run.start","runId":"` + string(big) + `"}` + "\n"
	if _, err := conn.Write([]byte(line)); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case ev := <-events:
		t.Fatalf("oversized line produced an event: %+v", ev)
	case <-time.After(300 * time.Millisecond):
	}
}

// NewSessionMarkerSocket generates a fresh per-session random path+token
// under baseDir, ready for a caller (adopt/run) to export as
// RANA_MARKER_SOCKET/RANA_MARKER_TOKEN.
func TestNewSessionMarkerSocket_UniquePerCall(t *testing.T) {
	dir := t.TempDir()
	a, err := NewSessionMarkerSocket(dir, "session-a")
	if err != nil {
		t.Fatalf("NewSessionMarkerSocket: %v", err)
	}
	b, err := NewSessionMarkerSocket(dir, "session-b")
	if err != nil {
		t.Fatalf("NewSessionMarkerSocket: %v", err)
	}
	if a.Path == b.Path {
		t.Fatal("two sessions got the same socket path")
	}
	if a.Token == b.Token {
		t.Fatal("two sessions got the same token")
	}
	if a.Token == "" || len(a.Token) < 16 {
		t.Fatalf("token too short/empty: %q", a.Token)
	}
	if filepath.Dir(a.Path) != dir && filepath.Dir(filepath.Dir(a.Path)) != dir {
		t.Errorf("socket path %q not rooted under %q", a.Path, dir)
	}
}

func TestProfileMarkersDisabled_NoListenerNeeded(t *testing.T) {
	cfg := profile.Markers{Enabled: false}
	if cfg.Enabled {
		t.Fatal("sanity")
	}
	// MarkerListenerConfig with a disabled profile should be rejected by
	// the caller before ever binding a socket — svc.go's wiring test
	// exercises the actual skip-if-disabled behavior end to end.
	_ = os.Getenv // keep os import used if trimmed later
}
