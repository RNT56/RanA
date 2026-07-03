package service

import (
	"net"
	"testing"
	"time"

	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/schema"
	"github.com/RNT56/RanA/internal/wire"
)

// fakeAppender is a minimal ledger.Writer stand-in recording every
// schema.Event handed to Append, so tests can assert on wire-frame-to-
// ledger plumbing without spinning up a real SQLite-backed Writer.
type fakeAppender struct {
	mu     chan struct{} // binary semaphore-ish guard, avoids importing sync for a 3-field type
	events []schema.Event
	err    error
}

func newFakeAppender() *fakeAppender {
	return &fakeAppender{mu: make(chan struct{}, 1)}
}

func (f *fakeAppender) AppendEncoded(ev schema.Event, _ []byte) error {
	f.mu <- struct{}{}
	defer func() { <-f.mu }()
	f.events = append(f.events, ev)
	return f.err
}

func (f *fakeAppender) snapshot() []schema.Event {
	f.mu <- struct{}{}
	defer func() { <-f.mu }()
	out := make([]schema.Event, len(f.events))
	copy(out, f.events)
	return out
}

// pairedUnixConns returns two connected *net.UnixConn endpoints (a real
// socketpair via net.Pipe would not satisfy *net.UnixConn-typed APIs like
// wire.PeerCred, but RanadServer.HandleConn accepts a plain net.Conn so a
// net.Pipe pair is sufficient and avoids filesystem socket path-length
// issues entirely for this file's tests).
func pairedConns() (net.Conn, net.Conn) {
	return net.Pipe()
}

func TestRanadServer_HelloThenEvAppendsToLedger(t *testing.T) {
	appender := newFakeAppender()
	srv := NewRanadServer(RanadServerConfig{
		Appender: appender,
	})

	client, serverSide := pairedConns()
	defer client.Close()

	done := make(chan error, 1)
	go func() { done <- srv.HandleConn(serverSide) }()

	if err := wire.WriteFrame(client, &wire.Hello{V: wire.Version, Role: wire.RoleRanad, Salt: []byte("saltsaltsaltsaltsaltsaltsaltsalt")}); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	ev := schema.NewSessionEnd("01ARZ3NDEKTSV4RRFFQ69G5FAV", 0, 1, 1000, 2000, 42)
	encoded, err := cborcanon.EncodeEvent(ev)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	if err := wire.WriteFrame(client, &wire.Ev{Event: encoded}); err != nil {
		t.Fatalf("write ev: %v", err)
	}
	if err := wire.WriteFrame(client, &wire.Bye{}); err != nil {
		t.Fatalf("write bye: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandleConn returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HandleConn to finish")
	}

	got := appender.snapshot()
	if len(got) != 1 {
		t.Fatalf("appended %d events, want 1", len(got))
	}
	if got[0].Type != schema.EventTypeSessionEnd {
		t.Fatalf("appended event type = %q", got[0].Type)
	}
}

func TestRanadServer_WrongRoleHelloRejected(t *testing.T) {
	appender := newFakeAppender()
	srv := NewRanadServer(RanadServerConfig{Appender: appender})

	client, serverSide := pairedConns()
	defer client.Close()

	done := make(chan error, 1)
	go func() { done <- srv.HandleConn(serverSide) }()

	// svc role, not ranad: the server side of this connection expects a
	// ranad peer; a mismatched Hello must be rejected.
	if err := wire.WriteFrame(client, &wire.Hello{V: wire.Version, Role: wire.RoleSVC, Salt: []byte("x")}); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected HandleConn to reject a non-ranad Hello, got nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}

func TestRanadServer_MultipleEvFramesAllAppended(t *testing.T) {
	appender := newFakeAppender()
	srv := NewRanadServer(RanadServerConfig{Appender: appender})

	client, serverSide := pairedConns()
	defer client.Close()

	done := make(chan error, 1)
	go func() { done <- srv.HandleConn(serverSide) }()

	if err := wire.WriteFrame(client, &wire.Hello{V: wire.Version, Role: wire.RoleRanad, Salt: []byte("s")}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	for i := uint64(1); i <= 3; i++ {
		ev := schema.NewSessionEnd("01ARZ3NDEKTSV4RRFFQ69G5FAV", 0, i, 1000, 2000, 42)
		encoded, err := cborcanon.EncodeEvent(ev)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if err := wire.WriteFrame(client, &wire.Ev{Event: encoded}); err != nil {
			t.Fatalf("write ev %d: %v", i, err)
		}
	}
	if err := wire.WriteFrame(client, &wire.Bye{}); err != nil {
		t.Fatalf("write bye: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandleConn: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}

	if got := len(appender.snapshot()); got != 3 {
		t.Fatalf("appended %d events, want 3", got)
	}
}

func TestRanadServer_MalformedEvBytesRejectedNotFatal(t *testing.T) {
	appender := newFakeAppender()
	srv := NewRanadServer(RanadServerConfig{Appender: appender})

	client, serverSide := pairedConns()
	defer client.Close()

	done := make(chan error, 1)
	go func() { done <- srv.HandleConn(serverSide) }()

	if err := wire.WriteFrame(client, &wire.Hello{V: wire.Version, Role: wire.RoleRanad, Salt: []byte("s")}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	// Not valid canonical CBOR for a schema.Event.
	if err := wire.WriteFrame(client, &wire.Ev{Event: []byte{0xff, 0xff, 0xff}}); err != nil {
		t.Fatalf("write bad ev: %v", err)
	}
	// A well-formed event afterwards should still go through — one bad
	// frame must not take down the connection (ranad is the privileged,
	// trusted peer in v1, but svc still must not crash on a decode error).
	ev := schema.NewSessionEnd("01ARZ3NDEKTSV4RRFFQ69G5FAV", 0, 1, 1000, 2000, 42)
	encoded, err := cborcanon.EncodeEvent(ev)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := wire.WriteFrame(client, &wire.Ev{Event: encoded}); err != nil {
		t.Fatalf("write ev: %v", err)
	}
	if err := wire.WriteFrame(client, &wire.Bye{}); err != nil {
		t.Fatalf("write bye: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}

	got := appender.snapshot()
	if len(got) != 1 {
		t.Fatalf("appended %d events, want 1 (the valid one, bad frame skipped)", len(got))
	}
}

func TestRanadServer_HeadReportCallbackWiredOnCheckpoint(t *testing.T) {
	// The server itself does not produce Head frames (that is the ledger
	// Writer's HeadReportFunc, wired at Writer construction time to call
	// SendHead on this server's active connections) — this test exercises
	// SendHead directly to prove a HeadReport is correctly framed and
	// written back to the ranad peer.
	appender := newFakeAppender()
	srv := NewRanadServer(RanadServerConfig{Appender: appender})

	client, serverSide := pairedConns()
	defer client.Close()

	readErrCh := make(chan error, 1)
	frameCh := make(chan wire.Frame, 1)
	go func() {
		if err := wire.WriteFrame(client, &wire.Hello{V: wire.Version, Role: wire.RoleRanad, Salt: []byte("s")}); err != nil {
			readErrCh <- err
			return
		}
		f, err := wire.ReadFrame(client)
		if err != nil {
			readErrCh <- err
			return
		}
		frameCh <- f
	}()

	// Something must read serverSide's incoming Hello so the client-side
	// write above does not block forever on the fully-synchronous
	// net.Pipe transport; register the connection the same way HandleConn
	// would after reading that Hello.
	helloFrame, err := wire.ReadFrame(serverSide)
	if err != nil {
		t.Fatalf("reading hello on server side: %v", err)
	}
	if h, ok := helloFrame.(*wire.Hello); !ok || h.Role != wire.RoleRanad {
		t.Fatalf("unexpected first frame: %#v", helloFrame)
	}
	conn := srv.registerForTest(serverSide)
	defer conn.close()

	report := chain.HeadReport{SessionID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", SegLast: 7, At: 123}
	if err := conn.SendHead(report); err != nil {
		t.Fatalf("SendHead: %v", err)
	}

	select {
	case err := <-readErrCh:
		t.Fatalf("client-side error: %v", err)
	case f := <-frameCh:
		head, ok := f.(*wire.Head)
		if !ok {
			t.Fatalf("got frame %T, want *wire.Head", f)
		}
		if head.Report.SessionID != report.SessionID || head.Report.SegLast != report.SegLast {
			t.Fatalf("head report mismatch: got %+v want %+v", head.Report, report)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Head frame")
	}
}
