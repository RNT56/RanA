package vm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pipeDialer is a DialFunc backed by in-memory net.Pipe connections
// (CONTRACTS: "test with net.Pipe/in-memory fakes — no real vsock"). Each
// call to Dial returns one end of a fresh net.Pipe and hands the other end
// to onAccept, simulating a guest-side vsock listener accepting the
// forwarded connection.
type pipeDialer struct {
	mu       sync.Mutex
	dials    int
	dialErr  error
	onAccept func(guestSide net.Conn)
}

func (d *pipeDialer) Dial(ctx context.Context) (net.Conn, error) {
	d.mu.Lock()
	d.dials++
	err := d.dialErr
	onAccept := d.onAccept
	d.mu.Unlock()

	if err != nil {
		return nil, err
	}

	hostSide, guestSide := net.Pipe()
	if onAccept != nil {
		go onAccept(guestSide)
	} else {
		go guestSide.Close()
	}
	return hostSide, nil
}

func (d *pipeDialer) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

// echoAccept is an onAccept handler that echoes everything read back to
// the writer, until the connection is closed.
func echoAccept(conn net.Conn) {
	defer conn.Close()
	io.Copy(conn, conn)
}

func TestPortForwardEchoesRoundTrip(t *testing.T) {
	dialer := &pipeDialer{onAccept: echoAccept}

	pf, err := NewPortForward(PortForwardConfig{
		ListenAddr: "127.0.0.1:0",
		Dial:       dialer.Dial,
	})
	if err != nil {
		t.Fatalf("NewPortForward: %v", err)
	}
	defer pf.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pf.Serve(ctx)

	conn, err := net.Dial("tcp", pf.Addr().String())
	if err != nil {
		t.Fatalf("dial forwarded listener: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello guest")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("got %q, want %q", buf, msg)
	}
}

func TestPortForwardHandlesConcurrentConnections(t *testing.T) {
	dialer := &pipeDialer{onAccept: echoAccept}

	pf, err := NewPortForward(PortForwardConfig{
		ListenAddr: "127.0.0.1:0",
		Dial:       dialer.Dial,
	})
	if err != nil {
		t.Fatalf("NewPortForward: %v", err)
	}
	defer pf.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pf.Serve(ctx)

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", pf.Addr().String())
			if err != nil {
				t.Errorf("dial %d: %v", i, err)
				return
			}
			defer conn.Close()

			msg := []byte("ping")
			if _, err := conn.Write(msg); err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Errorf("read %d: %v", i, err)
				return
			}
			if !bytes.Equal(buf, msg) {
				t.Errorf("conn %d: got %q want %q", i, buf, msg)
			}
		}(i)
	}
	wg.Wait()

	if got := dialer.dialCount(); got != n {
		t.Fatalf("dial count = %d, want %d", got, n)
	}
}

func TestPortForwardClosingTCPSideClosesGuestSide(t *testing.T) {
	guestClosed := make(chan struct{})
	dialer := &pipeDialer{onAccept: func(conn net.Conn) {
		// Block on a read; when the host TCP side closes, the pipe
		// (relayed through io.Copy on the host side of the proxy)
		// should cause this end to observe EOF/closure too.
		buf := make([]byte, 1)
		conn.Read(buf)
		close(guestClosed)
		conn.Close()
	}}

	pf, err := NewPortForward(PortForwardConfig{
		ListenAddr: "127.0.0.1:0",
		Dial:       dialer.Dial,
	})
	if err != nil {
		t.Fatalf("NewPortForward: %v", err)
	}
	defer pf.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pf.Serve(ctx)

	conn, err := net.Dial("tcp", pf.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	select {
	case <-guestClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for guest side to observe closure")
	}
}

func TestPortForwardDialErrorClosesTCPConnRatherThanHanging(t *testing.T) {
	dialer := &pipeDialer{dialErr: errors.New("guest unreachable")}

	pf, err := NewPortForward(PortForwardConfig{
		ListenAddr: "127.0.0.1:0",
		Dial:       dialer.Dial,
	})
	if err != nil {
		t.Fatalf("NewPortForward: %v", err)
	}
	defer pf.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pf.Serve(ctx)

	conn, err := net.Dial("tcp", pf.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed after dial error, got a successful read")
	}
}

func TestPortForwardCloseStopsAcceptingAndUnblocksServe(t *testing.T) {
	dialer := &pipeDialer{onAccept: echoAccept}

	pf, err := NewPortForward(PortForwardConfig{
		ListenAddr: "127.0.0.1:0",
		Dial:       dialer.Dial,
	})
	if err != nil {
		t.Fatalf("NewPortForward: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- pf.Serve(context.Background())
	}()

	// Give Serve a moment to actually start Accept()-ing (avoids a
	// racy Close-before-Accept edge that isn't the thing under test).
	time.Sleep(20 * time.Millisecond)

	if err := pf.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-serveErr:
		if err == nil {
			t.Fatal("expected Serve to return a non-nil error after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Close")
	}

	if _, err := net.Dial("tcp", pf.Addr().String()); err == nil {
		t.Fatal("expected dial to closed listener to fail")
	}
}

func TestPortForwardServeRespectsContextCancellation(t *testing.T) {
	dialer := &pipeDialer{onAccept: echoAccept}

	pf, err := NewPortForward(PortForwardConfig{
		ListenAddr: "127.0.0.1:0",
		Dial:       dialer.Dial,
	})
	if err != nil {
		t.Fatalf("NewPortForward: %v", err)
	}
	defer pf.Close()

	ctx, cancel := context.WithCancel(context.Background())

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- pf.Serve(ctx)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-serveErr:
		if err == nil {
			t.Fatal("expected Serve to return non-nil after context cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}

func TestPortForwardRejectsNilDial(t *testing.T) {
	_, err := NewPortForward(PortForwardConfig{
		ListenAddr: "127.0.0.1:0",
		Dial:       nil,
	})
	if err == nil {
		t.Fatal("expected error for nil Dial func")
	}
}

func TestPortForwardBytesRelayedBothDirections(t *testing.T) {
	var guestReceived, guestSent atomic.Int64
	dialer := &pipeDialer{onAccept: func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		guestReceived.Add(int64(n))

		reply := bytes.Repeat([]byte("y"), 1000)
		nw, _ := conn.Write(reply)
		guestSent.Add(int64(nw))
	}}

	pf, err := NewPortForward(PortForwardConfig{
		ListenAddr: "127.0.0.1:0",
		Dial:       dialer.Dial,
	})
	if err != nil {
		t.Fatalf("NewPortForward: %v", err)
	}
	defer pf.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pf.Serve(ctx)

	conn, err := net.Dial("tcp", pf.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	sent := bytes.Repeat([]byte("x"), 500)
	if _, err := conn.Write(sent); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 1000)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for guestReceived.Load() != int64(len(sent)) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := guestReceived.Load(); got != int64(len(sent)) {
		t.Fatalf("guest received %d bytes, want %d", got, len(sent))
	}
}
