package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// DialFunc opens a connection to the guest-side service being forwarded.
// In production this dials a vsock port (Code-Hex/vz exposes vsock as a
// net.Conn — docs/ARCHITECTURE.md §6.2 "Control/data plane: vsock ...
// exposes it as net.Conn"); in tests it is any injected fake, typically
// backed by net.Pipe (CONTRACTS §internal/vm: "vsock-dialer-func <-> TCP
// listener proxy using an injected dialer"). DialFunc must not itself
// retry; PortForward calls it once per accepted TCP connection.
type DialFunc func(ctx context.Context) (net.Conn, error)

// ErrNilDial is returned by NewPortForward when Dial is nil.
var ErrNilDial = errors.New("vm: PortForwardConfig.Dial must not be nil")

// PortForwardConfig configures a PortForward proxy.
type PortForwardConfig struct {
	// ListenAddr is the host TCP address to listen on, e.g.
	// "127.0.0.1:18789" or "127.0.0.1:0" to pick a free port
	// (docs/ARCHITECTURE.md §6.2 "vsock<->TCP proxy forwards adopted
	// services' listening ports ... to host localhost").
	ListenAddr string

	// Dial opens one connection to the guest-side target for each
	// accepted host TCP connection.
	Dial DialFunc
}

// PortForward re-exposes a guest-side service (reached via Dial, normally
// a vsock port) as a host TCP listener, relaying bytes unmodified in both
// directions (docs/MACOS.md "Port-forward: vsock<->TCP proxy re-exposing
// adopted services' listening ports ... on host localhost").
//
// PortForward performs no inspection or modification of the relayed
// stream — it is a byte-transparent proxy, consistent with P2 (observation
// is inert): this package is not in the eBPF observe path at all, but the
// same "never interfere with agent traffic" posture applies to the
// forwarded connection.
type PortForward struct {
	dial DialFunc
	ln   net.Listener

	closeOnce sync.Once
	closeErr  error
}

// NewPortForward creates a PortForward and binds its host TCP listener
// immediately (so Addr() is valid right after construction, before Serve
// is called). It does not start relaying connections; call Serve for that.
func NewPortForward(cfg PortForwardConfig) (*PortForward, error) {
	if cfg.Dial == nil {
		return nil, ErrNilDial
	}

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("vm: listen on %q: %w", cfg.ListenAddr, err)
	}

	return &PortForward{dial: cfg.Dial, ln: ln}, nil
}

// Addr returns the address the host TCP listener is bound to.
func (pf *PortForward) Addr() net.Addr {
	return pf.ln.Addr()
}

// Serve accepts host TCP connections until ctx is cancelled or Close is
// called, relaying each to a freshly dialed guest-side connection. It
// always returns a non-nil error (ctx.Err() on cancellation, or the
// listener's closed-error otherwise) once it stops.
func (pf *PortForward) Serve(ctx context.Context) error {
	// Closing the listener when ctx is cancelled is what makes the
	// blocking Accept() below return promptly; without this, Serve
	// would only observe cancellation on the next accepted connection
	// (or never, if none arrive).
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			pf.ln.Close()
		case <-stop:
		}
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := pf.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			pf.relay(ctx, conn)
		}()
	}
}

// relay dials the guest side for one accepted host connection and copies
// bytes in both directions until either side closes.
func (pf *PortForward) relay(ctx context.Context, hostConn net.Conn) {
	defer hostConn.Close()

	guestConn, err := pf.dial(ctx)
	if err != nil {
		// No guest-side reachable: close the host connection rather
		// than hang it open with nothing on the other end (an agent
		// connecting to a dead forwarded port sees a clean
		// connection-closed, not an indefinite stall).
		return
	}
	defer guestConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(guestConn, hostConn)
		// The host->guest direction is done (host side reached EOF,
		// e.g. because it closed). Signal that to the guest side: a
		// real half-close (CloseWrite) if the connection type
		// supports it, leaving the guest->host direction free to
		// keep draining any in-flight reply; otherwise (e.g.
		// net.Pipe, which has no half-close, used by tests in place
		// of a real vsock conn) fully close guestConn so a peer
		// blocked reading on it unblocks rather than deadlocking
		// forever waiting for bytes that will never come.
		if !closeWrite(guestConn) {
			guestConn.Close()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(hostConn, guestConn)
		if !closeWrite(hostConn) {
			hostConn.Close()
		}
	}()
	wg.Wait()

	// Both directions have finished. The deferred Close calls in
	// relay's caller close both ends unconditionally as a backstop,
	// but that's already covered above for connections without
	// half-close support; for real half-closable connections the
	// caller's defers provide the final full teardown.
}

// halfCloser is implemented by net.Conn types that support a half-close
// (e.g. *net.TCPConn's CloseWrite). Used so that finishing one direction
// of the relay signals EOF to the peer without tearing down the other
// direction still in flight.
type halfCloser interface {
	CloseWrite() error
}

// closeWrite half-closes conn's write side if it supports it, reporting
// whether it did. Callers that get false back are responsible for a full
// Close instead, since the connection type has no way to signal EOF to
// its peer short of closing entirely.
func closeWrite(conn net.Conn) bool {
	hc, ok := conn.(halfCloser)
	if !ok {
		return false
	}
	return hc.CloseWrite() == nil
}

// Close stops the listener, causing any in-progress Serve call to return.
// It is idempotent and safe to call multiple times or concurrently with
// Serve.
func (pf *PortForward) Close() error {
	pf.closeOnce.Do(func() {
		pf.closeErr = pf.ln.Close()
	})
	return pf.closeErr
}
