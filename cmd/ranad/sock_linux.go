//go:build linux

package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/RNT56/RanA/internal/wire"
)

// randRead fills b with cryptographically random bytes (used only for the
// once-per-install redaction salt — never for anything secret-derived from
// process environment, P3).
func randRead(b []byte) (int, error) {
	return rand.Read(b)
}

// connFrameSink adapts a *net.UnixConn to the portable FrameSink interface
// pump.go depends on. It is the only place in this package that touches a
// real socket; everything else in the pump is exercised through fakeSink
// in tests.
type connFrameSink struct {
	conn *net.UnixConn
}

func newConnFrameSink(conn *net.UnixConn) *connFrameSink {
	return &connFrameSink{conn: conn}
}

func (s *connFrameSink) Send(f wire.Frame) error {
	return wire.WriteFrame(s.conn, f)
}

// Recv reads one frame with a short deadline so the daemon's inbound loop
// can poll cooperatively against ctx cancellation instead of blocking
// forever on a socket read (outboundLoop/inboundLoop in main_linux.go both
// tick on a short interval already). A deadline timeout is reported via
// ErrNoMoreFrames so PumpInbound treats it as "nothing available right
// now", not a broken connection; any other read error is a genuine
// connection failure and is propagated as-is.
func (s *connFrameSink) Recv() (wire.Frame, error) {
	if err := s.conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		return nil, fmt.Errorf("ranad: setting read deadline: %w", err)
	}
	f, err := wire.ReadFrame(s.conn)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, ErrNoMoreFrames
		}
		return nil, err
	}
	return f, nil
}

func (s *connFrameSink) Close() error {
	return s.conn.Close()
}
