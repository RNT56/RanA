package service

import (
	"bufio"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/RNT56/RanA/internal/profile"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// SessionMarkerSocket is the per-session random path+token svc generates
// for a session's marker channel (docs/OPENCLAW.md: RANA_MARKER_SOCKET /
// RANA_MARKER_TOKEN). The token is a connection-level shared secret, not a
// per-line field an agent chooses — see MarkerListenerConfig.Token.
type SessionMarkerSocket struct {
	Path  string
	Token string
}

// NewSessionMarkerSocket generates a fresh unpredictable unix-socket path
// and bearer token for one session's marker channel, rooted under baseDir.
// Both are crypto/rand-derived so a co-resident, non-privileged process
// cannot guess either the path or the token (the marker channel's only
// authentication is knowing both).
func NewSessionMarkerSocket(baseDir, session string) (SessionMarkerSocket, error) {
	pathSuffix, err := randomToken(10) // 16 base32 chars
	if err != nil {
		return SessionMarkerSocket{}, err
	}
	token, err := randomToken(20) // 32 base32 chars
	if err != nil {
		return SessionMarkerSocket{}, err
	}
	name := fmt.Sprintf("rana-marker-%s-%s.sock", session, pathSuffix)
	return SessionMarkerSocket{
		Path:  filepath.Join(baseDir, name),
		Token: token,
	}, nil
}

func randomToken(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("service: generating random token: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// MarkerListenerConfig configures a MarkerListener.
type MarkerListenerConfig struct {
	// SocketPath is the unix socket path to bind (per session, per
	// NewSessionMarkerSocket).
	SocketPath string
	// Token is the per-session bearer token every marker line must carry
	// in its "token" field to be considered (see parseTokenLine). This is
	// intentionally a field on each JSON line rather than a connection- or
	// transport-level credential: a unix-domain socket at an unguessable
	// path is already a strong access control, and requiring the token on
	// every line means a process that merely inherited an open fd to the
	// socket (but was never told the token) still cannot inject events.
	Token string
	// Profile is the active session's [markers] table (allowlist +
	// denylist, event names). Emitting a MarkerListener with
	// Profile.Enabled == false is a caller error — see NewMarkerListener.
	Profile profile.Markers
	// Pipeline redacts every carried string field before it reaches Emit.
	Pipeline *redact.Pipeline
	// Session is the session id stamped on every emitted event.
	Session string
	// Emit receives every accepted, validated, redacted marker event ready
	// for ledger append (origin=enrichment already set). Required.
	Emit func(schema.Event) error
	// Clock supplies TsWall/TsMono-ish timestamps for markers, since a
	// marker's timing is svc-observed (arrival time), never agent-claimed.
	Clock Clock
}

// ErrMarkersDisabled is returned by NewMarkerListener when cfg.Profile is
// not enabled — svc must not open a marker socket for a profile that never
// declared one (P6/P7: no surprise capture surface).
var ErrMarkersDisabled = errors.New("service: profile does not enable markers")

// ErrNilEmit is returned by NewMarkerListener when cfg.Emit is nil.
var ErrNilEmit = errors.New("service: MarkerListenerConfig.Emit must not be nil")

// MarkerListener accepts connections on a per-session unix socket and turns
// well-formed, correctly-tokened, allowlisted marker lines into
// schema.Event values delivered to Emit. It never blocks a producer (P2
// spirit extended to enrichment: a slow/hostile marker sender can only hurt
// itself, never the capture pipeline) and never lets malformed input crash
// the listener or leak content (P7/P3).
type MarkerListener struct {
	cfg      MarkerListenerConfig
	ln       net.Listener
	idx      atomic.Uint64
	closeOne sync.Once
}

// NewMarkerListener binds cfg.SocketPath and returns a MarkerListener ready
// for Serve. The socket is created 0600-ish via unix semantics (default
// unix socket permissions plus the same-uid guarantee of the containing
// per-session directory, which is the caller's responsibility to make
// non-world-readable).
func NewMarkerListener(cfg MarkerListenerConfig) (*MarkerListener, error) {
	if !cfg.Profile.Enabled {
		return nil, ErrMarkersDisabled
	}
	if cfg.Emit == nil {
		return nil, ErrNilEmit
	}
	if cfg.Clock == nil {
		cfg.Clock = SystemClock
	}

	_ = os.Remove(cfg.SocketPath) // stale socket from a crashed prior run
	ln, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("service: binding marker socket %s: %w", cfg.SocketPath, err)
	}
	_ = os.Chmod(cfg.SocketPath, 0o600)

	return &MarkerListener{cfg: cfg, ln: ln}, nil
}

// Close closes the listener and removes the socket file. Idempotent.
func (m *MarkerListener) Close() error {
	var err error
	m.closeOne.Do(func() {
		err = m.ln.Close()
		_ = os.Remove(m.cfg.SocketPath)
	})
	return err
}

// Serve accepts connections until the listener is closed, handling each
// connection's ndjson lines synchronously in its own goroutine. Serve
// returns nil when the listener is closed cleanly (Close was called).
func (m *MarkerListener) Serve() error {
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("service: accepting marker connection: %w", err)
		}
		go m.handleConn(conn)
	}
}

// markerLine is the wire shape of one ndjson line: the token plus whatever
// the profile's [markers] table allows through parseMarkerLine.
type markerLineEnvelope struct {
	Token string `json:"token"`
}

func (m *MarkerListener) handleConn(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	// Cap the scanner's buffer at slightly above maxMarkerLineBytes so an
	// oversized line is reported as a token error (bufio.ErrTooLong) rather
	// than silently growing an unbounded buffer — a hostile sender must not
	// be able to make svc allocate without bound (P2-adjacent: enrichment
	// ingestion must stay cheap to reject).
	scanner.Buffer(make([]byte, 0, maxMarkerLineBytes+64), maxMarkerLineBytes+64)

	for scanner.Scan() {
		line := scanner.Bytes()
		m.handleLine(line)
	}
	// scanner.Err() on ErrTooLong or a transport error simply ends the loop;
	// there is nothing further to emit and nothing to crash. A future line
	// on a NEW connection is unaffected.
}

func (m *MarkerListener) handleLine(line []byte) {
	if len(line) == 0 {
		return
	}
	if len(line) > maxMarkerLineBytes {
		return
	}

	var env markerLineEnvelope
	if err := json.Unmarshal(line, &env); err != nil {
		return
	}
	if !constantTimeTokenEq(env.Token, m.cfg.Token) {
		return
	}

	idx := m.idx.Add(1)
	now := m.cfg.Clock.Now()
	ev, err := parseMarkerLine(line, m.cfg.Profile, m.cfg.Pipeline, markerContext{
		Session: m.cfg.Session,
		Idx:     idx,
		TsMono:  uint64(now.UnixNano()),
		TsWall:  uint64(now.UnixNano()),
	})
	if err != nil {
		return
	}

	// The listener discards Emit's error here (it must keep serving), but the
	// error is not lost: svc's Emit callback (emitMarker, lifecycle.go)
	// surfaces any failure — including a fatal Writer.Err() commit failure —
	// to Config.OnFault before returning (P5: losses are loud on every
	// ingress, symmetric with the kernel-event path).
	_ = m.cfg.Emit(ev)
}

// constantTimeTokenEq compares two tokens without leaking a timing side
// channel proportional to the matching prefix length (defense in depth —
// the token is per-session and short-lived, but there is no reason to take
// the cheap-and-wrong path, mirroring internal/ui's constantTimeEq).
func constantTimeTokenEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
