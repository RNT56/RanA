package service

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/schema"
	"github.com/RNT56/RanA/internal/wire"
)

// Appender is the subset of *ledger.Writer the ranad wire server depends
// on: accept an already-decoded schema.Event for persistence. Depending on
// this narrow interface (rather than *ledger.Writer directly) keeps the
// server unit-testable against a fake without spinning up SQLite.
// Appender persists events arriving over the ranad socket. The wire delivers
// each event's canonical CBOR bytes already redacted and guard-checked by
// ranad (cborcanon.EncodeEvent ran upstream before the wire), so the svc hands
// those exact bytes to the ledger rather than decode-and-re-encode:
// re-encoding would lose the redact.Redacted type on every string field and
// spuriously reject already-redacted data. AppendEncoded takes the decoded
// envelope (for indexing) plus the original canonical bytes (to hash and
// store), matching docs/TRUST.md §7's "hash the given bytes, do not re-encode".
type Appender interface {
	AppendEncoded(ev schema.Event, enc []byte) error
}

// ErrWrongHelloRole is returned by HandleConn when the peer's Hello frame
// does not declare wire.RoleRanad — the ranad-facing socket only ever
// speaks to the ranad role (docs/ARCHITECTURE.md §2).
var ErrWrongHelloRole = errors.New("service: expected a ranad-role Hello on the ranad socket")

// ErrNoHelloFirst is returned when the first frame on a connection is not
// a Hello.
var ErrNoHelloFirst = errors.New("service: first frame on ranad socket must be Hello")

// RanadServerConfig configures a RanadServer.
type RanadServerConfig struct {
	// Appender receives every decoded event (typically *ledger.Writer).
	// Required.
	Appender Appender
	// RequirePeerUID, when non-nil, is checked against the connecting
	// peer's SO_PEERCRED/LOCAL_PEERCRED uid (wire.PeerCred) for
	// *net.UnixConn connections; a mismatch rejects the connection before
	// any frame is processed (docs/ARCHITECTURE.md §2: "SO_PEERCRED-gated
	// to owner uid"). nil disables the check (used in tests that connect
	// over net.Pipe, which has no peer credentials to check at all).
	RequirePeerUID *uint32
	// OnDecodeError, if set, is called for a frame that fails to decode
	// into a schema.Event or fails ledger append — non-fatal to the
	// connection (CONTRACTS: a hostile/malformed frame must not be able to
	// take down the whole ranad<->svc link), but svc needs visibility.
	OnDecodeError func(error)
}

// RanadServer accepts connections from ranad (the privileged collector,
// docs/ARCHITECTURE.md §2) speaking the internal/wire framed protocol:
// Hello{role=ranad} first, then a stream of Ev frames (each appended to the
// configured Appender), until Bye or the connection closes. It also sends
// Head frames back to ranad on each ledger checkpoint via
// ledger.HeadReportFunc, wired externally to call SendHead on the
// currently-active connection(s) — see Service.wireHeadReports.
type RanadServer struct {
	cfg RanadServerConfig

	mu    sync.Mutex
	conns map[*ranadConn]struct{}
}

// NewRanadServer constructs a RanadServer. Binding a listener socket is the
// caller's job (docs/ARCHITECTURE.md: "unix socket, SO_PEERCRED-gated to
// owner uid") — RanadServer itself only knows how to handle one accepted
// connection at a time via HandleConn, so it is testable without any
// socket at all (net.Pipe suffices, see ranad_server_test.go).
func NewRanadServer(cfg RanadServerConfig) *RanadServer {
	return &RanadServer{cfg: cfg, conns: make(map[*ranadConn]struct{})}
}

// ranadConn wraps one accepted connection so SendHead can be targeted at
// it later (from the ledger's checkpoint callback, which fires on the
// writer goroutine, not from within HandleConn's own read loop).
type ranadConn struct {
	conn net.Conn
	mu   sync.Mutex // guards writes (WriteFrame is not safe for concurrent callers)
}

func (c *ranadConn) close() error { return c.conn.Close() }

// SendHead frames and writes r to this connection's ranad peer
// (docs/TRUST.md §5: "the session service reports ... to ranad").
func (c *ranadConn) SendHead(r chain.HeadReport) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return wire.WriteFrame(c.conn, &wire.Head{Report: toWireHeadReport(r)})
}

// SendSessionEnd tells this connection's ranad peer that a session has ended,
// so ranad can release that session's per-session collector state. Best-effort
// on the same reverse channel as SendHead; carries only the session id.
func (c *ranadConn) SendSessionEnd(session string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return wire.WriteFrame(c.conn, &wire.SessionEnd{Session: session})
}

// toWireHeadReport converts a chain.HeadReport to wire's own identically-
// shaped HeadReport type (internal/wire deliberately does not import
// internal/chain — see wire.HeadReport's doc comment).
func toWireHeadReport(r chain.HeadReport) wire.HeadReport {
	return wire.HeadReport{
		SessionID: r.SessionID,
		SegLast:   r.SegLast,
		ChainHead: r.ChainHead,
		CkptHash:  r.CkptHash,
		At:        r.At,
	}
}

// registerForTest exposes the connection-registration path so tests can
// obtain a *ranadConn (and thus exercise SendHead) without going through
// the full accept-loop plumbing of a real listener.
func (s *RanadServer) registerForTest(conn net.Conn) *ranadConn {
	return s.register(conn)
}

func (s *RanadServer) register(conn net.Conn) *ranadConn {
	rc := &ranadConn{conn: conn}
	s.mu.Lock()
	s.conns[rc] = struct{}{}
	s.mu.Unlock()
	return rc
}

func (s *RanadServer) unregister(rc *ranadConn) {
	s.mu.Lock()
	delete(s.conns, rc)
	s.mu.Unlock()
}

// Broadcast sends r to every currently-registered ranad connection. In
// practice v1 expects exactly one live ranad<->svc connection at a time,
// but the server does not assume that structurally.
func (s *RanadServer) Broadcast(r chain.HeadReport) {
	s.mu.Lock()
	conns := make([]*ranadConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	for _, c := range conns {
		_ = c.SendHead(r) // best-effort: a HeadReport that fails to reach ranad still had its local durable side-effect (docs/TRUST.md heads.log fallback is svc's job, see digest.go's local mirror)
	}
}

// BroadcastSessionEnd tells every registered ranad connection that session has
// ended so ranad evicts its per-session collector state. Best-effort: if ranad
// is not connected, the state is released the next time ranad restarts (a
// fresh ranad has no accumulated state) — nothing is lost by a dropped signal
// except a bounded delay in reclaiming memory.
func (s *RanadServer) BroadcastSessionEnd(session string) {
	s.mu.Lock()
	conns := make([]*ranadConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	for _, c := range conns {
		_ = c.SendSessionEnd(session)
	}
}

// Serve accepts connections on ln until it is closed, handling each with
// HandleConn in its own goroutine. Serve returns nil when ln is closed
// cleanly.
func (s *RanadServer) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("service: accepting ranad connection: %w", err)
		}
		go func() {
			if err := s.HandleConn(conn); err != nil && s.cfg.OnDecodeError != nil {
				s.cfg.OnDecodeError(err)
			}
		}()
	}
}

// HandleConn drives one accepted connection to completion: verifies the
// peer credential (if configured and the connection is a *net.UnixConn),
// requires a ranad-role Hello first, then loops decoding Ev frames into
// the Appender until Bye or the peer closes the connection. A single
// malformed Ev frame or a failed Append is reported via OnDecodeError (if
// set) but does not terminate the connection — CONTRACTS requires a
// hostile marker to be "rejected or stripped, NEVER... crash"; the same
// discipline is applied here defensively even though ranad is the
// privileged, normally-trusted peer, since P2's "ranad dying must not hurt
// the agent" spirit extends to "a malformed ranad frame must not hurt
// svc".
func (s *RanadServer) HandleConn(conn net.Conn) error {
	defer conn.Close()

	if s.cfg.RequirePeerUID != nil {
		if uc, ok := conn.(*net.UnixConn); ok {
			uid, err := wire.PeerCred(uc)
			if err != nil {
				return fmt.Errorf("service: peer credential check failed: %w", err)
			}
			if uid != *s.cfg.RequirePeerUID {
				return fmt.Errorf("service: rejecting ranad connection from uid %d (want %d)", uid, *s.cfg.RequirePeerUID)
			}
		}
	}

	first, err := wire.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoHelloFirst, err)
	}
	hello, ok := first.(*wire.Hello)
	if !ok {
		return ErrNoHelloFirst
	}
	if hello.Role != wire.RoleRanad {
		return fmt.Errorf("%w: got role %q", ErrWrongHelloRole, hello.Role)
	}

	rc := s.register(conn)
	defer s.unregister(rc)

	for {
		f, err := wire.ReadFrame(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("service: reading ranad frame: %w", err)
		}

		switch v := f.(type) {
		case *wire.Ev:
			if err := s.appendEv(v); err != nil && s.cfg.OnDecodeError != nil {
				s.cfg.OnDecodeError(err)
			}
		case *wire.Bye:
			return nil
		case *wire.Hello:
			// A second Hello mid-stream is not part of the protocol;
			// tolerate it as a no-op rather than tearing down the
			// connection over a peer quirk.
			continue
		default:
			if s.cfg.OnDecodeError != nil {
				s.cfg.OnDecodeError(fmt.Errorf("service: unexpected frame type %T on ranad socket", f))
			}
		}
	}
}

func (s *RanadServer) appendEv(f *wire.Ev) error {
	var ev schema.Event
	if err := decodeEventFrame(f.Event, &ev); err != nil {
		return fmt.Errorf("service: decoding Ev frame: %w", err)
	}
	// Persist the wire's canonical bytes verbatim — do not re-encode (see
	// Appender's doc comment: re-encoding loses the redact.Redacted type and
	// would reject already-redacted data). f.Event is exactly the bytes ev
	// was just decoded from.
	if err := s.cfg.Appender.AppendEncoded(ev, f.Event); err != nil {
		return fmt.Errorf("service: appending kernel event to ledger: %w", err)
	}
	return nil
}

// decodeEventFrame decodes canonical CBOR event bytes (as produced by
// cborcanon.EncodeEvent) back into a schema.Event. cborcanon.Decode is
// generic (strict, struct-typed); this wraps it with the same field-name
// mapping cborcanon.EncodeEvent uses on the way out, so the ranad socket's
// receive path is the exact inverse of the send path used throughout the
// rest of the codebase (wire, ledger tests) and by cmd/ranad.
func decodeEventFrame(b []byte, out *schema.Event) error {
	var env struct {
		V       uint8          `cbor:"v"`
		Type    string         `cbor:"type"`
		Session string         `cbor:"session"`
		Seg     uint64         `cbor:"seg"`
		Idx     uint64         `cbor:"idx"`
		TsMono  uint64         `cbor:"ts_mono"`
		TsWall  uint64         `cbor:"ts_wall"`
		Pid     uint32         `cbor:"pid"`
		Origin  string         `cbor:"origin"`
		State   string         `cbor:"state"`
		Data    map[string]any `cbor:"data"`
	}
	if err := cborcanon.Decode(b, &env); err != nil {
		return err
	}
	*out = schema.Event{
		V:       env.V,
		Type:    schema.EventType(env.Type),
		Session: env.Session,
		Seg:     env.Seg,
		Idx:     env.Idx,
		TsMono:  env.TsMono,
		TsWall:  env.TsWall,
		Pid:     env.Pid,
		Origin:  schema.Origin(env.Origin),
		State:   schema.State(env.State),
		Data:    env.Data,
	}
	return nil
}
