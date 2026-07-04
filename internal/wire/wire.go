// Package wire implements RanA's framed unix-socket protocol between ranad
// (the privileged, root-owned collector) and svc (the user-owned session
// service) — CONTRACTS §internal/wire.
//
// A frame is a uvarint-encoded length prefix followed by a canonical CBOR
// body (internal/cborcanon), capped at MaxFrameSize. The codec is pure: it
// operates over any io.Reader/io.Writer and is fully testable with
// bytes.Buffer — no socket is required to exercise it (P2: this package
// itself never blocks on or inspects syscalls; peer-credential helpers are a
// thin, separate concern used once at connection setup, not per-frame).
//
// Frame bodies never carry raw strings: Hello/Head/Bye payloads are numeric
// or byte-oriented by construction, and Ev carries pre-encoded,
// already-canonical event bytes (produced by cborcanon.EncodeEvent
// upstream) as an opaque []byte — wire does not decode or re-validate event
// contents, it only transports them.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/RNT56/RanA/internal/cborcanon"
)

// MaxFrameSize is the maximum permitted encoded body size for a single
// frame (CONTRACTS §internal/wire: "Max frame 1MiB").
const MaxFrameSize = 1 << 20 // 1 MiB

// ErrFrameTooLarge is returned by WriteFrame when a frame's encoded body
// would exceed MaxFrameSize, and by ReadFrame when the declared length
// prefix alone already exceeds MaxFrameSize (rejected before any attempt to
// read or allocate the body).
var ErrFrameTooLarge = errors.New("wire: frame exceeds max size (1MiB)")

// ErrTornFrame is returned by ReadFrame when a length prefix or frame body
// is truncated (a partial frame reached EOF mid-read). It is distinct from
// a clean io.EOF at a frame boundary, which is the normal end-of-stream
// signal.
var ErrTornFrame = errors.New("wire: torn frame (truncated length prefix or body)")

// ErrUnknownFrameTag is returned by ReadFrame when a body decodes as
// well-formed canonical CBOR but does not match the shape of any known
// frame type.
var ErrUnknownFrameTag = errors.New("wire: unrecognized frame tag")

// ErrInvalidHello is returned when a Hello frame carries a Role outside the
// known set (RoleRanad, RoleSVC), or a V that does not equal Version.
var ErrInvalidHello = errors.New("wire: invalid Hello frame")

// Role identifies which side of the ranad<->svc connection sent a Hello.
const (
	RoleRanad = "ranad"
	RoleSVC   = "svc"
)

var knownRoles = map[string]bool{
	RoleRanad: true,
	RoleSVC:   true,
}

// Version is the wire protocol version this package speaks: 1 in v1
// (CONTRACTS §internal/wire: "V uint8 // wire protocol version; 1 in v1").
// WriteFrame and ReadFrame both reject any Hello whose V does not equal
// Version — silently accepting an unknown version (or, worse, silently
// truncating an out-of-range wire value into a byte that happens to match
// Version) would let an incompatible future peer be misinterpreted as
// speaking today's protocol.
const Version uint8 = 1

// Frame is any of the four wire frame types: Hello, Ev, Head, Bye.
type Frame interface {
	frameTag() string
}

// Hello is the first frame sent on a new connection, identifying the
// sender's role and carrying the redaction salt (already-generated, never
// derived from environment — P3) so both sides agree on it out of band from
// any secret material.
type Hello struct {
	V    uint8  // wire protocol version; 1 in v1
	Role string // sender's role: RoleRanad or RoleSVC
	Salt []byte // redaction salt, agreed out of band from any secret material
}

func (*Hello) frameTag() string { return "hello" }

// Ev carries one pre-encoded, canonical event (cborcanon.EncodeEvent
// output) as opaque bytes. wire does not decode the event; the receiver is
// responsible for validating and persisting it.
type Ev struct {
	Event []byte // canonical CBOR bytes of a schema.Event, as produced by cborcanon.EncodeEvent
}

func (*Ev) frameTag() string { return "ev" }

// HeadReport mirrors chain.HeadReport's fields (CONTRACTS §internal/chain).
// wire defines its own copy rather than importing internal/chain: the
// package graph places wire's own (non-test) dependency at {cborcanon} only,
// and HeadReport is a plain data shape with no chain-package behavior
// attached, so duplicating the field set here keeps that dependency edge
// honest. If internal/chain's HeadReport ever diverges from this shape, that
// is a contract break to flag, not something wire should paper over.
type HeadReport struct {
	SessionID string   // session id (ULID-format string) the checkpoint belongs to
	SegLast   uint64   // last segment index covered by the checkpoint
	ChainHead [32]byte // BLAKE3 seg_hash of the last segment (chain.SegHash)
	CkptHash  [32]byte // hash of the signed checkpoint body (chain.CheckpointHash)
	At        uint64   // wall-clock ns the checkpoint was signed
}

// Head reports a checkpoint's chain head to the peer.
type Head struct {
	Report HeadReport // the checkpoint summary being reported
}

func (*Head) frameTag() string { return "head" }

// SessionEnd tells ranad that a recorded session has ended (its cgroup scope
// emptied, or `rana stop`), so ranad can evict that session's per-session
// collector state (rate-governor buckets, segment tracker, exe-provenance
// seen-map) — otherwise a long-lived ranad accumulates one such entry per
// session it ever observed. It travels the same svc->ranad reverse channel as
// Head. It carries only the session id (an opaque ULID), never any content.
type SessionEnd struct {
	Session string // session id whose collector state ranad should release
}

func (*SessionEnd) frameTag() string { return "session_end" }

// Bye signals a clean, intentional connection close.
type Bye struct{}

func (*Bye) frameTag() string { return "bye" }

// ---- wire encodings (internal, not exported types) ----
//
// Each frame type gets its own small CBOR-tagged struct so ReadFrame can
// distinguish frame kinds unambiguously: every wire body is a one-key map
// whose single key is the frame tag, mapping to the frame's fields. This
// avoids inventing a numeric discriminant while still giving
// ReadFrame an exact, non-guessing dispatch.

type wireHello struct {
	V    uint64 `cbor:"v"`
	Role string `cbor:"role"`
	Salt []byte `cbor:"salt"`
}

type wireEv struct {
	Event []byte `cbor:"event"`
}

type wireHead struct {
	SessionID string `cbor:"session_id"`
	SegLast   uint64 `cbor:"seg_last"`
	ChainHead []byte `cbor:"chain_head"`
	CkptHash  []byte `cbor:"ckpt_hash"`
	At        uint64 `cbor:"at"`
}

type wireBye struct{}

type wireSessionEnd struct {
	Session string `cbor:"session"`
}

type wireEnvelope struct {
	Hello      *wireHello      `cbor:"hello,omitempty"`
	Ev         *wireEv         `cbor:"ev,omitempty"`
	Head       *wireHead       `cbor:"head,omitempty"`
	SessionEnd *wireSessionEnd `cbor:"session_end,omitempty"`
	Bye        *wireBye        `cbor:"bye,omitempty"`
}

// WriteFrame encodes f as a length-prefixed canonical CBOR frame and writes
// it to w. It returns ErrFrameTooLarge if the encoded body would exceed
// MaxFrameSize, and ErrInvalidHello if f is a Hello with an unknown Role or
// a V that does not equal Version.
func WriteFrame(w io.Writer, f Frame) error {
	env, err := toEnvelope(f)
	if err != nil {
		return err
	}

	body, err := cborcanon.Encode(env)
	if err != nil {
		return fmt.Errorf("wire: encode frame body: %w", err)
	}
	if len(body) > MaxFrameSize {
		return fmt.Errorf("%w: body is %d bytes", ErrFrameTooLarge, len(body))
	}

	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], uint64(len(body)))

	if _, err := w.Write(lenBuf[:n]); err != nil {
		return fmt.Errorf("wire: write length prefix: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("wire: write frame body: %w", err)
	}
	return nil
}

func toEnvelope(f Frame) (wireEnvelope, error) {
	switch v := f.(type) {
	case *Hello:
		if v.V != Version {
			return wireEnvelope{}, fmt.Errorf("%w: version %d (want %d)", ErrInvalidHello, v.V, Version)
		}
		if !knownRoles[v.Role] {
			return wireEnvelope{}, fmt.Errorf("%w: role %q", ErrInvalidHello, v.Role)
		}
		return wireEnvelope{Hello: &wireHello{V: uint64(v.V), Role: v.Role, Salt: v.Salt}}, nil
	case *Ev:
		return wireEnvelope{Ev: &wireEv{Event: v.Event}}, nil
	case *Head:
		ch := append([]byte(nil), v.Report.ChainHead[:]...)
		ck := append([]byte(nil), v.Report.CkptHash[:]...)
		return wireEnvelope{Head: &wireHead{
			SessionID: v.Report.SessionID,
			SegLast:   v.Report.SegLast,
			ChainHead: ch,
			CkptHash:  ck,
			At:        v.Report.At,
		}}, nil
	case *SessionEnd:
		return wireEnvelope{SessionEnd: &wireSessionEnd{Session: v.Session}}, nil
	case *Bye:
		return wireEnvelope{Bye: &wireBye{}}, nil
	default:
		return wireEnvelope{}, fmt.Errorf("wire: unknown frame type %T", f)
	}
}

// ReadFrame reads and decodes exactly one frame from r.
//
// It returns io.EOF (unwrapped, checkable with errors.Is) only when zero
// bytes could be read at a clean frame boundary. Any truncation after that
// point — a partial length prefix or a short body — is reported as an error
// wrapping ErrTornFrame/io.ErrUnexpectedEOF, never as a bare io.EOF, so
// callers can distinguish "stream ended cleanly" from "stream ended mid-
// frame". A declared length exceeding MaxFrameSize is rejected via
// ErrFrameTooLarge before any attempt to read or allocate the body.
func ReadFrame(r io.Reader) (Frame, error) {
	length, err := readUvarint(r)
	if err != nil {
		return nil, err
	}
	if length > MaxFrameSize {
		return nil, fmt.Errorf("%w: declared length %d", ErrFrameTooLarge, length)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("%w: %w", ErrTornFrame, io.ErrUnexpectedEOF)
		}
		return nil, fmt.Errorf("wire: read frame body: %w", err)
	}

	var env wireEnvelope
	if err := cborcanon.Decode(body, &env); err != nil {
		return nil, fmt.Errorf("wire: decode frame body: %w", err)
	}

	return fromEnvelope(env)
}

func fromEnvelope(env wireEnvelope) (Frame, error) {
	set := 0
	var f Frame
	if env.Hello != nil {
		set++
		// Reject out-of-uint8-range V before narrowing: uint8(env.Hello.V)
		// would otherwise silently wrap (e.g. 257 -> 1), letting a malformed
		// or hostile V value masquerade as a legitimate Version.
		if env.Hello.V > 255 {
			return nil, fmt.Errorf("%w: version %d out of range", ErrInvalidHello, env.Hello.V)
		}
		if uint8(env.Hello.V) != Version {
			return nil, fmt.Errorf("%w: version %d (want %d)", ErrInvalidHello, env.Hello.V, Version)
		}
		if !knownRoles[env.Hello.Role] {
			return nil, fmt.Errorf("%w: role %q", ErrInvalidHello, env.Hello.Role)
		}
		f = &Hello{V: uint8(env.Hello.V), Role: env.Hello.Role, Salt: env.Hello.Salt}
	}
	if env.Ev != nil {
		set++
		f = &Ev{Event: env.Ev.Event}
	}
	if env.Head != nil {
		set++
		hd := Head{Report: HeadReport{
			SessionID: env.Head.SessionID,
			SegLast:   env.Head.SegLast,
			At:        env.Head.At,
		}}
		copy(hd.Report.ChainHead[:], env.Head.ChainHead)
		copy(hd.Report.CkptHash[:], env.Head.CkptHash)
		f = &hd
	}
	if env.SessionEnd != nil {
		set++
		f = &SessionEnd{Session: env.SessionEnd.Session}
	}
	if env.Bye != nil {
		set++
		f = &Bye{}
	}

	if set != 1 {
		return nil, fmt.Errorf("%w: envelope carries %d recognized frame kinds (want exactly 1)", ErrUnknownFrameTag, set)
	}
	return f, nil
}

// readUvarint reads a uvarint length prefix a byte at a time (io.Reader
// gives us nothing better to work with portably) and distinguishes a clean
// end-of-stream (io.EOF on the very first byte) from a torn prefix (EOF
// after at least one byte, or a malformed/overlong varint).
func readUvarint(r io.Reader) (uint64, error) {
	var buf [1]byte
	var result uint64
	var shift uint

	for i := 0; i < binary.MaxVarintLen64; i++ {
		n, err := r.Read(buf[:])
		if n == 0 && err != nil {
			if i == 0 && errors.Is(err, io.EOF) {
				return 0, io.EOF
			}
			return 0, fmt.Errorf("%w: %v", ErrTornFrame, err)
		}
		if n == 0 {
			// Reader returned (0, nil): treat as no progress, not infinite
			// loop; surface as torn rather than spin.
			return 0, fmt.Errorf("%w: reader made no progress", ErrTornFrame)
		}

		b := buf[0]
		if i == binary.MaxVarintLen64-1 && b > 1 {
			// The 10th byte may only contribute bit 63; anything larger
			// overflows uint64. Discarding the excess (as a naive shift
			// would) accepts non-injective encodings — reject instead.
			return 0, fmt.Errorf("%w: uvarint length prefix overflows uint64", ErrTornFrame)
		}
		if b < 0x80 {
			if b == 0 && i > 0 {
				// A zero terminal byte after continuation bytes is an
				// overlong (non-minimal) encoding; canonical uvarints are
				// injective, so reject it rather than aliasing lengths.
				return 0, fmt.Errorf("%w: non-canonical uvarint length prefix", ErrTornFrame)
			}
			result |= uint64(b) << shift
			return result, nil
		}
		result |= uint64(b&0x7f) << shift
		shift += 7
	}
	return 0, fmt.Errorf("%w: uvarint length prefix too long", ErrTornFrame)
}
