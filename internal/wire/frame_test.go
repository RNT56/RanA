// Frame codec tests (TDD: written before frame.go). Pure, over bytes.Buffer —
// no sockets here (peer-credential tests live in peercred_test.go /
// peercred_darwin_test.go).
package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/RNT56/RanA/internal/schema"
)

func mustEvent(t *testing.T) schema.Event {
	t.Helper()
	return schema.NewSessionEnd("01ARZ3NDEKTSV4RRFFQ69G5FAV", 0, 1, 1000, 2000, 42)
}

func TestWriteReadFrame_RoundTrip(t *testing.T) {
	ev := mustEvent(t)
	evBytes, err := encodeEventForTest(ev)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}

	cases := []struct {
		name string
		f    Frame
	}{
		{"hello", &Hello{V: 1, Role: RoleSVC, Salt: []byte{0x01, 0x02, 0x03, 0x04}}},
		{"hello-ranad-empty-salt", &Hello{V: 1, Role: RoleRanad, Salt: nil}},
		{"ev", &Ev{Event: evBytes}},
		{"head", &Head{Report: HeadReport{
			SessionID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
			SegLast:   7,
			ChainHead: [32]byte{0xAA, 0xBB},
			CkptHash:  [32]byte{0xCC, 0xDD},
			At:        123456789,
		}}},
		{"bye", &Bye{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteFrame(&buf, tc.f); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			got, err := ReadFrame(&buf)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			assertFramesEqual(t, tc.f, got)
			if buf.Len() != 0 {
				t.Fatalf("expected buffer fully consumed, %d bytes left", buf.Len())
			}
		})
	}
}

func TestWriteReadFrame_MultipleFramesSequentially(t *testing.T) {
	var buf bytes.Buffer
	frames := []Frame{
		&Hello{V: 1, Role: RoleSVC, Salt: []byte{1, 2, 3}},
		&Ev{Event: []byte{0xA1, 0x00}},
		&Head{Report: HeadReport{SessionID: "s1", SegLast: 1, At: 1}},
		&Bye{},
	}
	for _, f := range frames {
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatalf("WriteFrame(%T): %v", f, err)
		}
	}
	for i, want := range frames {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame[%d]: %v", i, err)
		}
		assertFramesEqual(t, want, got)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected buffer drained, %d bytes left", buf.Len())
	}
}

func TestReadFrame_EOFOnEmpty(t *testing.T) {
	var buf bytes.Buffer
	_, err := ReadFrame(&buf)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF on empty reader, got %v", err)
	}
}

func TestReadFrame_TornLengthPrefix(t *testing.T) {
	// A single byte with the continuation bit set (0x80) but nothing after it:
	// the uvarint is truncated mid-length.
	var buf bytes.Buffer
	buf.Write([]byte{0x80})
	_, err := ReadFrame(&buf)
	if err == nil {
		t.Fatalf("expected error for torn length prefix, got nil")
	}
	if errors.Is(err, io.EOF) {
		// Torn prefix should surface as ErrUnexpectedEOF/ErrTornFrame, not a
		// bare EOF that a caller might mistake for "no more frames".
		t.Fatalf("torn length prefix must not report as plain io.EOF: %v", err)
	}
}

func TestReadFrame_TornBody(t *testing.T) {
	// Valid length prefix claiming N bytes, but fewer than N bytes follow.
	var buf bytes.Buffer
	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], 100)
	buf.Write(lenBuf[:n])
	buf.Write([]byte{0x01, 0x02, 0x03}) // far short of 100 bytes

	_, err := ReadFrame(&buf)
	if err == nil {
		t.Fatalf("expected error for torn body, got nil")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF-wrapping error for torn body, got %v", err)
	}
}

func TestReadFrame_OversizeFrameRejectedNamedError(t *testing.T) {
	var buf bytes.Buffer
	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], MaxFrameSize+1)
	buf.Write(lenBuf[:n])
	// Do not bother writing MaxFrameSize+1 bytes of body — the codec must
	// reject based on the declared length alone, before attempting to read
	// (or allocate) the body.
	_, err := ReadFrame(&buf)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestReadFrame_ExactlyMaxFrameSizeAccepted(t *testing.T) {
	// Body of exactly MaxFrameSize bytes of valid CBOR (a byte string) must
	// be accepted by the length-prefix/size gate. We don't need it to decode
	// into a known frame type to prove the size boundary is inclusive — but
	// our decoder requires a recognizable frame, so build a legitimately
	// huge Ev frame whose total encoded size is <= MaxFrameSize.
	huge := make([]byte, MaxFrameSize-64) // leave room for CBOR/frame overhead
	f := &Ev{Event: huge}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if buf.Len() > MaxFrameSize+binary.MaxVarintLen64 {
		t.Fatalf("test setup produced a frame larger than expected: %d bytes", buf.Len())
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	gotEv, ok := got.(*Ev)
	if !ok {
		t.Fatalf("expected *Ev, got %T", got)
	}
	if len(gotEv.Event) != len(huge) {
		t.Fatalf("event length mismatch: got %d want %d", len(gotEv.Event), len(huge))
	}
}

func TestReadFrame_GarbageBodyNoPanic(t *testing.T) {
	garbageBodies := [][]byte{
		{},                             // empty body
		{0xFF},                         // invalid CBOR initial byte in strict mode
		{0xA1, 0x61, 'x'},              // truncated map (missing value)
		bytes.Repeat([]byte{0x00}, 50), // looks like nothing valid
		{0x9F, 0x01, 0x02, 0xFF},       // indefinite-length array (forbidden by strict decode)
	}
	for i, body := range garbageBodies {
		var buf bytes.Buffer
		var lenBuf [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(lenBuf[:], uint64(len(body)))
		buf.Write(lenBuf[:n])
		buf.Write(body)

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("garbage body %d panicked: %v", i, r)
				}
			}()
			_, err := ReadFrame(&buf)
			if err == nil {
				t.Fatalf("garbage body %d: expected a decode error, got nil", i)
			}
		}()
	}
}

func TestWriteFrame_RejectsOversizeBody(t *testing.T) {
	huge := make([]byte, MaxFrameSize+1)
	f := &Ev{Event: huge}
	var buf bytes.Buffer
	err := WriteFrame(&buf, f)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestReadFrame_UnknownFrameTag(t *testing.T) {
	// A well-formed canonical CBOR map that simply doesn't match any known
	// frame's field shape/tag.
	body := encodeRawMapForTest(t, map[string]any{"unknown_frame_tag": true})
	var buf bytes.Buffer
	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], uint64(len(body)))
	buf.Write(lenBuf[:n])
	buf.Write(body)

	_, err := ReadFrame(&buf)
	if err == nil {
		t.Fatalf("expected error for unrecognized frame tag, got nil")
	}
}

func TestReadFrame_ExtraUnknownKeyAlongsideKnownTagRejected(t *testing.T) {
	// A recognized "bye" key plus an extra field the envelope doesn't
	// declare must be rejected outright (strict decode, no silent
	// best-effort partial parse of a frame that isn't exactly what we
	// expect).
	body := encodeRawMapForTest(t, map[string]any{
		"bye":   map[string]any{},
		"extra": true,
	})
	var buf bytes.Buffer
	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], uint64(len(body)))
	buf.Write(lenBuf[:n])
	buf.Write(body)

	_, err := ReadFrame(&buf)
	if err == nil {
		t.Fatalf("expected error for extra unknown key alongside a known frame tag, got nil")
	}
}

func TestHello_RoleValidation(t *testing.T) {
	tests := []struct {
		role    string
		wantErr bool
	}{
		{RoleRanad, false},
		{RoleSVC, false},
		{"bogus", true},
		{"", true},
	}
	for _, tc := range tests {
		h := &Hello{V: 1, Role: tc.role, Salt: []byte{1}}
		var buf bytes.Buffer
		err := WriteFrame(&buf, h)
		if tc.wantErr && err == nil {
			t.Fatalf("role %q: expected WriteFrame error, got nil", tc.role)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("role %q: unexpected WriteFrame error: %v", tc.role, err)
		}
	}
}

func TestHello_VersionValidation(t *testing.T) {
	tests := []struct {
		name    string
		v       uint8
		wantErr bool
	}{
		{"current version", Version, false},
		{"zero", 0, true},
		{"future version", 2, true},
		{"max uint8", 255, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hello{V: tc.v, Role: RoleSVC, Salt: []byte{1}}
			var buf bytes.Buffer
			err := WriteFrame(&buf, h)
			if tc.wantErr && err == nil {
				t.Fatalf("V=%d: expected WriteFrame error, got nil", tc.v)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("V=%d: unexpected WriteFrame error: %v", tc.v, err)
			}
			if tc.wantErr && !errors.Is(err, ErrInvalidHello) {
				t.Fatalf("V=%d: expected ErrInvalidHello, got %v", tc.v, err)
			}
		})
	}
}

// TestReadFrame_OutOfRangeVersionRejectedNotTruncated proves that a Hello
// carrying a wire-level `v` value outside uint8 range (e.g. sent by a buggy
// or hostile peer bypassing the exported Hello type) is rejected outright
// rather than being silently narrowed by uint8(...) into a value that
// happens to collide with a legitimate version. Truncation would let V=257
// masquerade as V=1.
func TestReadFrame_OutOfRangeVersionRejectedNotTruncated(t *testing.T) {
	body := encodeRawWireEnvelopeForTest(t, wireEnvelope{Hello: &wireHello{V: 257, Role: RoleSVC, Salt: []byte{1}}})

	var buf bytes.Buffer
	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], uint64(len(body)))
	buf.Write(lenBuf[:n])
	buf.Write(body)

	_, err := ReadFrame(&buf)
	if err == nil {
		t.Fatalf("expected V=257 to be rejected, got nil error (silent truncation risk)")
	}
	if !errors.Is(err, ErrInvalidHello) {
		t.Fatalf("expected ErrInvalidHello, got %v", err)
	}
}

// assertFramesEqual compares two Frame values structurally per concrete type.
func assertFramesEqual(t *testing.T, want, got Frame) {
	t.Helper()
	switch w := want.(type) {
	case *Hello:
		g, ok := got.(*Hello)
		if !ok {
			t.Fatalf("type mismatch: want *Hello, got %T", got)
		}
		if w.V != g.V || w.Role != g.Role || !bytes.Equal(w.Salt, g.Salt) {
			t.Fatalf("Hello mismatch: want %+v got %+v", w, g)
		}
	case *Ev:
		g, ok := got.(*Ev)
		if !ok {
			t.Fatalf("type mismatch: want *Ev, got %T", got)
		}
		if !bytes.Equal(w.Event, g.Event) {
			t.Fatalf("Ev mismatch: want %d bytes got %d bytes", len(w.Event), len(g.Event))
		}
	case *Head:
		g, ok := got.(*Head)
		if !ok {
			t.Fatalf("type mismatch: want *Head, got %T", got)
		}
		if w.Report != g.Report {
			t.Fatalf("Head mismatch: want %+v got %+v", w.Report, g.Report)
		}
	case *Bye:
		if _, ok := got.(*Bye); !ok {
			t.Fatalf("type mismatch: want *Bye, got %T", got)
		}
	default:
		t.Fatalf("unhandled frame type in test helper: %T", want)
	}
}

// TestReadFrame_NonCanonicalUvarintRejected pins the injectivity of the
// length prefix: overlong (non-minimal) uvarint encodings and encodings that
// overflow uint64 must be rejected as torn frames, never silently aliased to
// another length (the pre-fix decoder accepted {0x80 x9, 0x02} as length 0).
func TestReadFrame_NonCanonicalUvarintRejected(t *testing.T) {
	cases := []struct {
		name   string
		prefix []byte
	}{
		{"overlong zero two bytes", []byte{0x80, 0x00}},
		{"overlong zero ten bytes", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}},
		{"tenth byte overflow", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}},
		{"overlong small value", []byte{0x85, 0x00}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadFrame(bytes.NewReader(tc.prefix))
			if !errors.Is(err, ErrTornFrame) {
				t.Fatalf("want ErrTornFrame for %x, got %v", tc.prefix, err)
			}
		})
	}
	// The canonical 10-byte encoding of 1<<63 is well-formed; it must fail as
	// oversize (a *different*, later check), not as a torn/malformed prefix.
	canonical63 := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
	_, err := ReadFrame(bytes.NewReader(canonical63))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge for canonical 1<<63, got %v", err)
	}
}

// TestWriteReadFrame_SessionEndRoundTrip covers the svc->ranad session-end
// signal frame (used to evict finished-session collector state).
func TestWriteReadFrame_SessionEndRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := &SessionEnd{Session: "01ARZ3NDEKTSV4RRFFQ69G5FAV"}
	if err := WriteFrame(&buf, want); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	se, ok := got.(*SessionEnd)
	if !ok {
		t.Fatalf("frame type = %T, want *SessionEnd", got)
	}
	if se.Session != want.Session {
		t.Fatalf("Session = %q, want %q", se.Session, want.Session)
	}
}
