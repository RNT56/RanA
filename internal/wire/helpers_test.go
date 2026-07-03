package wire

import (
	"testing"

	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/schema"
)

// encodeEventForTest produces canonical event bytes suitable for embedding in
// an Ev frame, using the real cborcanon encoder (wire treats event bytes as
// an opaque payload it neither decodes nor re-encodes).
func encodeEventForTest(ev schema.Event) ([]byte, error) {
	return cborcanon.EncodeEvent(ev)
}

// encodeRawMapForTest produces canonical CBOR for an arbitrary map, used to
// build "well-formed CBOR but not a recognized frame" fixtures.
func encodeRawMapForTest(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := cborcanon.Encode(m)
	if err != nil {
		t.Fatalf("encodeRawMapForTest: %v", err)
	}
	return b
}

// encodeRawWireEnvelopeForTest encodes a wireEnvelope directly, bypassing
// the exported Frame constructors/validation in toEnvelope. Used to craft
// frame bodies a well-behaved sender could never produce (e.g. an
// out-of-uint8-range version field), simulating a hostile or buggy peer
// writing raw bytes to the socket.
func encodeRawWireEnvelopeForTest(t *testing.T, env wireEnvelope) []byte {
	t.Helper()
	b, err := cborcanon.Encode(env)
	if err != nil {
		t.Fatalf("encodeRawWireEnvelopeForTest: %v", err)
	}
	return b
}
