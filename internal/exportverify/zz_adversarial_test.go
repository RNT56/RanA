package exportverify_test

import (
	"encoding/binary"
	"testing"

	"github.com/RNT56/RanA/internal/exportverify"
)

func validManifest() []byte {
	return []byte(`{"format_version":1,"hash":"blake3","sig":"ed25519","encoding":"cbor-rfc8949-cde"}`)
}

func TestAdversarialMalformedInputsDoNotPanic(t *testing.T) {
	// A uvarint claiming a huge length (near uint64 max) must not cause an
	// out-of-memory panic or integer overflow wraparound leading to a false
	// "valid" read.
	hugeLenBuf := make([]byte, 32)
	n := binary.PutUvarint(hugeLenBuf, ^uint64(0)-5) // near max uint64
	hugeLenBuf = hugeLenBuf[:n]
	hugeLenBuf = append(hugeLenBuf, []byte{1, 2, 3}...)

	// uvarint that overflows int on 32-bit platforms / huge but not max.
	overflowLenBuf := make([]byte, 32)
	n2 := binary.PutUvarint(overflowLenBuf, uint64(1)<<62)
	overflowLenBuf = overflowLenBuf[:n2]
	overflowLenBuf = append(overflowLenBuf, []byte{1, 2, 3}...)

	cases := map[string]map[string][]byte{
		"huge events len": {
			"manifest.json": validManifest(),
			"events.cbor":   hugeLenBuf,
		},
		"huge segments len": {
			"manifest.json": validManifest(),
			"events.cbor":   {},
			"segments.cbor": hugeLenBuf,
		},
		"huge checkpoints len": {
			"manifest.json":    validManifest(),
			"events.cbor":      {},
			"segments.cbor":    {},
			"checkpoints.cbor": hugeLenBuf,
		},
		"overflow events len": {
			"manifest.json": validManifest(),
			"events.cbor":   overflowLenBuf,
		},
		"empty events, garbage segments": {
			"manifest.json": validManifest(),
			"events.cbor":   {},
			"segments.cbor": []byte{0x00}, // len=0 record, empty CBOR -> decode fails
		},
		"checkpoint body length huge inside outer": {
			"manifest.json":    validManifest(),
			"events.cbor":      {},
			"segments.cbor":    {},
			"checkpoints.cbor": mustOuterWithHugeBodyLen(),
		},
		// bodyLen near uint64 max: int(bodyLen) wraps negative on a 64-bit
		// build, which must still be rejected cleanly rather than bypassing
		// the "off+int(n) > len(rec)" bounds check and panicking on the
		// subsequent slice expression (splitCheckpointRecord).
		"checkpoint body length overflows int inside outer": {
			"manifest.json":    validManifest(),
			"events.cbor":      {},
			"segments.cbor":    {},
			"checkpoints.cbor": mustOuterWithOverflowingBodyLen(),
		},
		// sigLen near uint64 max, with a well-formed (small) bodyLen —
		// exercises the second half of splitCheckpointRecord's bounds check.
		"checkpoint sig length overflows int inside outer": {
			"manifest.json":    validManifest(),
			"events.cbor":      {},
			"segments.cbor":    {},
			"checkpoints.cbor": mustOuterWithOverflowingSigLen(),
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panicked: %v", r)
				}
			}()
			res := exportverify.VerifyExportFiles(c)
			t.Logf("res = %+v", res)
		})
	}
}

func mustOuterWithHugeBodyLen() []byte {
	inner := make([]byte, 32)
	n := binary.PutUvarint(inner, uint64(1)<<40)
	inner = inner[:n]
	inner = append(inner, []byte{1, 2, 3}...)

	outer := make([]byte, 32)
	m := binary.PutUvarint(outer, uint64(len(inner)))
	outer = outer[:m]
	outer = append(outer, inner...)
	return outer
}

// mustOuterWithOverflowingBodyLen builds a checkpoints.cbor outer record
// whose inner bodyLen uvarint is ^uint64(0)-5 (near uint64 max, well above
// math.MaxInt64) — large enough that int(bodyLen) wraps to a negative
// number on a 64-bit build, the exact shape that defeated
// splitCheckpointRecord's bounds check before it was fixed to compare
// against the remaining buffer length pre-conversion.
func mustOuterWithOverflowingBodyLen() []byte {
	inner := make([]byte, 32)
	n := binary.PutUvarint(inner, ^uint64(0)-5)
	inner = inner[:n]
	inner = append(inner, []byte{1, 2, 3}...)

	outer := make([]byte, 32)
	m := binary.PutUvarint(outer, uint64(len(inner)))
	outer = outer[:m]
	outer = append(outer, inner...)
	return outer
}

// mustOuterWithOverflowingSigLen is mustOuterWithOverflowingBodyLen's
// counterpart for the sigLen half of splitCheckpointRecord: a small,
// well-formed bodyLen/body followed by a sigLen uvarint near uint64 max.
func mustOuterWithOverflowingSigLen() []byte {
	inner := make([]byte, 0, 32)
	bodyLenBuf := make([]byte, 32)
	n := binary.PutUvarint(bodyLenBuf, 3)
	inner = append(inner, bodyLenBuf[:n]...)
	inner = append(inner, []byte{1, 2, 3}...) // body

	sigLenBuf := make([]byte, 32)
	n2 := binary.PutUvarint(sigLenBuf, ^uint64(0)-5)
	inner = append(inner, sigLenBuf[:n2]...)

	outer := make([]byte, 32)
	m := binary.PutUvarint(outer, uint64(len(inner)))
	outer = outer[:m]
	outer = append(outer, inner...)
	return outer
}
