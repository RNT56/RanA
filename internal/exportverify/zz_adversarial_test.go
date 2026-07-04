package exportverify_test

import (
	"encoding/binary"
	"testing"

	"github.com/RNT56/RanA/internal/cborcanon"
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

// adversarialSegHeader mirrors verify.go's unexported segHeaderRecord
// field-for-field, so this test can encode a seg_header with an
// attacker-controlled event_count without VerifyExportFiles's own decode
// path caring which struct produced the identical CBOR shape.
type adversarialSegHeader struct {
	SessionID    string            `cbor:"session_id"`
	SegIndex     uint64            `cbor:"seg_index"`
	FirstRowID   int64             `cbor:"first_rowid"`
	LastRowID    int64             `cbor:"last_rowid"`
	EventCount   uint64            `cbor:"event_count"`
	MerkleRoot   []byte            `cbor:"merkle_root"`
	PrevSegHash  []byte            `cbor:"prev_seg_hash"`
	GapSummary   map[string]uint64 `cbor:"gap_summary"`
	SealedAtWall uint64            `cbor:"sealed_at_wall"`
}

// TestHugeEventCountInSegHeaderDoesNotPanic proves that a seg_header
// record (inside segments.cbor) claiming an event_count at/above 2^63 is
// rejected with a clean BROKEN result rather than panicking: converting
// such a value to int wraps negative, which — if compared to the
// remaining-leaf count only AFTER conversion — silently defeats an
// "end > len(all)" bounds check and panics on the subsequent slice
// expression in verifySegments. This is the same overflow-before-compare
// trap that readUvarintPrefixedRecords/splitCheckpointRecord already guard
// against for their raw uvarint length prefixes, but event_count arrives
// via a decoded CBOR struct field instead of a raw uvarint, so it needs its
// own coverage.
func TestHugeEventCountInSegHeaderDoesNotPanic(t *testing.T) {
	sh := adversarialSegHeader{
		SessionID:   "01ARZ3NDEKTSV4RRFFQ69G5FC0",
		EventCount:  1<<63 + 5, // wraps negative when cast to int
		MerkleRoot:  make([]byte, 32),
		PrevSegHash: make([]byte, 32),
		GapSummary:  map[string]uint64{},
	}
	body, err := cborcanon.Encode(sh)
	if err != nil {
		t.Fatalf("encoding adversarial seg_header: %v", err)
	}
	lenBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(lenBuf, uint64(len(body)))
	rec := append(lenBuf[:n], body...)

	files := map[string][]byte{
		"manifest.json": validManifest(),
		"events.cbor":   {},
		"segments.cbor": rec,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked: %v", r)
		}
	}()
	res := exportverify.VerifyExportFiles(files)
	if res.Code != exportverify.CodeBroken {
		t.Fatalf("Code = %d, want CodeBroken for an event_count overrun; reason=%q", res.Code, res.Reason)
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
