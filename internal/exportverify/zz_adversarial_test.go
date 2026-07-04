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
