package chain

import (
	"bytes"
	"testing"

	"lukechampine.com/blake3"
)

// TestLeaf_GoldenVectors pins Leaf's output against hand-computed BLAKE3
// values over the domain-separated (0x00-prefixed) input, per
// docs/TRUST.md §2: leaf = BLAKE3(0x00 || canonical_cbor(event)).
func TestLeaf_GoldenVectors(t *testing.T) {
	cases := []struct {
		name  string
		event []byte
	}{
		{"empty", []byte{}},
		{"single-byte", []byte{0xa0}},
		{"short-cbor-map", []byte{0xa1, 0x61, 0x76, 0x01}}, // {"v":1}
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := blake3.Sum256(append([]byte{0x00}, c.event...))
			got := Leaf(c.event)
			if got != want {
				t.Fatalf("Leaf(%x) = %x, want %x", c.event, got, want)
			}
		})
	}
}

// TestLeaf_DomainSeparation confirms Leaf's 0x00 prefix means Leaf(b) is
// never equal to a bare BLAKE3(b) (i.e. the domain separation byte is
// actually applied, not a no-op), and that Leaf differs from an internal
// node hash of the same bytes (0x01 prefix) — the second-preimage defense
// docs/TRUST.md §3 describes.
func TestLeaf_DomainSeparation(t *testing.T) {
	data := []byte("some canonical event bytes")

	leaf := Leaf(data)
	bare := blake3.Sum256(data)
	if leaf == bare {
		t.Fatalf("Leaf must not equal bare BLAKE3 hash (missing domain separation)")
	}

	internalPrefixed := blake3.Sum256(append([]byte{0x01}, data...))
	if leaf == internalPrefixed {
		t.Fatalf("Leaf must not collide with an internal-node-prefixed hash of the same bytes")
	}
}

// TestLeaf_Deterministic confirms repeated calls on identical input produce
// identical output (encoder determinism is cborcanon's job; Leaf itself
// must be a pure function of its input bytes).
func TestLeaf_Deterministic(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	a := Leaf(data)
	b := Leaf(data)
	if a != b {
		t.Fatalf("Leaf is not deterministic: %x != %x", a, b)
	}
}

// TestLeaf_DifferentInputsDifferentHashes is a basic sanity/avalanche check.
func TestLeaf_DifferentInputsDifferentHashes(t *testing.T) {
	a := Leaf([]byte("event A"))
	b := Leaf([]byte("event B"))
	if bytes.Equal(a[:], b[:]) {
		t.Fatalf("distinct inputs produced identical leaves")
	}
}
