package chain

import (
	"math/rand"
	"testing"

	"lukechampine.com/blake3"
)

func internalNode(left, right [32]byte) [32]byte {
	buf := make([]byte, 0, 65)
	buf = append(buf, 0x01)
	buf = append(buf, left[:]...)
	buf = append(buf, right[:]...)
	return blake3.Sum256(buf)
}

// TestMerkleRoot_GoldenVectors pins MerkleRoot against hand-computed trees
// for 1..5 leaves (CONTRACTS §internal/chain golden test requirement),
// using the domain-separated internal-node construction from
// docs/TRUST.md §3: node = BLAKE3(0x01 || left || right), duplicating the
// last node when a level has odd length.
func TestMerkleRoot_GoldenVectors(t *testing.T) {
	leaves := make([][32]byte, 5)
	for i := range leaves {
		leaves[i] = Leaf([]byte{byte('A' + i)})
	}

	t.Run("1-leaf", func(t *testing.T) {
		want := leaves[0]
		got := MerkleRoot(leaves[:1])
		if got != want {
			t.Fatalf("got %x, want %x", got, want)
		}
	})

	t.Run("2-leaves", func(t *testing.T) {
		want := internalNode(leaves[0], leaves[1])
		got := MerkleRoot(leaves[:2])
		if got != want {
			t.Fatalf("got %x, want %x", got, want)
		}
	})

	t.Run("3-leaves", func(t *testing.T) {
		// level0: L0,L1,L2 (odd -> duplicate last)
		n0 := internalNode(leaves[0], leaves[1])
		n1 := internalNode(leaves[2], leaves[2])
		want := internalNode(n0, n1)
		got := MerkleRoot(leaves[:3])
		if got != want {
			t.Fatalf("got %x, want %x", got, want)
		}
	})

	t.Run("4-leaves", func(t *testing.T) {
		n0 := internalNode(leaves[0], leaves[1])
		n1 := internalNode(leaves[2], leaves[3])
		want := internalNode(n0, n1)
		got := MerkleRoot(leaves[:4])
		if got != want {
			t.Fatalf("got %x, want %x", got, want)
		}
	})

	t.Run("5-leaves", func(t *testing.T) {
		// level0: L0,L1,L2,L3,L4 (odd -> duplicate last)
		n0 := internalNode(leaves[0], leaves[1])
		n1 := internalNode(leaves[2], leaves[3])
		n2 := internalNode(leaves[4], leaves[4])
		// level1: n0,n1,n2 (odd -> duplicate last)
		m0 := internalNode(n0, n1)
		m1 := internalNode(n2, n2)
		want := internalNode(m0, m1)
		got := MerkleRoot(leaves[:5])
		if got != want {
			t.Fatalf("got %x, want %x", got, want)
		}
	})
}

// TestMerkleRoot_EmptyIsZero defines the empty-segment edge case: a
// zero-leaf segment (which should not normally be sealed, but the function
// must not panic) returns the all-zero root.
func TestMerkleRoot_EmptyIsZero(t *testing.T) {
	var zero [32]byte
	got := MerkleRoot(nil)
	if got != zero {
		t.Fatalf("MerkleRoot(nil) = %x, want zero", got)
	}
}

// TestMerkleRoot_SingleBitFlip is the property test CONTRACTS demands: any
// single-bit flip in any leaf changes the root, across a range of tree
// sizes (exercising both even and odd levels / duplicate-last-odd paths).
func TestMerkleRoot_SingleBitFlip(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	for _, n := range []int{1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 31} {
		leaves := make([][32]byte, n)
		for i := range leaves {
			leaves[i] = Leaf([]byte{byte(i), byte(i >> 8), 0xAA})
		}
		baseRoot := MerkleRoot(leaves)

		for trial := 0; trial < 20; trial++ {
			flipIdx := rng.Intn(n)
			byteIdx := rng.Intn(32)
			bitIdx := uint(rng.Intn(8))

			mutated := make([][32]byte, n)
			copy(mutated, leaves)
			mutated[flipIdx][byteIdx] ^= 1 << bitIdx

			gotRoot := MerkleRoot(mutated)
			if gotRoot == baseRoot {
				t.Fatalf("n=%d flipIdx=%d byteIdx=%d bitIdx=%d: single-bit flip did not change root",
					n, flipIdx, byteIdx, bitIdx)
			}
		}
	}
}

// TestMerkleRoot_OrderMatters confirms MerkleRoot is not commutative over
// its leaf slice — reordering two leaves must (almost always) change the
// root, which is what lets verify catch reordered events within a segment
// (docs/TRUST.md §6 step 2).
func TestMerkleRoot_OrderMatters(t *testing.T) {
	leaves := [][32]byte{
		Leaf([]byte("event 0")),
		Leaf([]byte("event 1")),
		Leaf([]byte("event 2")),
		Leaf([]byte("event 3")),
	}
	reordered := [][32]byte{leaves[1], leaves[0], leaves[2], leaves[3]}

	if MerkleRoot(leaves) == MerkleRoot(reordered) {
		t.Fatalf("reordering leaves did not change the merkle root")
	}
}
