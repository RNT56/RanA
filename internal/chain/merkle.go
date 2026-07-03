package chain

import "lukechampine.com/blake3"

// MerkleRoot computes the binary Merkle root over an ordered slice of leaf
// hashes (docs/TRUST.md §3):
//
//	node = BLAKE3(0x01 || left || right)   # internal, domain-separated from Leaf's 0x00
//
// A level with an odd number of nodes duplicates its last node before
// pairing (standard Merkle duplicate-last-odd rule). MerkleRoot(nil) or
// MerkleRoot of an empty slice returns the all-zero root — segments are not
// expected to seal with zero events, but the function must not panic on
// the degenerate input.
//
// MerkleRoot does not mutate its input slice.
func MerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}

	level := make([][32]byte, len(leaves))
	copy(level, leaves)

	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][32]byte, len(level)/2)
		for i := 0; i < len(next); i++ {
			next[i] = internalNodeHash(level[2*i], level[2*i+1])
		}
		level = next
	}

	return level[0]
}

// internalNodeHash computes a single domain-separated internal Merkle node
// hash from its two children, per docs/TRUST.md §3.
func internalNodeHash(left, right [32]byte) [32]byte {
	buf := make([]byte, 0, 1+32+32)
	buf = append(buf, internalPrefix)
	buf = append(buf, left[:]...)
	buf = append(buf, right[:]...)
	return blake3.Sum256(buf)
}
