// Package chain implements RanA's tamper-evident chain: leaf hashing,
// Merkle segmentation, segment-header chaining, signed checkpoints, and the
// ed25519 device-key lifecycle (docs/TRUST.md §2-6). It is
// part of the trust core: the guarantee it exists to deliver is that any
// modification, deletion, reordering, or re-signing of persisted events is
// detectable (docs/TRUST.md, LIMITS.md §6 for the exact boundary).
package chain

import "lukechampine.com/blake3"

// leafPrefix domain-separates leaf hashes from internal Merkle node hashes
// (docs/TRUST.md §2-3), defending against second-preimage attacks that
// would otherwise let a crafted internal-node byte string be mistaken for
// a leaf (or vice versa).
const leafPrefix = 0x00

// internalPrefix domain-separates internal Merkle node hashes from leaves.
const internalPrefix = 0x01

// Leaf computes the leaf hash of a single canonically-encoded event:
//
//	leaf = BLAKE3(0x00 || canonicalEvent)
//
// canonicalEvent MUST already be the canonical CBOR encoding of the event
// (internal/cborcanon.EncodeEvent) — Leaf does not re-encode or validate
// its input, it only hashes the bytes it is given (docs/TRUST.md §2, and
// §8 step 2: "hash the provided bytes; do NOT re-encode").
func Leaf(canonicalEvent []byte) [32]byte {
	buf := make([]byte, 0, len(canonicalEvent)+1)
	buf = append(buf, leafPrefix)
	buf = append(buf, canonicalEvent...)
	return blake3.Sum256(buf)
}
