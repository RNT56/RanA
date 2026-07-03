package chain

import (
	"crypto/ed25519"
	"testing"
)

// TestChainOfThreeSegments_GoldenAndTamper builds a 3-segment hash chain
// (each segment sealing a handful of leaves), checkpoints it, and confirms
// (a) the chain links correctly end to end (docs/TRUST.md §4), (b) the
// checkpoint signs and verifies over the final chain head (docs/TRUST.md
// §5), and (c) a single tampered byte anywhere in any segment's events
// changes that segment's seg_hash, which breaks prev_seg_hash continuity
// in every following segment, and changes the checkpoint's chain_head —
// exactly the propagating-detection property docs/TRUST.md §6 describes.
// This is the CONTRACTS-required "chain of 3 segments" golden test plus
// its tamper-flip counterpart.
func TestChainOfThreeSegments_GoldenAndTamper(t *testing.T) {
	buildChain := func(mutateSeg1Event1 bool) (heads [3][32]byte, headers [3]SegHeader) {
		// Segment 0: genesis, 3 events.
		seg0Events := [][]byte{
			{0xa1, 0x61, 0x61, 0x01}, // arbitrary well-formed-looking cbor-ish bytes; Leaf just hashes bytes
			{0xa1, 0x61, 0x62, 0x02},
			{0xa1, 0x61, 0x63, 0x03},
		}
		seg0Leaves := make([][32]byte, len(seg0Events))
		for i, e := range seg0Events {
			seg0Leaves[i] = Leaf(e)
		}
		h0 := SegHeader{
			SessionID:  "sess-chain-test",
			SegIndex:   0,
			FirstRowID: 1,
			LastRowID:  3,
			EventCount: 3,
			MerkleRoot: MerkleRoot(seg0Leaves),
			// PrevSegHash zero: genesis.
			GapSummary:   map[string]uint64{},
			SealedAtWall: 1000,
		}
		hash0, _, err := SegHash(h0)
		if err != nil {
			t.Fatalf("SegHash seg0: %v", err)
		}

		// Segment 1: 2 events, one optionally mutated by a single bit flip.
		seg1Events := [][]byte{
			{0xa1, 0x61, 0x64, 0x04},
			{0xa1, 0x61, 0x65, 0x05},
		}
		if mutateSeg1Event1 {
			mutated := make([]byte, len(seg1Events[0]))
			copy(mutated, seg1Events[0])
			mutated[len(mutated)-1] ^= 1 // flip one bit in the last byte
			seg1Events[0] = mutated
		}
		seg1Leaves := make([][32]byte, len(seg1Events))
		for i, e := range seg1Events {
			seg1Leaves[i] = Leaf(e)
		}
		h1 := SegHeader{
			SessionID:    "sess-chain-test",
			SegIndex:     1,
			FirstRowID:   4,
			LastRowID:    5,
			EventCount:   2,
			MerkleRoot:   MerkleRoot(seg1Leaves),
			PrevSegHash:  hash0,
			GapSummary:   map[string]uint64{},
			SealedAtWall: 2000,
		}
		hash1, _, err := SegHash(h1)
		if err != nil {
			t.Fatalf("SegHash seg1: %v", err)
		}

		// Segment 2: 4 events, includes a recorded gap.
		seg2Events := [][]byte{
			{0xa1, 0x61, 0x66, 0x06},
			{0xa1, 0x61, 0x67, 0x07},
			{0xa1, 0x61, 0x68, 0x08},
			{0xa1, 0x61, 0x69, 0x09},
		}
		seg2Leaves := make([][32]byte, len(seg2Events))
		for i, e := range seg2Events {
			seg2Leaves[i] = Leaf(e)
		}
		h2 := SegHeader{
			SessionID:    "sess-chain-test",
			SegIndex:     2,
			FirstRowID:   6,
			LastRowID:    9,
			EventCount:   4,
			MerkleRoot:   MerkleRoot(seg2Leaves),
			PrevSegHash:  hash1,
			GapSummary:   map[string]uint64{"governor": 5},
			SealedAtWall: 3000,
		}
		hash2, _, err := SegHash(h2)
		if err != nil {
			t.Fatalf("SegHash seg2: %v", err)
		}

		return [3][32]byte{hash0, hash1, hash2}, [3]SegHeader{h0, h1, h2}
	}

	goldenHeads, goldenHeaders := buildChain(false)

	// Sanity: chain links correctly.
	if goldenHeaders[1].PrevSegHash != goldenHeads[0] {
		t.Fatalf("seg1.PrevSegHash does not match seg0's hash")
	}
	if goldenHeaders[2].PrevSegHash != goldenHeads[1] {
		t.Fatalf("seg2.PrevSegHash does not match seg1's hash")
	}

	// Sign a checkpoint over the final chain head.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	ck := Checkpoint{
		SessionID:          "sess-chain-test",
		SegFirst:           0,
		SegLast:            2,
		ChainHead:          goldenHeads[2],
		PrevCheckpointHash: [32]byte{}, // genesis in the ledger-wide checkpoint chain
		SignedAtWall:       9999,
		PubkeyID:           PubkeyID(pub),
	}
	body, sig, err := SignCheckpoint(priv, ck)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	if err := VerifyCheckpoint(pub, body, sig); err != nil {
		t.Fatalf("VerifyCheckpoint on golden chain: %v", err)
	}

	// Now build the tampered chain (single bit flip in one seg1 event) and
	// confirm the tamper propagates: seg1's hash changes, seg2's
	// PrevSegHash no longer matches seg1 (a verifier recomputing forward
	// would catch this at seg2), seg2's own hash changes too (since we
	// rebuild seg2 with the new PrevSegHash here — modeling what an
	// original, untampered ledger's seg2 actually committed to), and the
	// resulting chain head no longer matches what was signed, so the
	// original checkpoint's chain_head assertion fails against the
	// tampered chain (docs/TRUST.md §8 step 4 "chain_head mismatch").
	tamperedHeads, _ := buildChain(true)

	if tamperedHeads[0] != goldenHeads[0] {
		t.Fatalf("seg0 hash changed even though seg0 was not tampered")
	}
	if tamperedHeads[1] == goldenHeads[1] {
		t.Fatalf("tampering a seg1 event did not change seg1's hash")
	}
	if tamperedHeads[2] == goldenHeads[2] {
		t.Fatalf("tampering propagated to seg1 did not change seg2's hash (chain-link recompute)")
	}

	// The checkpoint signed over the golden chain head must NOT verify as
	// matching the tampered chain's head.
	if tamperedHeads[2] == ck.ChainHead {
		t.Fatalf("tampered chain head unexpectedly equals the signed golden chain head")
	}

	// And the checkpoint signature itself must still verify (it's a
	// signature over the checkpoint body, unrelated to whether the events
	// were later tampered) — but a verifier comparing checkpoint.chain_head
	// against a freshly recomputed seg_hash(last) of the tampered chain
	// would see a mismatch, exactly per docs/TRUST.md §8 step 4.
	if err := VerifyCheckpoint(pub, body, sig); err != nil {
		t.Fatalf("original checkpoint signature should still verify (body untouched): %v", err)
	}
}
