package chain

import (
	"lukechampine.com/blake3"
)

// SegHeader binds a sealed segment to its predecessor (docs/TRUST.md §4).
// SegIndex, FirstRowID, and LastRowID together let verify confirm row
// continuity against segment bounds (docs/TRUST.md §6 step 5, gap
// honesty). PrevSegHash is 32 zero bytes for a session's first segment
// (genesis).
type SegHeader struct {
	SessionID    string
	SegIndex     uint64
	FirstRowID   int64
	LastRowID    int64
	EventCount   uint64
	MerkleRoot   [32]byte
	PrevSegHash  [32]byte
	GapSummary   map[string]uint64 // counts by reason: ringbuf_full / governor / daemon_restart
	SealedAtWall uint64            // ns
}

// segHeaderWire is the canonical CBOR encoding of SegHeader, field names
// exactly as docs/TRUST.md §4 (snake_case). Struct field declaration order
// is for readability only — encMode (RFC 8949 Core Deterministic Encoding)
// sorts map keys bytewise regardless.
type segHeaderWire struct {
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

// SegHash computes seg_hash = BLAKE3(canonical_cbor(seg_header))
// (docs/TRUST.md §4). It returns both the 32-byte hash and the exact
// canonical CBOR bytes that were hashed (headerCBOR) — callers that persist
// the header (internal/ledger) store headerCBOR verbatim so a verifier can
// recompute the hash from stored bytes without needing to reconstruct
// struct field ordering itself (docs/TRUST.md §8 step 3).
//
// GapSummary map keys are expected to be drawn from the frozen GapReason
// set (internal/schema); SegHash does not itself validate that — callers
// building a header from sealed events are responsible for that invariant.
func SegHash(h SegHeader) (segHash [32]byte, headerCBOR []byte, err error) {
	gapSummary := h.GapSummary
	if gapSummary == nil {
		gapSummary = map[string]uint64{}
	}

	wire := segHeaderWire{
		SessionID:    h.SessionID,
		SegIndex:     h.SegIndex,
		FirstRowID:   h.FirstRowID,
		LastRowID:    h.LastRowID,
		EventCount:   h.EventCount,
		MerkleRoot:   h.MerkleRoot[:],
		PrevSegHash:  h.PrevSegHash[:],
		GapSummary:   gapSummary,
		SealedAtWall: h.SealedAtWall,
	}

	headerCBOR, err = canonEncMode.Marshal(wire)
	if err != nil {
		return [32]byte{}, nil, err
	}

	return blake3.Sum256(headerCBOR), headerCBOR, nil
}
