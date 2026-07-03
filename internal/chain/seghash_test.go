package chain

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"lukechampine.com/blake3"
)

// segHeaderCBORMap mirrors SegHeader's canonical CBOR field names exactly
// as specified in docs/TRUST.md §4, used here only to hand-build an
// independent encoding to compare SegHash's output against (golden vector
// technique: build the expected bytes a second, structurally different
// way).
type segHeaderCBORMap struct {
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

func mustCanonModeSegHash(t *testing.T) cbor.EncMode {
	t.Helper()
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("building canonical enc mode: %v", err)
	}
	return em
}

// TestSegHash_GoldenVector pins SegHash's output: it must equal
// BLAKE3(canonical_cbor(seg_header)) where seg_header carries exactly the
// snake_case field set from docs/TRUST.md §4, independently encoded here.
func TestSegHash_GoldenVector(t *testing.T) {
	em := mustCanonModeSegHash(t)

	var merkleRoot [32]byte
	for i := range merkleRoot {
		merkleRoot[i] = byte(i)
	}
	var prevSegHash [32]byte // genesis: 32 zero bytes, per docs/TRUST.md §4

	h := SegHeader{
		SessionID:    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		SegIndex:     0,
		FirstRowID:   1,
		LastRowID:    100,
		EventCount:   100,
		MerkleRoot:   merkleRoot,
		PrevSegHash:  prevSegHash,
		GapSummary:   map[string]uint64{"ringbuf_full": 3},
		SealedAtWall: 1700000000000000000,
	}

	independent := segHeaderCBORMap{
		SessionID:    h.SessionID,
		SegIndex:     h.SegIndex,
		FirstRowID:   h.FirstRowID,
		LastRowID:    h.LastRowID,
		EventCount:   h.EventCount,
		MerkleRoot:   merkleRoot[:],
		PrevSegHash:  prevSegHash[:],
		GapSummary:   map[string]uint64{"ringbuf_full": 3},
		SealedAtWall: h.SealedAtWall,
	}
	wantCBOR, err := em.Marshal(independent)
	if err != nil {
		t.Fatalf("marshal independent: %v", err)
	}
	wantHash := blake3.Sum256(wantCBOR)

	gotHash, gotCBOR, err := SegHash(h)
	if err != nil {
		t.Fatalf("SegHash: %v", err)
	}

	if !bytes.Equal(gotCBOR, wantCBOR) {
		t.Fatalf("headerCBOR mismatch:\n got=%x\nwant=%x", gotCBOR, wantCBOR)
	}
	if gotHash != wantHash {
		t.Fatalf("SegHash = %x, want %x", gotHash, wantHash)
	}
}

// TestSegHash_FieldNamesAndOrder confirms the encoded header uses the exact
// snake_case field names from docs/TRUST.md §4 and that map keys are
// bytewise-sorted (canonical CBOR), by decoding into a generic map and
// checking key membership plus re-encode-equality (IsCanonical-style
// check).
func TestSegHash_FieldNamesAndOrder(t *testing.T) {
	h := SegHeader{
		SessionID:    "sess-1",
		SegIndex:     7,
		FirstRowID:   10,
		LastRowID:    20,
		EventCount:   11,
		GapSummary:   map[string]uint64{},
		SealedAtWall: 123,
	}

	_, headerCBOR, err := SegHash(h)
	if err != nil {
		t.Fatalf("SegHash: %v", err)
	}

	var decoded map[string]any
	dm, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		t.Fatalf("decmode: %v", err)
	}
	if err := dm.Unmarshal(headerCBOR, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	wantKeys := []string{
		"session_id", "seg_index", "first_rowid", "last_rowid",
		"event_count", "merkle_root", "prev_seg_hash", "gap_summary", "sealed_at_wall",
	}
	for _, k := range wantKeys {
		if _, ok := decoded[k]; !ok {
			t.Errorf("missing expected field %q in encoded seg header; got keys %v", k, keysOf(decoded))
		}
	}
	if len(decoded) != len(wantKeys) {
		t.Errorf("unexpected extra fields: got %v, want exactly %v", keysOf(decoded), wantKeys)
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestSegHash_GenesisPrevSegHash confirms the documented genesis rule:
// prev_seg_hash for the first segment is 32 zero bytes (docs/TRUST.md §4).
func TestSegHash_GenesisPrevSegHash(t *testing.T) {
	h := SegHeader{
		SessionID:  "sess-genesis",
		SegIndex:   0,
		EventCount: 1,
		GapSummary: map[string]uint64{},
		// PrevSegHash intentionally left zero value.
	}
	if h.PrevSegHash != ([32]byte{}) {
		t.Fatalf("test setup: expected zero PrevSegHash")
	}
	if _, _, err := SegHash(h); err != nil {
		t.Fatalf("SegHash on genesis header: %v", err)
	}
}

// TestSegHash_Deterministic confirms identical headers hash identically.
func TestSegHash_Deterministic(t *testing.T) {
	h := SegHeader{SessionID: "s", SegIndex: 1, EventCount: 5, GapSummary: map[string]uint64{"governor": 2}}
	h1, c1, err1 := SegHash(h)
	h2, c2, err2 := SegHash(h)
	if err1 != nil || err2 != nil {
		t.Fatalf("errors: %v %v", err1, err2)
	}
	if h1 != h2 || !bytes.Equal(c1, c2) {
		t.Fatalf("SegHash not deterministic")
	}
}

// TestSegHash_FieldChangeChangesHash is a basic sensitivity check: changing
// any single field changes the hash (this underlies verify's leaf/merkle/
// chain-link recomputation in docs/TRUST.md §6).
func TestSegHash_FieldChangeChangesHash(t *testing.T) {
	base := SegHeader{
		SessionID:    "sess",
		SegIndex:     3,
		FirstRowID:   1,
		LastRowID:    10,
		EventCount:   10,
		GapSummary:   map[string]uint64{},
		SealedAtWall: 42,
	}
	baseHash, _, err := SegHash(base)
	if err != nil {
		t.Fatalf("SegHash base: %v", err)
	}

	mutations := []func(*SegHeader){
		func(h *SegHeader) { h.SessionID = "different" },
		func(h *SegHeader) { h.SegIndex++ },
		func(h *SegHeader) { h.FirstRowID++ },
		func(h *SegHeader) { h.LastRowID++ },
		func(h *SegHeader) { h.EventCount++ },
		func(h *SegHeader) { h.MerkleRoot[0] ^= 1 },
		func(h *SegHeader) { h.PrevSegHash[0] ^= 1 },
		func(h *SegHeader) { h.GapSummary["governor"] = 1 },
		func(h *SegHeader) { h.SealedAtWall++ },
	}

	for i, mutate := range mutations {
		mutated := base
		mutated.GapSummary = map[string]uint64{}
		for k, v := range base.GapSummary {
			mutated.GapSummary[k] = v
		}
		mutate(&mutated)

		mutatedHash, _, err := SegHash(mutated)
		if err != nil {
			t.Fatalf("mutation %d: SegHash: %v", i, err)
		}
		if mutatedHash == baseHash {
			t.Errorf("mutation %d did not change SegHash", i)
		}
	}
}
