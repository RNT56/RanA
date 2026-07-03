package chainmutations

import (
	"encoding/json"
	"testing"

	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/schema"
)

// TestUnattestedTailGapSuppressionDetected is a gate-G5 case for the gap-
// summary cross-check (docs/TRUST.md §4, P5 "losses are loud"). It builds a
// session whose final (unattested-tail) segment legitimately records a gap
// EVENT, confirms the ledger verifies clean, then plays the attacker: with
// only raw sqlite write access (no device key), it zeros that segment's
// header gap_summary and recomputes a self-consistent seg_hash — the exact
// forgery that was undetected before Verify cross-checked the header tally
// against the gap events in the segment's own merkle-protected bytes.
//
// Because the tail is not yet checkpoint-signed, the seg_hash recomputation
// alone leaves no signature to break; detection rests entirely on the gap-
// summary/gap-events consistency check.
func TestUnattestedTailGapSuppressionDetected(t *testing.T) {
	d, session := buildLedgerWithTailGap(t)

	// Baseline: the honestly-gap-bearing ledger verifies clean.
	resBefore, err := ledger.Verify(d, ledger.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify (before forgery): %v", err)
	}
	if resBefore.Code != ledger.CodeOK {
		t.Fatalf("Verify (before forgery) Code = %d, want CodeOK; findings=%+v", resBefore.Code, resBefore.Findings)
	}

	// Locate the last (unattested-tail) segment — the one carrying the gap.
	db := openRawDB(t, d)
	var seg uint64
	var firstRowID, lastRowID int64
	var eventCount uint64
	var merkleRoot, prevSegHash []byte
	var sealedNs int64
	var gapBlob []byte
	row := db.QueryRow(`SELECT seg, first_rowid, last_rowid, event_count, merkle_root, prev_seg_hash, sealed_ns, gap
		FROM segments WHERE session = ? ORDER BY seg DESC LIMIT 1`, session)
	if err := row.Scan(&seg, &firstRowID, &lastRowID, &eventCount, &merkleRoot, &prevSegHash, &sealedNs, &gapBlob); err != nil {
		t.Fatalf("selecting last segment: %v", err)
	}
	var mr, psh [32]byte
	copy(mr[:], merkleRoot)
	copy(psh[:], prevSegHash)

	// Sanity: this segment's header really does record a gap (so the
	// forgery below is a genuine suppression, not a no-op).
	var baseline map[string]uint64
	if err := json.Unmarshal(gapBlob, &baseline); err != nil {
		t.Fatalf("unmarshal baseline gap: %v", err)
	}
	if len(baseline) == 0 {
		t.Fatalf("test setup: last segment has no recorded gap to suppress (gap=%s)", gapBlob)
	}

	// Attacker: suppress the gap in the header and recompute a self-
	// consistent seg_hash with the SAME function Verify uses. The gap EVENT
	// remains in the events table (still in the merkle root), so event_count
	// and merkle_root are unchanged — only the header's summary is a lie.
	forgedGap := map[string]uint64{}
	forgedHash, _, err := chain.SegHash(chain.SegHeader{
		SessionID: session, SegIndex: seg, FirstRowID: firstRowID, LastRowID: lastRowID,
		EventCount: eventCount, MerkleRoot: mr, PrevSegHash: psh,
		GapSummary: forgedGap, SealedAtWall: uint64(sealedNs),
	})
	if err != nil {
		t.Fatalf("SegHash (forged): %v", err)
	}
	forgedGapBlob, err := json.Marshal(forgedGap)
	if err != nil {
		t.Fatalf("marshal forged gap: %v", err)
	}
	mustExec(t, db, `UPDATE segments SET gap = ?, seg_hash = ? WHERE session = ? AND seg = ?`, forgedGapBlob, forgedHash[:], session, seg)
	db.Close()

	res, err := ledger.Verify(d, ledger.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify (after forgery): %v", err)
	}
	if res.Code != ledger.CodeBroken {
		t.Fatalf("gap suppression not detected: Verify Code = %d, want CodeBroken (2)", res.Code)
	}
	var found bool
	for _, f := range res.Findings {
		if f.Kind == ledger.FindingGapDishonest {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a %q finding, got %+v", ledger.FindingGapDishonest, res.Findings)
	}
}

// buildLedgerWithTailGap builds a single-session ledger whose final sealed
// segment contains a real schema.EventTypeGap event (so the segment header's
// gap_summary honestly reflects it), and returns the datadir + session id.
func buildLedgerWithTailGap(t *testing.T) (ledger.Datadir, string) {
	t.Helper()
	root := t.TempDir()
	d := ledger.Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	key, err := chain.GenerateKey(root)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	w, err := ledger.NewWriter(d, ledger.WriterOptions{
		SegSealMaxEvents:  4,
		CheckpointMaxSegs: 2,
		Key:               key,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	session := schema.NewSessionID(fixedClock{ms: 4242})

	// Fill several segments with execs, then place a gap event in the final
	// segment so it lands in the unattested tail.
	writeExecs(t, w, session, 9)
	gap := schema.NewGap(session, 0, 99, 99_000, 99_000, 0, string(schema.GapReasonGovernor),
		map[string]uint64{"fs.write_open": 5}, 90_000, 99_000)
	if err := w.Append(gap); err != nil {
		t.Fatalf("Append gap: %v", err)
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := w.SealSession(session); err != nil {
		t.Fatalf("SealSession: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return d, session
}
