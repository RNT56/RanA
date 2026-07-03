package chainmutations

import (
	"path/filepath"
	"testing"

	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// TestFullyConsistentForgeryCaughtOnlyByMirror is the precise case
// docs/TRUST.md §6 step 6 and LIMITS.md §6.1 exist for: a same-uid
// attacker holding the legitimate, stolen device key rewrites a
// segment's content, correctly recomputes its merkle root and seg_hash,
// and re-signs a matching checkpoint with the REAL key — producing a
// chain that is 100% internally self-consistent. Every check 1-5 in
// docs/TRUST.md §6 passes against such a forgery by construction (that is
// exactly what "the attacker has your key" means). Only the pre-
// compromise heads.log mirror — populated by the root-owned ranad
// process, which the attacker's user-level compromise does not control —
// still holds the original chain_head, and `rana verify --mirror` is the
// sole check that flags the divergence (plan D27).
func TestFullyConsistentForgeryCaughtOnlyByMirror(t *testing.T) {
	root := t.TempDir()
	d := ledger.Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	key, err := chain.GenerateKey(root)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	headsPath := filepath.Join(t.TempDir(), "heads.log")

	w, err := ledger.NewWriter(d, ledger.WriterOptions{
		SegSealMaxEvents:  4,
		CheckpointMaxSegs: 1,
		Key:               key,
		OnHeadReport: func(r chain.HeadReport) {
			if err := chain.AppendHead(headsPath, r); err != nil {
				t.Fatalf("AppendHead: %v", err)
			}
		},
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	session := schema.NewSessionID(fixedClock{ms: 7000})
	writeExecs(t, w, session, 4)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	preHeads, err := chain.ReadHeads(headsPath)
	if err != nil {
		t.Fatalf("ReadHeads: %v", err)
	}
	if len(preHeads) != 1 {
		t.Fatalf("expected 1 pre-compromise head, got %d", len(preHeads))
	}
	origHead := preHeads[0]

	// Sanity: before any tampering, both plain and mirror verify pass.
	if res, err := ledger.Verify(d, ledger.VerifyOptions{}); err != nil || res.Code != ledger.CodeOK {
		t.Fatalf("Verify (pre-tamper): res=%+v err=%v", res, err)
	}
	if res, err := ledger.Verify(d, ledger.VerifyOptions{Mirror: true, HeadsLogPath: headsPath}); err != nil || res.Code != ledger.CodeOK {
		t.Fatalf("Verify --mirror (pre-tamper): res=%+v err=%v", res, err)
	}

	// Attacker: replace the segment's events wholesale with different
	// (but still individually canonical) forged events, recompute a
	// correct merkle root and seg_hash for the new content (so
	// intra-ledger checks 1-3 all pass), and re-sign a matching
	// checkpoint with the real, stolen key (so check 4 passes too).
	db := openRawDB(t, d)

	var firstRowID, lastRowID int64
	var eventCount uint64
	row := db.QueryRow(`SELECT first_rowid, last_rowid, event_count FROM segments WHERE session = ? AND seg = 0`, session)
	if err := row.Scan(&firstRowID, &lastRowID, &eventCount); err != nil {
		t.Fatalf("selecting segment: %v", err)
	}

	forgedEvents := make([][]byte, 0, eventCount)
	rowidsInOrder := make([]int64, 0, eventCount)
	for i := int64(0); i < int64(eventCount); i++ {
		ev := schema.NewProcExec(session, 0, uint64(i), uint64(i), uint64(i), 100,
			[]redact.Redacted{redact.Literal("/bin/FORGED")},
			redact.Literal("FORGED"), redact.Literal("/root"), redact.Literal("/bin/FORGED"),
			1, 0)
		enc := mustEncode(t, ev)
		forgedEvents = append(forgedEvents, enc)
		rowidsInOrder = append(rowidsInOrder, firstRowID+i)
	}
	for i, rowid := range rowidsInOrder {
		mustExec(t, db, `UPDATE events SET bytes = ? WHERE rowid = ?`, forgedEvents[i], rowid)
	}

	leaves := make([][32]byte, len(forgedEvents))
	for i, enc := range forgedEvents {
		leaves[i] = chain.Leaf(enc)
	}
	newRoot := chain.MerkleRoot(leaves)

	header := chain.SegHeader{
		SessionID: session, SegIndex: 0, FirstRowID: firstRowID, LastRowID: lastRowID,
		EventCount: eventCount, MerkleRoot: newRoot, PrevSegHash: [32]byte{},
		GapSummary: map[string]uint64{}, SealedAtWall: 123456,
	}
	newSegHash, newHeaderCBOR, err := chain.SegHash(header)
	if err != nil {
		t.Fatalf("SegHash: %v", err)
	}
	mustExec(t, db, `UPDATE segments SET merkle_root = ?, seg_hash = ?, header = ?, sealed_ns = ? WHERE session = ? AND seg = 0`,
		newRoot[:], newSegHash[:], newHeaderCBOR, header.SealedAtWall, session)

	body, sig, err := chain.SignCheckpoint(key.PrivateKey, chain.Checkpoint{
		SessionID: session, SegFirst: 0, SegLast: 0, ChainHead: newSegHash,
		PrevCheckpointHash: [32]byte{}, SignedAtWall: 123457, PubkeyID: key.PubkeyID,
	})
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	mustExec(t, db, `UPDATE checkpoints SET chain_head = ?, body = ?, sig = ? WHERE session = ?`, newSegHash[:], body, sig, session)
	db.Close()

	// Fully self-consistent forgery: plain Verify must report OK — this
	// is the documented boundary (LIMITS.md §6.1): a same-uid attacker
	// with the real key can produce a forged chain indistinguishable from
	// legitimate history by internal consistency checks alone.
	resPlain, err := ledger.Verify(d, ledger.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify (plain): %v", err)
	}
	if resPlain.Code != ledger.CodeOK {
		t.Fatalf("plain Verify Code = %d, want CodeOK (fully self-consistent forgery is undetectable without --mirror); findings=%+v", resPlain.Code, resPlain.Findings)
	}

	// --mirror must catch it: the mirrored pre-compromise chain_head no
	// longer matches what's now recorded for this checkpoint.
	resMirror, err := ledger.Verify(d, ledger.VerifyOptions{Mirror: true, HeadsLogPath: headsPath})
	if err != nil {
		t.Fatalf("Verify (mirror): %v", err)
	}
	if resMirror.Code != ledger.CodeBroken {
		t.Fatalf("mirror Verify Code = %d, want CodeBroken; findings=%+v", resMirror.Code, resMirror.Findings)
	}
	kinds := findingKinds(resMirror)
	if !kinds[ledger.FindingMirrorMismatch] {
		t.Fatalf("expected mirror_mismatch finding, got %+v", resMirror.Findings)
	}
	if origHead.ChainHead == newSegHash {
		t.Fatalf("test bug: forged chain head coincidentally equals the original")
	}
}
