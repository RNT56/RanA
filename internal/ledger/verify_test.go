package ledger

import (
	"os"
	"testing"

	"github.com/RNT56/RanA/internal/chain"
)

// buildCleanLedger writes a small multi-session, multi-segment,
// multi-checkpoint ledger and returns the Datadir plus the signing key
// used, for verify tests to open independently (as `rana verify` would).
func buildCleanLedger(t *testing.T) (Datadir, chain.KeyInfo) {
	t.Helper()
	root := t.TempDir()
	d := Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	key, err := chain.GenerateKey(root)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	opts := WriterOptions{SegSealMaxEvents: 5, CheckpointMaxSegs: 2, Key: key}
	fc := newFakeClock(1_000_000_000)
	w, err := newWriterWithClock(d, opts, fc)
	if err != nil {
		t.Fatalf("newWriterWithClock: %v", err)
	}

	session := "01ARZ3NDEKTSV4RRFFQ69G5FC0"
	// 3 segments' worth (15 events) so a checkpoint covers segs [0,1] and
	// seg 2 remains unattested tail.
	for i := 0; i < 15; i++ {
		ev := testMkExec(session, 0, uint64(i), fc.Now(), 100)
		if err := w.Append(ev); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if err := w.FlushForTest(); err != nil {
			t.Fatalf("flush %d: %v", i, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	return d, key
}

func TestVerifyCleanLedgerPasses(t *testing.T) {
	d, key := buildCleanLedger(t)

	res, err := Verify(d, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Code != 0 {
		t.Fatalf("Code = %d, want 0; findings: %+v", res.Code, res.Findings)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected zero findings on clean ledger, got %+v", res.Findings)
	}
	if len(res.UnattestedTail) == 0 {
		t.Fatalf("expected a non-empty unattested tail (seg 2 was sealed but not checkpointed)")
	}
	_ = key
}

func TestVerifyEmptyLedgerPasses(t *testing.T) {
	root := t.TempDir()
	d := Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	res, err := Verify(d, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Code != 0 {
		t.Fatalf("Code = %d, want 0 on an empty ledger", res.Code)
	}
}

// TestVerifyWithNoResolvablePubkeyIsIncompleteNotOK proves that when a
// session has signed checkpoints but NO public key can be resolved (the
// ledger's meta table pubkey rows are gone AND device.key is gone — e.g.
// an attacker deleted both, or an operator lost the key), Verify reports
// CodeIncomplete(3) rather than silently degrading check 4
// (docs/TRUST.md §6: "verify every checkpoint signature") into a no-op
// that reports CodeOK. Deleting the means to check a signature must never
// be cheaper than defeating the signature itself — see
// TestFullyConsistentForgeryCaughtOnlyByMirror in
// test/chain-mutations for the (much more expensive, key-required) attack
// this must not be strictly weaker than.
func TestVerifyWithNoResolvablePubkeyIsIncompleteNotOK(t *testing.T) {
	d, _ := buildCleanLedger(t)

	db, err := openDB(d.DBPath)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM meta WHERE k IN ('pubkey_id','pubkey_pem')`); err != nil {
		t.Fatalf("wiping meta pubkey rows: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing db: %v", err)
	}
	if err := os.Remove(d.KeyPath); err != nil {
		t.Fatalf("removing device.key: %v", err)
	}

	res, err := Verify(d, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Code == CodeOK {
		t.Fatalf("Code = OK, want Incomplete(3): a session has signed checkpoints but no pubkey is resolvable to check them, findings=%+v", res.Findings)
	}
	if res.Code != CodeIncomplete {
		t.Fatalf("Code = %d, want CodeIncomplete(3); findings=%+v", res.Code, res.Findings)
	}

	// A garbage/corrupted signature must be EQUALLY unmissable in this
	// state (never masked by the missing-pubkey degrade) — same
	// CodeIncomplete outcome, not a silent pass-through.
	d2, _ := buildCleanLedger(t)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FC0"
	db2, err := openDB(d2.DBPath)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	if _, err := db2.Exec(`UPDATE checkpoints SET sig = ? WHERE session = ?`, []byte("garbage-not-a-real-sig"), session); err != nil {
		t.Fatalf("corrupting sig: %v", err)
	}
	if _, err := db2.Exec(`DELETE FROM meta WHERE k IN ('pubkey_id','pubkey_pem')`); err != nil {
		t.Fatalf("wiping meta pubkey rows: %v", err)
	}
	if err := db2.Close(); err != nil {
		t.Fatalf("closing db: %v", err)
	}
	if err := os.Remove(d2.KeyPath); err != nil {
		t.Fatalf("removing device.key: %v", err)
	}
	res2, err := Verify(d2, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res2.Code == CodeOK {
		t.Fatalf("Code = OK for a GARBAGE signature merely because the pubkey is unresolvable; want Incomplete(3) at minimum, findings=%+v", res2.Findings)
	}
}
