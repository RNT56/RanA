package ledger

import (
	"testing"

	"github.com/RNT56/RanA/internal/chain"
)

// TestCheckpointChainSpansSessions confirms prev_checkpoint_hash chains
// across the WHOLE ledger, not per-session (docs/TRUST.md §5):
// the second session's first checkpoint must chain from the first
// session's last checkpoint.
func TestCheckpointChainSpansSessions(t *testing.T) {
	key, err := chain.GenerateKey(t.TempDir())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	opts := WriterOptions{SegSealMaxEvents: 1, CheckpointMaxSegs: 1, Key: key}
	w, fc := newTestWriterWithOpts(t, opts)

	sessionA := "01ARZ3NDEKTSV4RRFFQ69G5FB0"
	sessionB := "01ARZ3NDEKTSV4RRFFQ69G5FB1"

	evA := testMkExec(sessionA, 0, 0, fc.Now(), 100)
	if err := w.Append(evA); err != nil {
		t.Fatalf("Append A: %v", err)
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("flush A: %v", err)
	}

	evB := testMkExec(sessionB, 0, 0, fc.Now(), 100)
	if err := w.Append(evB); err != nil {
		t.Fatalf("Append B: %v", err)
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("flush B: %v", err)
	}

	cksA, err := readCheckpoints(w.db, sessionA)
	if err != nil {
		t.Fatalf("readCheckpoints A: %v", err)
	}
	cksB, err := readCheckpoints(w.db, sessionB)
	if err != nil {
		t.Fatalf("readCheckpoints B: %v", err)
	}
	if len(cksA) != 1 || len(cksB) != 1 {
		t.Fatalf("expected 1 checkpoint per session, got %d and %d", len(cksA), len(cksB))
	}

	hashA := chain.CheckpointHash(cksA[0].Body)
	if cksB[0].PrevHash != hashA {
		t.Fatalf("session B's checkpoint does not chain from session A's checkpoint: got prev_hash %x, want %x", cksB[0].PrevHash, hashA)
	}

	// The very first checkpoint in the ledger chains from genesis (zero).
	if cksA[0].PrevHash != ([32]byte{}) {
		t.Fatalf("first-ever checkpoint's prev_hash should be genesis zero, got %x", cksA[0].PrevHash)
	}
}

func TestCheckpointDueAfterMaxWait(t *testing.T) {
	key, err := chain.GenerateKey(t.TempDir())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	opts := WriterOptions{
		SegSealMaxEvents:  1,
		CheckpointMaxSegs: 1000, // effectively disabled by count
		CheckpointMaxWait: 5 * 60 * 1_000_000_000,
		Key:               key,
	}
	w, fc := newTestWriterWithOpts(t, opts)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FB2"

	ev := testMkExec(session, 0, 0, fc.Now(), 100)
	if err := w.Append(ev); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	cks, err := readCheckpoints(w.db, session)
	if err != nil {
		t.Fatalf("readCheckpoints: %v", err)
	}
	if len(cks) != 0 {
		t.Fatalf("checkpoint written before wait threshold: %d", len(cks))
	}

	// Advance past 5 minutes and touch the session again to trigger the
	// due-check.
	w.AdvanceAndSync(fc, 5*60*1_000_000_000+1)
	ev2 := testMkExec(session, 1, 1, fc.Now(), 100)
	if err := w.Append(ev2); err != nil {
		t.Fatalf("Append 2: %v", err)
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("flush 2: %v", err)
	}

	cks, err = readCheckpoints(w.db, session)
	if err != nil {
		t.Fatalf("readCheckpoints: %v", err)
	}
	if len(cks) != 1 {
		t.Fatalf("got %d checkpoints after wait threshold, want 1", len(cks))
	}
}
