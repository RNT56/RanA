package ledger

import (
	"strings"
	"testing"
)

// TestWriterAppendRefusesAfterCommitError proves the writer surfaces a
// fatal commit-time failure via Err() and that Append immediately refuses
// further writes once Err() is set (P5's "losses are loud" spirit applied
// to the writer's own durability, rather than silently accepting events
// into a writer that has already shown it cannot persist them).
func TestWriterAppendRefusesAfterCommitError(t *testing.T) {
	w, fc := newTestWriter(t)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FD0"

	// Force a commit-time failure by closing the underlying sqlite handle
	// out from under the writer goroutine, then trigger a flush.
	if err := w.db.Close(); err != nil {
		t.Fatalf("closing db to simulate failure: %v", err)
	}

	ev := testMkExec(session, 0, 0, fc.Now(), 100)
	if err := w.Append(ev); err != nil {
		t.Fatalf("Append (before the writer has processed the batch) should still succeed: %v", err)
	}
	_ = w.FlushForTest() // the flush itself will fail; FlushForTest only waits for the attempt, not success

	if w.Err() == nil {
		t.Fatalf("expected Writer.Err() to report the simulated commit failure")
	}

	err := w.Append(testMkExec(session, 0, 1, fc.Now(), 100))
	if err == nil {
		t.Fatalf("expected Append to refuse further writes once Err() is set")
	}
	if !strings.Contains(err.Error(), "fatal commit error") {
		t.Fatalf("Append error = %q, want it to mention the fatal commit error", err.Error())
	}

	// Close should still succeed (it releases the writer goroutine even
	// though the underlying db handle is already closed/broken).
	_ = w.Close()
}
