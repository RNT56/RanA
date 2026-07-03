package ledger

import (
	"testing"

	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// testMkExec builds a minimal, valid proc.exec event for session at the
// given idx/ts.
func testMkExec(session string, seg, idx uint64, ts uint64, pid uint32) schema.Event {
	return schema.NewProcExec(session, seg, idx, ts, ts, pid,
		[]redact.Redacted{redact.Literal("/bin/true")},
		redact.Literal("true"), redact.Literal("/root"), redact.Literal("/bin/true"),
		1, 0)
}

func newTestWriter(t *testing.T) (*Writer, *fakeClock) {
	t.Helper()
	root := t.TempDir()
	d := Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	fc := newFakeClock(1_000_000_000)
	w, err := newWriterWithClock(d, WriterOptions{}, fc)
	if err != nil {
		t.Fatalf("newWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, fc
}

func TestWriterAppendAndFlushByCount(t *testing.T) {
	w, fc := newTestWriter(t)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FAV"

	for i := 0; i < 5; i++ {
		ev := testMkExec(session, 0, uint64(i), fc.Now(), 100)
		if err := w.Append(ev); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// Force a flush by advancing the group-commit timer.
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("FlushForTest: %v", err)
	}

	count, err := countEventsForSession(w.db, session)
	if err != nil {
		t.Fatalf("countEvents: %v", err)
	}
	if count != 5 {
		t.Fatalf("event count = %d, want 5", count)
	}
}

func TestWriterAppendRejectsInvalidEvent(t *testing.T) {
	w, _ := newTestWriter(t)
	bad := schema.Event{} // empty: fails schema.Validate
	if err := w.Append(bad); err == nil {
		t.Fatalf("expected error appending invalid event")
	}
}

func TestWriterGroupCommitByTimer(t *testing.T) {
	w, fc := newTestWriter(t)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FAW"

	ev := testMkExec(session, 0, 0, fc.Now(), 100)
	if err := w.Append(ev); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Advance past the 10ms group-commit timer and let the writer loop
	// process it.
	w.AdvanceAndSync(fc, 11_000_000) // 11ms in ns

	count, err := countEventsForSession(w.db, session)
	if err != nil {
		t.Fatalf("countEvents: %v", err)
	}
	if count != 1 {
		t.Fatalf("event count = %d, want 1", count)
	}
}

func TestWriterAssignsMonotonicRowID(t *testing.T) {
	w, fc := newTestWriter(t)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FAX"

	for i := 0; i < 10; i++ {
		ev := testMkExec(session, 0, uint64(i), fc.Now(), 100)
		if err := w.Append(ev); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("FlushForTest: %v", err)
	}

	rows, err := readEventRowIDs(w.db, session)
	if err != nil {
		t.Fatalf("readEventRowIDs: %v", err)
	}
	if len(rows) != 10 {
		t.Fatalf("got %d rows, want 10", len(rows))
	}
	for i := 1; i < len(rows); i++ {
		if rows[i] != rows[i-1]+1 {
			t.Fatalf("rowids not contiguous/monotonic: %v", rows)
		}
	}
}
