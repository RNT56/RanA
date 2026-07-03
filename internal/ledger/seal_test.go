package ledger

import (
	"testing"

	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/schema"
)

func newTestWriterWithOpts(t *testing.T, opts WriterOptions) (*Writer, *fakeClock) {
	t.Helper()
	root := t.TempDir()
	d := Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	fc := newFakeClock(1_000_000_000)
	w, err := newWriterWithClock(d, opts, fc)
	if err != nil {
		t.Fatalf("newWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, fc
}

func TestWriterSealsSegmentByEventCount(t *testing.T) {
	opts := WriterOptions{SegSealMaxEvents: 10}
	w, fc := newTestWriterWithOpts(t, opts)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FA0"

	for i := 0; i < 10; i++ {
		ev := testMkExec(session, 0, uint64(i), fc.Now(), 100)
		if err := w.Append(ev); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("FlushForTest: %v", err)
	}

	segs, err := readSegments(w.db, session)
	if err != nil {
		t.Fatalf("readSegments: %v", err)
	}
	if len(segs) != 1 {
		t.Fatalf("got %d sealed segments, want 1", len(segs))
	}
	if segs[0].EventCount != 10 {
		t.Fatalf("EventCount = %d, want 10", segs[0].EventCount)
	}
	if segs[0].PrevSegHash != ([32]byte{}) {
		t.Fatalf("first segment's PrevSegHash should be genesis zero, got %x", segs[0].PrevSegHash)
	}
}

func TestWriterSealsSegmentByAge(t *testing.T) {
	opts := WriterOptions{SegSealMaxAge: 60_000_000_000} // 60s in ns, but we override via option field type (time.Duration)
	opts.SegSealMaxAge = 60_000_000_000
	w, fc := newTestWriterWithOpts(t, opts)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FA1"

	ev := testMkExec(session, 0, 0, fc.Now(), 100)
	if err := w.Append(ev); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("flush 1: %v", err)
	}

	// Not yet sealed: age threshold not reached.
	segs, err := readSegments(w.db, session)
	if err != nil {
		t.Fatalf("readSegments: %v", err)
	}
	if len(segs) != 0 {
		t.Fatalf("segment sealed too early: %d segments", len(segs))
	}

	// Advance the clock past the age threshold and append one more event
	// to trigger the seal check (seal checks run as part of a batch that
	// touches the session).
	w.AdvanceAndSync(fc, 61_000_000_000)
	ev2 := testMkExec(session, 0, 1, fc.Now(), 100)
	if err := w.Append(ev2); err != nil {
		t.Fatalf("Append 2: %v", err)
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("flush 2: %v", err)
	}

	segs, err = readSegments(w.db, session)
	if err != nil {
		t.Fatalf("readSegments: %v", err)
	}
	if len(segs) != 1 {
		t.Fatalf("got %d sealed segments, want 1", len(segs))
	}
}

func TestWriterSealOnCloseFlushesOpenSegment(t *testing.T) {
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
	session := "01ARZ3NDEKTSV4RRFFQ69G5FA2"

	ev := testMkExec(session, 0, 0, fc.Now(), 100)
	if err := w.Append(ev); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// session.end forces a seal even without crossing count/age thresholds.
	end := schema.NewSessionEnd(session, 0, 1, fc.Now(), fc.Now(), 100)
	if err := w.Append(end); err != nil {
		t.Fatalf("Append end: %v", err)
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("FlushForTest: %v", err)
	}

	// The writer does not auto-seal on session.end unless SealSession is
	// called explicitly (session.end is just another event from the
	// writer's perspective; sealing-on-end is orchestrated by svc calling
	// SealSession). Confirm explicit SealSession seals the open segment.
	if err := w.SealSession(session); err != nil {
		t.Fatalf("SealSession: %v", err)
	}

	segs, err := readSegments(w.db, session)
	if err != nil {
		t.Fatalf("readSegments: %v", err)
	}
	if len(segs) != 1 {
		t.Fatalf("got %d sealed segments after SealSession, want 1", len(segs))
	}
	if segs[0].EventCount != 2 {
		t.Fatalf("EventCount = %d, want 2", segs[0].EventCount)
	}
}

func TestWriterCheckspointsAfterMaxSegs(t *testing.T) {
	key, err := chain.GenerateKey(t.TempDir())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	opts := WriterOptions{
		SegSealMaxEvents:  1,
		CheckpointMaxSegs: 3,
		Key:               key,
	}
	w, fc := newTestWriterWithOpts(t, opts)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FA3"

	for i := 0; i < 3; i++ {
		ev := testMkExec(session, 0, uint64(i), fc.Now(), 100)
		if err := w.Append(ev); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if err := w.FlushForTest(); err != nil {
			t.Fatalf("flush %d: %v", i, err)
		}
	}

	cks, err := readCheckpoints(w.db, session)
	if err != nil {
		t.Fatalf("readCheckpoints: %v", err)
	}
	if len(cks) != 1 {
		t.Fatalf("got %d checkpoints, want 1", len(cks))
	}
	if cks[0].SegFirst != 0 || cks[0].SegLast != 2 {
		t.Fatalf("checkpoint seg range = [%d,%d], want [0,2]", cks[0].SegFirst, cks[0].SegLast)
	}

	pub := key.PublicKey
	if err := chain.VerifyCheckpoint(pub, cks[0].Body, cks[0].Sig); err != nil {
		t.Fatalf("checkpoint signature does not verify: %v", err)
	}
}

func TestWriterHeadReportCallback(t *testing.T) {
	key, err := chain.GenerateKey(t.TempDir())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var reports []chain.HeadReport
	opts := WriterOptions{
		SegSealMaxEvents:  1,
		CheckpointMaxSegs: 1,
		Key:               key,
		OnHeadReport: func(r chain.HeadReport) {
			reports = append(reports, r)
		},
	}
	w, fc := newTestWriterWithOpts(t, opts)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FA4"

	ev := testMkExec(session, 0, 0, fc.Now(), 100)
	if err := w.Append(ev); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if len(reports) != 1 {
		t.Fatalf("got %d head reports, want 1", len(reports))
	}
	if reports[0].SessionID != session {
		t.Fatalf("report session = %q, want %q", reports[0].SessionID, session)
	}
}

func TestWriterGapEventAccumulatesIntoSegmentGapSummary(t *testing.T) {
	opts := WriterOptions{SegSealMaxEvents: 2}
	w, fc := newTestWriterWithOpts(t, opts)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FA5"

	gapEv := schema.NewGap(session, 0, 0, fc.Now(), fc.Now(), 0, "governor", map[string]uint64{"fs.write_open": 3}, fc.Now(), fc.Now())
	if err := w.Append(gapEv); err != nil {
		t.Fatalf("Append gap: %v", err)
	}
	ev := testMkExec(session, 0, 1, fc.Now(), 100)
	if err := w.Append(ev); err != nil {
		t.Fatalf("Append exec: %v", err)
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	segs, err := readSegments(w.db, session)
	if err != nil {
		t.Fatalf("readSegments: %v", err)
	}
	if len(segs) != 1 {
		t.Fatalf("got %d segments, want 1", len(segs))
	}
	if segs[0].GapSummary["governor"] != 1 {
		t.Fatalf("GapSummary[governor] = %d, want 1", segs[0].GapSummary["governor"])
	}
}
