package ledger

import (
	"os"
	"testing"
	"time"
)

func TestGCArchivesOldSegmentsAndNullsEventBytes(t *testing.T) {
	d, _ := buildCleanLedger(t)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FC0"

	db, err := openDB(d.DBPath)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()

	segsBefore, err := readSegments(db, session)
	if err != nil {
		t.Fatalf("readSegments: %v", err)
	}
	if len(segsBefore) == 0 {
		t.Fatalf("fixture has no sealed segments to archive")
	}

	// GC everything (ttl=0 means "everything sealed is eligible").
	n, err := GC(d, 0)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n == 0 {
		t.Fatalf("GC archived 0 segments, want > 0")
	}

	segsAfter, err := readSegments(db, session)
	if err != nil {
		t.Fatalf("readSegments after GC: %v", err)
	}
	archivedCount := 0
	for _, s := range segsAfter {
		if s.ArchivedPath.Valid {
			archivedCount++
			if _, err := os.Stat(s.ArchivedPath.String); err != nil {
				t.Errorf("archive file missing for seg %d: %v", s.Seg, err)
			}
		}
	}
	if archivedCount == 0 {
		t.Fatalf("no segment rows marked archived after GC")
	}

	// Every archived segment's event bytes must be nulled out (GC compacts
	// the hot events table; the archive is the only remaining copy).
	evs, err := readSegmentEvents(db, session, segsBefore[0].FirstRowID, segsBefore[0].LastRowID)
	if err != nil {
		t.Fatalf("readSegmentEvents: %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("expected archived segment's event bytes to be nulled, found %d non-null rows", len(evs))
	}
}

func TestGCRespectsTTL(t *testing.T) {
	d, _ := buildCleanLedger(t)

	// buildCleanLedger seals everything using a fakeClock starting at
	// 1_000_000_000 ns; GCAt lets us pin "now" to shortly after that, so
	// a large ttl genuinely means "nothing is old enough yet" rather than
	// being swamped by the huge gap between a fakeClock's epoch and the
	// real wall clock GC's public entrypoint uses.
	now := uint64(1_000_000_000) + uint64(time.Second.Nanoseconds()) // 1s after fixture sealing
	n, err := GCAt(d, 365*24*time.Hour, now)
	if err != nil {
		t.Fatalf("GCAt: %v", err)
	}
	if n != 0 {
		t.Fatalf("GCAt archived %d segments with a far-future ttl, want 0", n)
	}

	// The same segments become eligible once "now" is far enough past
	// their sealed_ns for the ttl to have elapsed.
	nowLater := now + uint64((366 * 24 * time.Hour).Nanoseconds())
	n2, err := GCAt(d, 365*24*time.Hour, nowLater)
	if err != nil {
		t.Fatalf("GCAt (later): %v", err)
	}
	if n2 == 0 {
		t.Fatalf("GCAt archived 0 segments once ttl had elapsed, want > 0")
	}
}

func TestVerifyOverArchivedRangeReportsIncompleteNotBroken(t *testing.T) {
	d, _ := buildCleanLedger(t)

	if _, err := GC(d, 0); err != nil {
		t.Fatalf("GC: %v", err)
	}

	res, err := Verify(d, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Code != CodeIncomplete {
		t.Fatalf("Code = %d, want CodeIncomplete(3) over an archived range; findings=%+v", res.Code, res.Findings)
	}
	for _, f := range res.Findings {
		if f.Kind == FindingChainLinkBroken || f.Kind == FindingMerkleMismatch {
			t.Errorf("archived range must not report BROKEN-style findings, got %+v", f)
		}
	}
}

func TestGCOnUnknownDatadirIsNoop(t *testing.T) {
	root := t.TempDir()
	d := Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	n, err := GC(d, 0)
	if err != nil {
		t.Fatalf("GC on empty ledger: %v", err)
	}
	if n != 0 {
		t.Fatalf("GC on empty ledger archived %d segments, want 0", n)
	}
}
