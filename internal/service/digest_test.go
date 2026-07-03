package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
	"lukechampine.com/blake3"
)

func blake3Sum(data []byte) []byte {
	h := blake3.Sum256(data)
	return h[:]
}

func TestDigestWorker_NewFileEmitsSettleWithNilPrevDigest(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "report.md")
	if err := os.WriteFile(filePath, []byte("hello world"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	fc := newFakeClock(time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC))
	events := make(chan schema.Event, 8)

	w, err := NewDigestWorker(DigestWorkerConfig{
		Scopes:   []string{filepath.Join(dir, "**")},
		Session:  "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Pipeline: testPipeline(t),
		Clock:    fc,
		Emit: func(ev schema.Event) error {
			events <- ev
			return nil
		},
		DebounceInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewDigestWorker: %v", err)
	}

	w.ScanOnce(fc.Now())
	fc.Advance(20 * time.Millisecond)
	w.ScanOnce(fc.Now())

	select {
	case ev := <-events:
		if ev.Type != schema.EventTypeFsSettle {
			t.Fatalf("type = %q, want fs.settle", ev.Type)
		}
		if pd, _ := ev.Data["prev_digest"].([]byte); len(pd) != 0 {
			t.Fatalf("prev_digest = %v, want empty for a newly created file", pd)
		}
		newDigest, _ := ev.Data["new_digest"].([]byte)
		want := blake3Sum([]byte("hello world"))
		if string(newDigest) != string(want) {
			t.Fatalf("new_digest mismatch")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for fs.settle")
	}
}

func TestDigestWorker_ModifiedFileEmitsPrevAndNewDigest(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "report.md")
	if err := os.WriteFile(filePath, []byte("v1"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	fc := newFakeClock(time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC))
	events := make(chan schema.Event, 8)

	w, err := NewDigestWorker(DigestWorkerConfig{
		Scopes:   []string{filepath.Join(dir, "**")},
		Session:  "s",
		Pipeline: testPipeline(t),
		Clock:    fc,
		Emit: func(ev schema.Event) error {
			events <- ev
			return nil
		},
		DebounceInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewDigestWorker: %v", err)
	}

	// Settle the initial version first.
	w.ScanOnce(fc.Now())
	fc.Advance(20 * time.Millisecond)
	w.ScanOnce(fc.Now())
	<-events // drain the "new file" settle

	// Modify.
	fc.Advance(1 * time.Second)
	if err := os.WriteFile(filePath, []byte("v2, longer content"), 0o644); err != nil {
		t.Fatalf("WriteFile v2: %v", err)
	}
	w.ScanOnce(fc.Now())
	fc.Advance(20 * time.Millisecond)
	w.ScanOnce(fc.Now())

	select {
	case ev := <-events:
		prev, _ := ev.Data["prev_digest"].([]byte)
		newD, _ := ev.Data["new_digest"].([]byte)
		if string(prev) != string(blake3Sum([]byte("v1"))) {
			t.Fatalf("prev_digest mismatch")
		}
		if string(newD) != string(blake3Sum([]byte("v2, longer content"))) {
			t.Fatalf("new_digest mismatch")
		}
		delta, _ := ev.Data["size_delta"].(int64)
		if delta != int64(len("v2, longer content")-len("v1")) {
			t.Fatalf("size_delta = %d, want %d", delta, len("v2, longer content")-len("v1"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for modified fs.settle")
	}
}

func TestDigestWorker_UnchangedFileEmitsNothing(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "static.txt")
	if err := os.WriteFile(filePath, []byte("never changes"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	fc := newFakeClock(time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC))
	events := make(chan schema.Event, 8)

	w, err := NewDigestWorker(DigestWorkerConfig{
		Scopes:   []string{filepath.Join(dir, "**")},
		Session:  "s",
		Pipeline: testPipeline(t),
		Clock:    fc,
		Emit: func(ev schema.Event) error {
			events <- ev
			return nil
		},
		DebounceInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewDigestWorker: %v", err)
	}

	w.ScanOnce(fc.Now())
	fc.Advance(20 * time.Millisecond)
	w.ScanOnce(fc.Now())
	<-events // initial settle

	fc.Advance(1 * time.Second)
	w.ScanOnce(fc.Now())
	fc.Advance(20 * time.Millisecond)
	w.ScanOnce(fc.Now())

	select {
	case ev := <-events:
		t.Fatalf("unchanged file produced a settle event: %+v", ev)
	case <-time.After(200 * time.Millisecond):
		// expected
	}
}

func TestDigestWorker_ExcludedPathNeverScanned(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "junk.tmp"), []byte("noise"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	fc := newFakeClock(time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC))
	events := make(chan schema.Event, 8)

	w, err := NewDigestWorker(DigestWorkerConfig{
		Scopes:   []string{filepath.Join(dir, "**")},
		Exclude:  []string{filepath.Join(dir, "cache", "**")},
		Session:  "s",
		Pipeline: testPipeline(t),
		Clock:    fc,
		Emit: func(ev schema.Event) error {
			events <- ev
			return nil
		},
		DebounceInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewDigestWorker: %v", err)
	}

	w.ScanOnce(fc.Now())
	fc.Advance(20 * time.Millisecond)
	w.ScanOnce(fc.Now())

	select {
	case ev := <-events:
		t.Fatalf("excluded path produced a settle event: %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestDigestWorker_PathIsRedactedBeforeEvent(t *testing.T) {
	dir := t.TempDir()
	// A path segment containing an AWS-key-shaped string should come out
	// redacted in the emitted event's path field. Split literal so the
	// contiguous AWS-key shape never appears in source (secret-scanner
	// hygiene); still matches AKIA[0-9A-Z]{16} at runtime.
	secretDirName := "AKIA" + "XXXXXXXXXXXXXXXX"
	secretDir := filepath.Join(dir, secretDirName)
	if err := os.MkdirAll(secretDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	filePath := filepath.Join(secretDir, "f.txt")
	if err := os.WriteFile(filePath, []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	fc := newFakeClock(time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC))
	events := make(chan schema.Event, 8)

	w, err := NewDigestWorker(DigestWorkerConfig{
		Scopes:   []string{filepath.Join(dir, "**")},
		Session:  "s",
		Pipeline: testPipeline(t),
		Clock:    fc,
		Emit: func(ev schema.Event) error {
			events <- ev
			return nil
		},
		DebounceInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewDigestWorker: %v", err)
	}

	w.ScanOnce(fc.Now())
	fc.Advance(20 * time.Millisecond)
	w.ScanOnce(fc.Now())

	select {
	case ev := <-events:
		rv, ok := ev.Data["path"].(redact.Redacted)
		if !ok {
			t.Fatalf("path field is %T, want redact.Redacted", ev.Data["path"])
		}
		if strings.Contains(string(rv), secretDirName) {
			t.Fatalf("path %q leaks the raw secret-shaped directory name", rv)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}
