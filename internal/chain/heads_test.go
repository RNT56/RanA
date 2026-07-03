package chain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func sampleHeadReport(segLast uint64) HeadReport {
	var head [32]byte
	var ckpt [32]byte
	for i := range head {
		head[i] = byte(segLast + uint64(i))
		ckpt[i] = byte(segLast*2 + uint64(i))
	}
	return HeadReport{
		SessionID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		SegLast:   segLast,
		ChainHead: head,
		CkptHash:  ckpt,
		At:        1700000000000000000 + segLast,
	}
}

// TestAppendHead_ReadHeadsRoundTrip: reports appended in order are read
// back in the same order with identical field values.
func TestAppendHead_ReadHeadsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heads.log")

	reports := []HeadReport{sampleHeadReport(0), sampleHeadReport(64), sampleHeadReport(128)}
	for _, r := range reports {
		if err := AppendHead(path, r); err != nil {
			t.Fatalf("AppendHead: %v", err)
		}
	}

	got, err := ReadHeads(path)
	if err != nil {
		t.Fatalf("ReadHeads: %v", err)
	}
	if len(got) != len(reports) {
		t.Fatalf("got %d reports, want %d", len(got), len(reports))
	}
	for i, want := range reports {
		if got[i] != want {
			t.Errorf("report %d = %+v, want %+v", i, got[i], want)
		}
	}
}

// TestAppendHead_NeverTruncates: AppendHead must never truncate the file —
// each call strictly appends (docs/TRUST.md §5, D27: root-owned,
// append-only heads.log).
func TestAppendHead_NeverTruncates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heads.log")

	if err := AppendHead(path, sampleHeadReport(0)); err != nil {
		t.Fatalf("append 1: %v", err)
	}
	sizeAfterFirst, err := fileSize(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if err := AppendHead(path, sampleHeadReport(1)); err != nil {
		t.Fatalf("append 2: %v", err)
	}
	sizeAfterSecond, err := fileSize(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if sizeAfterSecond <= sizeAfterFirst {
		t.Fatalf("file did not grow: %d -> %d (looks truncated)", sizeAfterFirst, sizeAfterSecond)
	}

	got, err := ReadHeads(path)
	if err != nil {
		t.Fatalf("ReadHeads: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d reports after two appends, want 2", len(got))
	}
}

func fileSize(path string) (int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// TestAppendHead_OneJSONLinePerRecord: each appended report is exactly one
// line of JSON (CONTRACTS: "O_APPEND single-line JSON").
func TestAppendHead_OneJSONLinePerRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heads.log")

	for i := uint64(0); i < 3; i++ {
		if err := AppendHead(path, sampleHeadReport(i)); err != nil {
			t.Fatalf("AppendHead: %v", err)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	lines := splitLines(raw)
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3 (raw=%q)", len(lines), raw)
	}
	for i, line := range lines {
		var v map[string]any
		if err := json.Unmarshal(line, &v); err != nil {
			t.Errorf("line %d is not valid JSON: %v (line=%q)", i, err, line)
		}
	}
}

func splitLines(b []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			if i > start {
				lines = append(lines, b[start:i])
			}
			start = i + 1
		}
	}
	if start < len(b) {
		lines = append(lines, b[start:])
	}
	return lines
}

// TestReadHeads_SkipsTornLastLine: a corrupted/truncated final line (as
// would happen if a crash occurred mid-write) is skipped, not treated as a
// fatal error — corruption tolerance is a named CONTRACTS requirement for
// ReadHeads.
func TestReadHeads_SkipsTornLastLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heads.log")

	if err := AppendHead(path, sampleHeadReport(0)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := AppendHead(path, sampleHeadReport(1)); err != nil {
		t.Fatalf("append: %v", err)
	}

	// Simulate a torn write: append a partial JSON line with no trailing
	// newline, as if the process died mid-write.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open for torn append: %v", err)
	}
	if _, err := f.WriteString(`{"session_id":"partial`); err != nil {
		t.Fatalf("write torn line: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, err := ReadHeads(path)
	if err != nil {
		t.Fatalf("ReadHeads must tolerate a torn last line, got error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d reports, want 2 (torn last line should be skipped)", len(got))
	}
	if got[0].SegLast != 0 || got[1].SegLast != 1 {
		t.Fatalf("unexpected report contents: %+v", got)
	}
}

// TestReadHeads_SkipsTornLastLine_MalformedJSONButNewlineTerminated: a
// line that IS newline-terminated but contains malformed JSON (e.g. a
// write that completed the newline but corrupted content mid-flush) is
// also tolerated when it's the last line — corruption tolerance applies to
// "torn last line" broadly, not only missing-newline cases. Non-last
// malformed lines are a harder error since they cannot be explained by an
// in-progress write.
func TestReadHeads_MalformedNonLastLineErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heads.log")

	if err := os.WriteFile(path, []byte("not json at all\n"+mustJSONLine(t, sampleHeadReport(5))), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := ReadHeads(path); err == nil {
		t.Fatalf("expected error for malformed non-last line, got nil")
	}
}

func mustJSONLine(t *testing.T, r HeadReport) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b) + "\n"
}

// TestReadHeads_EmptyOrMissingFile: reading a nonexistent heads.log
// returns an empty slice, not an error — a fresh install has no mirror
// yet, and that must not be fatal for --mirror consumers doing an initial
// check.
func TestReadHeads_MissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.log")

	got, err := ReadHeads(path)
	if err != nil {
		t.Fatalf("ReadHeads on missing file: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d reports from missing file, want 0", len(got))
	}
}

// TestAppendHead_CreatesFileIfMissing confirms AppendHead works against a
// path whose file does not yet exist (first checkpoint of a fresh
// install).
func TestAppendHead_CreatesFileIfMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heads.log")

	if err := AppendHead(path, sampleHeadReport(0)); err != nil {
		t.Fatalf("AppendHead on missing file: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("heads.log was not created: %v", err)
	}
}
