package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
	"lukechampine.com/blake3"
)

// buildLedgerWithFsSettle writes a small ledger containing one fs.settle
// event whose recorded path points at a real file under a scratch
// directory, and whose new_digest is that file's actual BLAKE3 digest — so
// `rana show --diff` should report a match. It returns the root data dir,
// the session id, and the on-disk file's path (for tests that want to
// mutate/delete it to exercise the mismatch/missing paths).
func buildLedgerWithFsSettle(t *testing.T, content string) (root, session, filePath string) {
	t.Helper()
	root = t.TempDir()
	d := ledger.Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	key, err := chain.GenerateKey(root)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	w, err := ledger.NewWriter(d, ledger.WriterOptions{Key: key})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	scratchDir := t.TempDir()
	filePath = filepath.Join(scratchDir, "settled.txt")
	if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
		t.Fatalf("writing settled file: %v", err)
	}
	h := blake3.New(32, nil)
	h.Write([]byte(content))
	digest := h.Sum(nil)

	session = "01ARZ3NDEKTSV4RRFFQ69G5FC1"
	ev := schema.NewFsSettle(session, 0, 1, 1_000_000_000, 1_000_000_000, 100,
		redact.Literal(filePath), nil, digest, int64(len(content)), 1_000_000_000)
	if err := w.Append(ev); err != nil {
		t.Fatalf("Append fs.settle: %v", err)
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
	return root, session, filePath
}

// TestShow_DiffReportsMatch proves `rana show --diff` runs
// report.DigestDiff for an fs.settle event and reports that the on-disk
// content matches the recorded digest, without ever printing file content.
func TestShow_DiffReportsMatch(t *testing.T) {
	root, session, _ := buildLedgerWithFsSettle(t, "hello from rana")

	code, out, errs := run("show", "--data", root, "--diff", session)
	if code != 0 {
		t.Fatalf("show --diff: code=%d err=%q", code, errs)
	}
	if !strings.Contains(out, "fs.settle") {
		t.Fatalf("show --diff: missing fs.settle line: %q", out)
	}
	if !strings.Contains(out, "matches the recorded new_digest") {
		t.Fatalf("show --diff: expected a match note, got: %q", out)
	}
	if strings.Contains(out, "hello from rana") {
		t.Fatalf("show --diff: leaked file content into output: %q", out)
	}
}

// TestShow_DiffReportsMissingFile proves the availability-only contract
// when the recorded file is no longer present on disk.
func TestShow_DiffReportsMissingFile(t *testing.T) {
	root, session, filePath := buildLedgerWithFsSettle(t, "will be deleted")
	if err := os.Remove(filePath); err != nil {
		t.Fatalf("removing settled file: %v", err)
	}

	code, out, errs := run("show", "--data", root, "--diff", session)
	if code != 0 {
		t.Fatalf("show --diff: code=%d err=%q", code, errs)
	}
	if !strings.Contains(out, "not present on local disk") {
		t.Fatalf("show --diff: expected a missing-file note, got: %q", out)
	}
}

// TestShow_WithoutDiffFlagNoDigestOutput proves --diff is opt-in: without
// it, show's output is unchanged from the pre-existing behavior (no diff
// lines at all).
func TestShow_WithoutDiffFlagNoDigestOutput(t *testing.T) {
	root, session, _ := buildLedgerWithFsSettle(t, "hello from rana")

	code, out, errs := run("show", "--data", root, session)
	if code != 0 {
		t.Fatalf("show: code=%d err=%q", code, errs)
	}
	if strings.Contains(out, "diff:") {
		t.Fatalf("show without --diff should not print diff lines: %q", out)
	}
}
