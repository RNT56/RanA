package main

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"

	_ "modernc.org/sqlite"
)

// run drives the dispatcher and returns (exitCode, stdout, stderr).
func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := dispatch(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestDispatch_UnknownAndHelp(t *testing.T) {
	if code, _, errs := run("bogus-verb"); code != exitUsage || !strings.Contains(errs, "unknown command") {
		t.Fatalf("unknown verb: code=%d err=%q", code, errs)
	}
	if code, out, _ := run("help"); code != exitOK || !strings.Contains(out, "flight recorder") {
		t.Fatalf("help: code=%d out=%q", code, out)
	}
	if code, _, _ := run(); code != exitUsage {
		t.Fatalf("no args should be usage error, got %d", code)
	}
	if code, out, _ := run("version"); code != exitOK || !strings.Contains(out, "rana") {
		t.Fatalf("version: code=%d out=%q", code, out)
	}
}

// TestDispatch_AllFrozenVerbsRoute confirms every plan-D20 verb is wired (no
// verb falls through to "unknown command"). We don't assert success — just
// that the dispatcher recognizes each.
func TestDispatch_AllFrozenVerbsRoute(t *testing.T) {
	verbs := []string{"run", "adopt", "ps", "timeline", "show", "tail", "verify", "export", "gc", "doctor", "vm"}
	for _, v := range verbs {
		t.Run(v, func(t *testing.T) {
			// Give each a harmless data dir so it doesn't touch the real one.
			dir := t.TempDir()
			_, _, errs := run(v, "--data", dir, "--help")
			if strings.Contains(errs, "unknown command") {
				t.Fatalf("verb %q not routed", v)
			}
		})
	}
}

// buildLedger writes a small, valid ledger under a fresh datadir and returns
// its root and the session id.
func buildLedger(t *testing.T) (root, session string) {
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
	w, err := ledger.NewWriter(d, ledger.WriterOptions{
		SegSealMaxEvents:  5,
		CheckpointMaxSegs: 2,
		Key:               key,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	session = "01ARZ3NDEKTSV4RRFFQ69G5FC0"
	for i := 0; i < 12; i++ {
		ts := uint64(1_000_000_000 + i)
		ev := schema.NewProcExec(session, 0, uint64(i), ts, ts, 100,
			[]redact.Redacted{redact.Literal("/bin/true")},
			redact.Literal("true"), redact.Literal("/root"), redact.Literal("/bin/true"), 1, 0)
		if err := w.Append(ev); err != nil {
			t.Fatalf("Append: %v", err)
		}
		if err := w.FlushForTest(); err != nil {
			t.Fatalf("flush: %v", err)
		}
	}
	if err := w.SealSession(session); err != nil {
		t.Fatalf("SealSession: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return root, session
}

// TestVerify_ExitCodeMapping is the load-bearing CLI contract (docs/TRUST.md
// §6): a clean ledger exits 0, a tampered one exits 2. The CLI must never
// soften this mapping.
func TestVerify_ExitCodeMapping(t *testing.T) {
	root, _ := buildLedger(t)

	code, out, _ := run("verify", "--data", root)
	if code != 0 {
		t.Fatalf("clean ledger: verify exit = %d, want 0 (out=%q)", code, out)
	}
	if !strings.Contains(out, "OK") {
		t.Fatalf("clean ledger: want OK in output, got %q", out)
	}

	// Corrupt the ledger's event bytes on disk and re-verify: must be 2.
	corruptEventByte(t, root)
	code, out, _ = run("verify", "--data", root)
	if code != 2 {
		t.Fatalf("tampered ledger: verify exit = %d, want 2 (BROKEN) (out=%q)", code, out)
	}
	if !strings.Contains(out, "BROKEN") {
		t.Fatalf("tampered ledger: want BROKEN in output, got %q", out)
	}
}

// corruptEventByte flips a byte inside one stored event's canonical CBOR via
// SQL, keeping the SQLite file itself valid so Verify returns a clean Code=2
// (a leaf-hash mismatch) rather than a database-open error.
func corruptEventByte(t *testing.T, root string) {
	t.Helper()
	db, err := sql.Open("sqlite", ledger.Dir(root).DBPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	var rowid int64
	var b []byte
	if err := db.QueryRow(`SELECT rowid, bytes FROM events ORDER BY rowid LIMIT 1`).Scan(&rowid, &b); err != nil {
		t.Fatalf("select event: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("first event has empty bytes")
	}
	b[len(b)/2] ^= 0xFF // flip a byte inside the canonical CBOR
	if _, err := db.Exec(`UPDATE events SET bytes = ? WHERE rowid = ?`, b, rowid); err != nil {
		t.Fatalf("update event: %v", err)
	}
}

// TestExportThenShowAndPs exercises the read-only verbs against a real ledger.
func TestExportThenShowAndPs(t *testing.T) {
	root, session := buildLedger(t)

	if code, out, errs := run("ps", "--data", root); code != 0 || !strings.Contains(out, session) {
		t.Fatalf("ps: code=%d out=%q err=%q", code, out, errs)
	}
	if code, out, errs := run("show", "--data", root, session); code != 0 || !strings.Contains(out, "proc.exec") {
		t.Fatalf("show: code=%d out=%q err=%q", code, out, errs)
	}

	outDir := filepath.Join(t.TempDir(), "export")
	if code, _, errs := run("export", "--data", root, "--session", session, "--out", outDir); code != 0 {
		t.Fatalf("export: code=%d err=%q", code, errs)
	}
	if _, err := os.Stat(filepath.Join(outDir, "events.cbor")); err != nil {
		t.Fatalf("export did not produce events.cbor: %v", err)
	}
}

// TestDoctorRunsClean confirms doctor produces a platform section and a data
// section without error on an empty datadir.
func TestDoctorRunsClean(t *testing.T) {
	dir := t.TempDir()
	code, out, errs := run("doctor", "--data", dir)
	if code != 0 {
		t.Fatalf("doctor: code=%d err=%q", code, errs)
	}
	if !strings.Contains(out, "Platform:") || !strings.Contains(out, "Data:") {
		t.Fatalf("doctor output missing sections: %q", out)
	}
}
