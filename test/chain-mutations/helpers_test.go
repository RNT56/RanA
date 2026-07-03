// Package chainmutations is RanA's permanent tamper-detection regression
// gate (CLAUDE.md §3.1, CONTRACTS §internal/ledger, gate G5): it builds a
// clean, multi-segment, multi-checkpoint ledger, applies one programmatic
// mutation at a time directly against the underlying SQLite file (the way
// an attacker with filesystem access would), and asserts ledger.Verify
// catches every single one with a precise Finding kind — or, for the two
// mutations docs/TRUST.md predicts verify canNOT catch alone (truncating
// the honest unattested tail; a rewrite-and-re-sign performed with the
// legitimate, stolen device key), asserts the documented distinct
// behavior (code 0 with an unattested-tail note; caught only by
// --mirror).
package chainmutations

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// buildLedger writes a clean, verifiable multi-segment, multi-checkpoint,
// two-session ledger and returns its Datadir plus the signing key used.
// Segment/checkpoint thresholds are set low so a modest number of events
// produces several sealed segments and more than one checkpoint,
// exercising both intra-session and ledger-wide chain linkage.
func buildLedger(t *testing.T) (ledger.Datadir, chain.KeyInfo) {
	t.Helper()
	root := t.TempDir()
	d := ledger.Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	key, err := chain.GenerateKey(root)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	w, err := ledger.NewWriter(d, ledger.WriterOptions{
		SegSealMaxEvents:  4,
		CheckpointMaxSegs: 2,
		Key:               key,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	sessionA := schema.NewSessionID(fixedClock{ms: 1000})
	sessionB := schema.NewSessionID(fixedClock{ms: 2000})

	writeExecs(t, w, sessionA, 20)
	if err := w.SealSession(sessionA); err != nil {
		t.Fatalf("SealSession A: %v", err)
	}
	writeExecs(t, w, sessionB, 12)
	if err := w.SealSession(sessionB); err != nil {
		t.Fatalf("SealSession B: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return d, key
}

type fixedClock struct{ ms int64 }

func (f fixedClock) Now() int64 { return f.ms }

func writeExecs(t *testing.T, w *ledger.Writer, session string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		ev := schema.NewProcExec(session, 0, uint64(i), uint64(i)*1000, uint64(i)*1000, 100,
			[]redact.Redacted{redact.Literal("/bin/true")},
			redact.Literal("true"), redact.Literal("/root"), redact.Literal("/bin/true"),
			1, 0)
		if err := w.Append(ev); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("FlushForTest: %v", err)
	}
}

// openRawDB opens the ledger's sqlite file directly, exactly as an
// attacker with filesystem access (or a mutation test) would, bypassing
// every in-process invariant the Writer/Verify machinery normally
// enforces.
func openRawDB(t *testing.T, d ledger.Datadir) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", d.DBPath)
	if err != nil {
		t.Fatalf("opening raw db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// mustExec runs a raw SQL statement against the ledger file and fails the
// test on error.
func mustExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

// mustEncode canonically encodes ev (internal/cborcanon.EncodeEvent),
// failing the test on error.
func mustEncode(t *testing.T, ev schema.Event) []byte {
	t.Helper()
	b, err := cborcanon.EncodeEvent(ev)
	if err != nil {
		t.Fatalf("EncodeEvent: %v", err)
	}
	return b
}

// findingKinds extracts the set of Finding.Kind values present in res.
func findingKinds(res ledger.Result) map[ledger.FindingKind]bool {
	out := make(map[ledger.FindingKind]bool)
	for _, f := range res.Findings {
		out[f.Kind] = true
	}
	return out
}
