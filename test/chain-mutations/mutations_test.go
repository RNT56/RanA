package chainmutations

import (
	"database/sql"
	"testing"

	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/ledger"
)

// TestChainMutations is gate G5: every programmatic mutation in the table
// must be detected by ledger.Verify with the precise Finding kind
// documented, OR (for the two mutations docs/TRUST.md predicts a plain
// Verify cannot catch) the specific alternate, still-honest behavior must
// hold. Table-driven per CONTRACTS §internal/ledger.
func TestChainMutations(t *testing.T) {
	type tc struct {
		name string
		// mutate applies the tamper directly against the raw sqlite file.
		// It also returns the session id the mutation targeted, if any
		// finding assertions need it (empty string = not session-scoped).
		mutate func(t *testing.T, db *sql.DB, sessionA, sessionB string)
		// wantCode is the expected ledger.Verify exit code after mutate.
		wantCode int
		// wantKind is the Finding kind that must appear at least once (for
		// wantCode == CodeBroken or CodeIncomplete). Ignored when empty.
		wantKind ledger.FindingKind
		// requireMirror, if true, means Verify WITHOUT --mirror must
		// return CodeOK (the mutation is undetectable by plain verify —
		// by design, docs/TRUST.md §6 step 6 / LIMITS.md §6.1), while
		// Verify WITH --mirror against the pre-compromise heads log must
		// return CodeBroken with wantKind.
		requireMirror bool
	}

	// sessionA/sessionB are re-derived per subtest from a freshly built
	// ledger (mutations must not leak between table entries).
	tcs := []tc{
		{
			name: "edit one event byte",
			mutate: func(t *testing.T, db *sql.DB, sessionA, _ string) {
				var rowid int64
				var b []byte
				row := db.QueryRow(`SELECT rowid, bytes FROM events WHERE session = ? ORDER BY rowid ASC LIMIT 1`, sessionA)
				if err := row.Scan(&rowid, &b); err != nil {
					t.Fatalf("selecting event: %v", err)
				}
				mutated := append([]byte(nil), b...)
				mutated[len(mutated)-1] ^= 0x01
				mustExec(t, db, `UPDATE events SET bytes = ? WHERE rowid = ?`, mutated, rowid)
			},
			wantCode: ledger.CodeBroken,
			wantKind: ledger.FindingMerkleMismatch,
		},
		{
			name: "delete an event row",
			mutate: func(t *testing.T, db *sql.DB, sessionA, _ string) {
				var rowid int64
				row := db.QueryRow(`SELECT rowid FROM events WHERE session = ? ORDER BY rowid ASC LIMIT 1`, sessionA)
				if err := row.Scan(&rowid); err != nil {
					t.Fatalf("selecting event: %v", err)
				}
				mustExec(t, db, `DELETE FROM events WHERE rowid = ?`, rowid)
			},
			wantCode: ledger.CodeBroken,
			wantKind: ledger.FindingRowContinuity,
		},
		{
			name: "reorder two rows (swap ts/type/pid/bytes content between two rowids)",
			mutate: func(t *testing.T, db *sql.DB, sessionA, _ string) {
				rows, err := db.Query(`SELECT rowid, bytes FROM events WHERE session = ? ORDER BY rowid ASC LIMIT 2`, sessionA)
				if err != nil {
					t.Fatalf("selecting events: %v", err)
				}
				var rowids []int64
				var payloads [][]byte
				for rows.Next() {
					var id int64
					var b []byte
					if err := rows.Scan(&id, &b); err != nil {
						t.Fatalf("scanning: %v", err)
					}
					rowids = append(rowids, id)
					payloads = append(payloads, b)
				}
				rows.Close()
				if len(rowids) != 2 {
					t.Fatalf("expected 2 rows, got %d", len(rowids))
				}
				// Swap the canonical bytes between the two rowids: the
				// leaf sequence that fed the segment's merkle root is now
				// out of order relative to what was actually hashed at
				// seal time.
				mustExec(t, db, `UPDATE events SET bytes = ? WHERE rowid = ?`, payloads[1], rowids[0])
				mustExec(t, db, `UPDATE events SET bytes = ? WHERE rowid = ?`, payloads[0], rowids[1])
			},
			wantCode: ledger.CodeBroken,
			wantKind: ledger.FindingMerkleMismatch,
		},
		{
			name: "delete a whole segment",
			mutate: func(t *testing.T, db *sql.DB, sessionA, _ string) {
				var seg uint64
				row := db.QueryRow(`SELECT seg FROM segments WHERE session = ? ORDER BY seg ASC LIMIT 1`, sessionA)
				if err := row.Scan(&seg); err != nil {
					t.Fatalf("selecting segment: %v", err)
				}
				mustExec(t, db, `DELETE FROM segments WHERE session = ? AND seg = ?`, sessionA, seg)
			},
			wantCode: ledger.CodeBroken,
			wantKind: ledger.FindingChainLinkBroken,
		},
		{
			name: "delete a whole session",
			mutate: func(t *testing.T, db *sql.DB, sessionA, _ string) {
				mustExec(t, db, `DELETE FROM events WHERE session = ?`, sessionA)
				mustExec(t, db, `DELETE FROM segments WHERE session = ?`, sessionA)
				mustExec(t, db, `DELETE FROM checkpoints WHERE session = ?`, sessionA)
				mustExec(t, db, `DELETE FROM sessions WHERE id = ?`, sessionA)
			},
			wantCode: ledger.CodeBroken,
			wantKind: ledger.FindingCkptChainBroken,
		},
		{
			name: "re-sign with a fresh (different) key",
			mutate: func(t *testing.T, db *sql.DB, sessionA, _ string) {
				freshKey, err := chain.GenerateKey(t.TempDir())
				if err != nil {
					t.Fatalf("GenerateKey: %v", err)
				}
				rows, err := db.Query(`SELECT cid, session, seg_first, seg_last, chain_head, prev_hash, signed_ns FROM checkpoints WHERE session = ?`, sessionA)
				if err != nil {
					t.Fatalf("selecting checkpoints: %v", err)
				}
				type ckpt struct {
					cid                 int64
					session             string
					segFirst, segLast   uint64
					chainHead, prevHash []byte
					signedNs            uint64
				}
				var list []ckpt
				for rows.Next() {
					var c ckpt
					if err := rows.Scan(&c.cid, &c.session, &c.segFirst, &c.segLast, &c.chainHead, &c.prevHash, &c.signedNs); err != nil {
						t.Fatalf("scanning checkpoint: %v", err)
					}
					list = append(list, c)
				}
				rows.Close()
				for _, c := range list {
					var chainHead, prevHash [32]byte
					copy(chainHead[:], c.chainHead)
					copy(prevHash[:], c.prevHash)
					body, sig, err := chain.SignCheckpoint(freshKey.PrivateKey, chain.Checkpoint{
						SessionID: c.session, SegFirst: c.segFirst, SegLast: c.segLast,
						ChainHead: chainHead, PrevCheckpointHash: prevHash,
						SignedAtWall: c.signedNs, PubkeyID: freshKey.PubkeyID,
					})
					if err != nil {
						t.Fatalf("SignCheckpoint: %v", err)
					}
					mustExec(t, db, `UPDATE checkpoints SET body = ?, sig = ?, pubkey_id = ? WHERE cid = ?`, body, sig, freshKey.PubkeyID, c.cid)
				}
			},
			wantCode: ledger.CodeBroken,
			wantKind: ledger.FindingSignatureInvalid,
		},
		{
			name: "truncate the unattested tail",
			mutate: func(t *testing.T, db *sql.DB, sessionA, _ string) {
				// Delete only segments/events STRICTLY AFTER the last
				// checkpointed segment for sessionA — this is deleting
				// data that was never attested, which docs/TRUST.md §5
				// says is a normal, honest state to observe (not tamper).
				var lastCkptSeg uint64
				row := db.QueryRow(`SELECT MAX(seg_last) FROM checkpoints WHERE session = ?`, sessionA)
				if err := row.Scan(&lastCkptSeg); err != nil {
					t.Fatalf("selecting last checkpointed seg: %v", err)
				}
				rows, err := db.Query(`SELECT seg, first_rowid, last_rowid FROM segments WHERE session = ? AND seg > ?`, sessionA, lastCkptSeg)
				if err != nil {
					t.Fatalf("selecting unattested segments: %v", err)
				}
				var segs []uint64
				for rows.Next() {
					var seg uint64
					var first, last int64
					if err := rows.Scan(&seg, &first, &last); err != nil {
						t.Fatalf("scanning: %v", err)
					}
					segs = append(segs, seg)
					mustExec(t, db, `DELETE FROM events WHERE session = ? AND rowid >= ? AND rowid <= ?`, sessionA, first, last)
				}
				rows.Close()
				if len(segs) == 0 {
					t.Fatalf("fixture has no unattested tail segment to truncate for %s", sessionA)
				}
				for _, seg := range segs {
					mustExec(t, db, `DELETE FROM segments WHERE session = ? AND seg = ?`, sessionA, seg)
				}
			},
			wantCode: ledger.CodeOK,
		},
		{
			name: "delete a signed checkpoint's segment",
			mutate: func(t *testing.T, db *sql.DB, sessionA, _ string) {
				var seg uint64
				row := db.QueryRow(`SELECT seg_last FROM checkpoints WHERE session = ? ORDER BY cid ASC LIMIT 1`, sessionA)
				if err := row.Scan(&seg); err != nil {
					t.Fatalf("selecting checkpointed seg: %v", err)
				}
				mustExec(t, db, `DELETE FROM segments WHERE session = ? AND seg = ?`, sessionA, seg)
			},
			wantCode: ledger.CodeBroken,
			wantKind: ledger.FindingArchiveMissing,
		},
	}

	for _, c := range tcs {
		t.Run(c.name, func(t *testing.T) {
			d, _ := buildLedger(t)
			sessionA, sessionB := twoSessionIDs(t, d)

			db := openRawDB(t, d)
			c.mutate(t, db, sessionA, sessionB)
			db.Close()

			res, err := ledger.Verify(d, ledger.VerifyOptions{})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if res.Code != c.wantCode {
				t.Fatalf("Code = %d, want %d; findings=%+v", res.Code, c.wantCode, res.Findings)
			}
			if c.wantKind != "" {
				kinds := findingKinds(res)
				if !kinds[c.wantKind] {
					t.Fatalf("expected finding kind %q, got findings=%+v", c.wantKind, res.Findings)
				}
			}
		})
	}
}

// twoSessionIDs reads back the two session ids present in a freshly built
// fixture ledger, in creation order.
func twoSessionIDs(t *testing.T, d ledger.Datadir) (a, b string) {
	t.Helper()
	db := openRawDB(t, d)
	defer db.Close()
	rows, err := db.Query(`SELECT id FROM sessions ORDER BY started_ns ASC, id ASC`)
	if err != nil {
		t.Fatalf("querying sessions: %v", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scanning session id: %v", err)
		}
		ids = append(ids, id)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 sessions in fixture, got %d", len(ids))
	}
	return ids[0], ids[1]
}
