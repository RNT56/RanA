package ledger

import (
	"crypto/ed25519"
	"database/sql"
	"fmt"

	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/chain"
)

// FindingKind names a precise, machine-checkable category of tamper or
// incompleteness `Verify` can detect (docs/TRUST.md §6). Kinds are stable
// identifiers other tools (rana-verify-standalone, tests) can match on.
type FindingKind string

// FindingKind constants — one per docs/TRUST.md §6 check, plus the
// completeness/gap-honesty kinds `test/chain-mutations` exercises.
//
// Two kinds intentionally do NOT exist:
//   - A distinct "leaf mismatch": individual leaf hashes are never persisted
//     or compared on their own — they only ever feed the segment's Merkle
//     root, so any single-event tamper surfaces as FindingMerkleMismatch
//     (test/chain-mutations "edit one event byte").
//   - A distinct "whole session deleted": deleting a session wholesale
//     (events, segments, and checkpoints all removed) is caught by
//     FindingCkptChainBroken via the ledger-wide checkpoint chain
//     (verifyLedgerWideCheckpointChain) — the deleted session's checkpoints
//     vanish from the sequence, breaking the hash link between its
//     neighbors (docs/TRUST.md §5, test/chain-mutations "delete a whole
//     session").
const (
	FindingNonCanonical      FindingKind = "non_canonical_encoding"
	FindingMerkleMismatch    FindingKind = "merkle_mismatch"
	FindingChainLinkBroken   FindingKind = "chain_link_broken"
	FindingSignatureInvalid  FindingKind = "signature_invalid"
	FindingCkptChainBroken   FindingKind = "checkpoint_chain_broken"
	FindingCkptHeadMismatch  FindingKind = "checkpoint_head_mismatch"
	FindingRowContinuity     FindingKind = "row_continuity_broken"
	FindingGapDishonest      FindingKind = "gap_dishonest"
	FindingMirrorMismatch    FindingKind = "mirror_mismatch"
	FindingMirrorUncheckable FindingKind = "mirror_uncheckable"
	FindingArchiveMissing    FindingKind = "archive_missing"
	FindingPubkeyUnresolved  FindingKind = "pubkey_unresolved"
)

// Finding is one concrete, precisely-categorized defect (or incompleteness
// note) `Verify` reports.
type Finding struct {
	Kind    FindingKind
	Session string
	Seg     uint64 // 0 if not segment-scoped
	Detail  string
}

// Exit codes, exactly per docs/TRUST.md §6.
const (
	CodeOK         = 0 // chain intact; complete-within-scope or honest gaps
	CodeBroken     = 2 // a leaf/root/link/signature mismatch: tamper detected
	CodeIncomplete = 3 // chain intact but verification incomplete (e.g. missing archive)
)

// UnattestedSegment is a sealed-but-not-yet-checkpointed segment
// (docs/TRUST.md §5): hash-linked, verified for linkage, not yet
// identity-bound by a signature. Reported distinctly from both "verified"
// and "broken" — a normal, expected state for recent data.
type UnattestedSegment struct {
	Session string
	Seg     uint64
}

// Result is the outcome of Verify: an exit Code plus every Finding and
// unattested-tail note accumulated while streaming the ledger.
type Result struct {
	Code     int
	Findings []Finding
	// IncompleteNotes holds findings that indicate verification could not
	// be fully completed (e.g. an archived segment's raw data is absent,
	// or no public key was resolvable to check a checkpoint's signature)
	// WITHOUT any evidence of tampering — these alone drive Code toward 3
	// (INCOMPLETE), never 2 (BROKEN). Kept separate from Findings (which
	// are tamper evidence and always drive Code to 2) so that "we could
	// not check" and "we checked and it's wrong" can never be conflated
	// into the same exit code — see docs/TRUST.md §6 (codes 2 vs 3).
	IncompleteNotes []Finding
	UnattestedTail  []UnattestedSegment
}

// VerifyOptions configures a Verify run.
type VerifyOptions struct {
	// Session restricts verification to one session id; empty means all
	// sessions.
	Session string

	// Mirror, when true, cross-checks every checkpoint against the
	// root-owned heads.log at HeadsLogPath (docs/TRUST.md §6 step 6,
	// plan D27). Requires HeadsLogPath to be set.
	Mirror       bool
	HeadsLogPath string
}

// Verify streams the ledger at dir and confirms, in order, the six checks
// of docs/TRUST.md §6: leaf recomputation, Merkle recomputation, segment
// chain linkage, checkpoint signatures + ledger-wide checkpoint-chain
// continuity, gap honesty, and (opt-in) the root-owned head mirror
// cross-check. It returns a Result whose Code is exactly 0 (intact —
// possibly with honest gaps or an unattested tail), 2 (broken: tamper
// detected), or 3 (incomplete: e.g. an archived segment's data is
// missing).
func Verify(dir Datadir, opts VerifyOptions) (Result, error) {
	db, err := openDB(dir.DBPath)
	if err != nil {
		return Result{}, err
	}
	defer db.Close()

	var res Result

	sessions, err := listSessions(db, opts.Session)
	if err != nil {
		return Result{}, err
	}

	pubkeyFromDir, err := resolveVerifyPubkey(db, dir)
	if err != nil {
		return Result{}, err
	}

	var incomplete bool

	for _, session := range sessions {
		segs, err := readAllSegments(db, session)
		if err != nil {
			return Result{}, err
		}
		cks, err := readCheckpoints(db, session)
		if err != nil {
			return Result{}, err
		}

		findings, incompleteNotes, unattested, sessIncomplete, err := verifySession(db, session, segs, cks, pubkeyFromDir)
		if err != nil {
			return Result{}, err
		}
		res.Findings = append(res.Findings, findings...)
		res.IncompleteNotes = append(res.IncompleteNotes, incompleteNotes...)
		res.UnattestedTail = append(res.UnattestedTail, unattested...)
		if sessIncomplete {
			incomplete = true
		}
	}

	// Ledger-wide checkpoint chain continuity (docs/TRUST.md §5: spans
	// sessions, not just within one) — only meaningful when verifying the
	// whole ledger.
	if opts.Session == "" {
		findings, err := verifyLedgerWideCheckpointChain(db)
		if err != nil {
			return Result{}, err
		}
		res.Findings = append(res.Findings, findings...)
	}

	if opts.Mirror {
		findings, incNotes, err := verifyMirror(db, opts.HeadsLogPath)
		if err != nil {
			return Result{}, err
		}
		res.Findings = append(res.Findings, findings...)
		if len(incNotes) > 0 {
			res.IncompleteNotes = append(res.IncompleteNotes, incNotes...)
			incomplete = true
		}
	}

	switch {
	case len(res.Findings) > 0:
		res.Code = CodeBroken
	case incomplete:
		res.Code = CodeIncomplete
	default:
		res.Code = CodeOK
	}
	return res, nil
}

func listSessions(db *sql.DB, only string) ([]string, error) {
	var rows *sql.Rows
	var err error
	if only != "" {
		rows, err = db.Query(`SELECT id FROM sessions WHERE id = ?`, only)
	} else {
		rows, err = db.Query(`SELECT id FROM sessions ORDER BY started_ns ASC`)
	}
	if err != nil {
		return nil, fmt.Errorf("ledger: listing sessions: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("ledger: scanning session id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// resolveVerifyPubkey returns the public key to check checkpoint
// signatures against, preferring the ledger's own meta table (written by
// the Writer at startup — a read-only path like Verify has no reason to
// ever load device.key's PRIVATE key material) and falling back to
// reading device.key's public half directly only for a ledger that
// predates meta population (e.g. one whose Writer never ran past
// construction in a test, or an older on-disk format). A
// passphrase-wrapped key with no passphrase available degrades to "no
// pubkey known" (signature checks are then skipped, matching Verify's
// existing best-effort-degradation contract) rather than erroring the
// whole run.
func resolveVerifyPubkey(db *sql.DB, dir Datadir) (ed25519.PublicKey, error) {
	pub, _, err := loadMetaPubkey(db)
	if err != nil {
		return nil, err
	}
	if pub != nil {
		return pub, nil
	}
	ki, err := chain.LoadKey(dir.Root, "")
	if err != nil {
		return nil, nil // best-effort: no key file, or wrapped — signature checks degrade gracefully below
	}
	return ki.PublicKey, nil
}

func readAllSegments(db *sql.DB, session string) ([]segmentRow, error) {
	return readSegments(db, session)
}

// verifySession runs checks 1-3 and 5 (leaf, merkle, chain-link, gap
// honesty) for one session's segments, and check 4 (signature) for its
// checkpoints. It returns findings (tamper evidence, drives BROKEN),
// incompleteness notes (no tamper evidence, drives INCOMPLETE — e.g. a
// missing archive or an unresolvable pubkey), the unattested tail, and
// whether any referenced archive was missing.
func verifySession(db *sql.DB, session string, segs []segmentRow, cks []checkpointRow, pub ed25519.PublicKey) (findings []Finding, incompleteNotes []Finding, unattested []UnattestedSegment, incomplete bool, err error) {
	var prevHash [32]byte // genesis

	lastCheckpointedSeg := int64(-1)
	for _, ck := range cks {
		if int64(ck.SegLast) > lastCheckpointedSeg {
			lastCheckpointedSeg = int64(ck.SegLast)
		}
	}

	for _, sr := range segs {
		if sr.ArchivedPath.Valid {
			// Cold-archived segment (docs/TRUST.md §9, GC): the header,
			// hashes, and chain linkage still live in `segments` and are
			// fully re-checked here — GC never touches them, only the hot
			// `events` copy of the raw bytes. Re-verifying the leaves
			// against the merkle_root would require the archive's
			// contents, which live outside the hot path by design; a live
			// verify therefore reports this range as INCOMPLETE (3), never
			// a false BROKEN (2) — the chain is not known-tampered, just
			// not fully re-checked without fetching the archive.
			expectHash, _, hErr := chain.SegHash(chain.SegHeader{
				SessionID: sr.Session, SegIndex: sr.Seg, FirstRowID: sr.FirstRowID,
				LastRowID: sr.LastRowID, EventCount: sr.EventCount, MerkleRoot: sr.MerkleRoot,
				PrevSegHash: sr.PrevSegHash, GapSummary: sr.GapSummary, SealedAtWall: sr.SealedNs,
			})
			if hErr != nil {
				return nil, nil, nil, false, hErr
			}
			if expectHash != sr.SegHash {
				findings = append(findings, Finding{Kind: FindingChainLinkBroken, Session: session, Seg: sr.Seg, Detail: "archived segment header hash mismatch"})
			}
			if sr.PrevSegHash != prevHash {
				findings = append(findings, Finding{Kind: FindingChainLinkBroken, Session: session, Seg: sr.Seg, Detail: "prev_seg_hash does not match previous segment"})
			}
			prevHash = sr.SegHash
			incomplete = true
			continue
		}

		evs, err := readSegmentEvents(db, session, sr.FirstRowID, sr.LastRowID)
		if err != nil {
			return nil, nil, nil, false, err
		}

		// Row continuity (check 5, gap honesty half 1): the segment's
		// first/last rowid bounds must match what's actually stored, and
		// the event count must match too, UNLESS a recorded gap explains
		// the discrepancy. We check the simple case here: no gap claimed
		// but rows missing => dishonest; rows present count must equal
		// EventCount when no gap is claimed for this segment.
		if len(evs) != int(sr.EventCount) {
			hasGap := len(sr.GapSummary) > 0
			if !hasGap {
				findings = append(findings, Finding{Kind: FindingRowContinuity, Session: session, Seg: sr.Seg,
					Detail: fmt.Sprintf("expected %d events, found %d, no gap recorded", sr.EventCount, len(evs))})
			}
		}

		// Gap honesty (check 5, half 2): the header's gap_summary is a
		// counts-by-reason tally of the `gap` events actually present in the
		// segment. It is part of the hashed header (seg_hash), so on a
		// SIGNED segment the checkpoint signature already protects it — but
		// the UNATTESTED TAIL (segments sealed since the last checkpoint) is
		// not yet signed, so a raw-sqlite attacker with no device key could
		// otherwise zero a segment's gap_summary and recompute a
		// self-consistent seg_hash, silently suppressing a recorded loss
		// (violating P5). Cross-checking the header tally against the gap
		// events decoded from the segment's own merkle-protected bytes makes
		// that inconsistency loud: a header claiming fewer (or different)
		// gaps than its events contain is tamper, on every segment, tail or
		// not.
		gotGaps, gErr := gapCountsFromEvents(evs)
		if gErr != nil {
			findings = append(findings, Finding{Kind: FindingNonCanonical, Session: session, Seg: sr.Seg, Detail: "gap event failed to decode for gap-summary cross-check"})
		} else if !gapCountsEqual(gotGaps, sr.GapSummary) {
			findings = append(findings, Finding{Kind: FindingGapDishonest, Session: session, Seg: sr.Seg,
				Detail: fmt.Sprintf("header gap_summary %v does not match the %d gap event(s) in the segment (%v)", sr.GapSummary, gapTotal(gotGaps), gotGaps)})
		}

		leaves := make([][32]byte, 0, len(evs))
		for _, encBytes := range evs {
			ok, err := cborcanon.IsCanonical(encBytes)
			if err != nil || !ok {
				findings = append(findings, Finding{Kind: FindingNonCanonical, Session: session, Seg: sr.Seg, Detail: "stored event bytes are not canonical CBOR"})
				continue
			}
			leaves = append(leaves, chain.Leaf(encBytes))
		}

		root := chain.MerkleRoot(leaves)
		if root != sr.MerkleRoot {
			findings = append(findings, Finding{Kind: FindingMerkleMismatch, Session: session, Seg: sr.Seg, Detail: "recomputed merkle root does not match stored merkle_root"})
		}

		expectHash, _, hErr := chain.SegHash(chain.SegHeader{
			SessionID: session, SegIndex: sr.Seg, FirstRowID: sr.FirstRowID, LastRowID: sr.LastRowID,
			EventCount: sr.EventCount, MerkleRoot: sr.MerkleRoot, PrevSegHash: sr.PrevSegHash,
			GapSummary: sr.GapSummary, SealedAtWall: sr.SealedNs,
		})
		if hErr != nil {
			return nil, nil, nil, false, hErr
		}
		if expectHash != sr.SegHash {
			findings = append(findings, Finding{Kind: FindingChainLinkBroken, Session: session, Seg: sr.Seg, Detail: "stored seg_hash does not match recomputed header hash"})
		}
		if sr.PrevSegHash != prevHash {
			findings = append(findings, Finding{Kind: FindingChainLinkBroken, Session: session, Seg: sr.Seg, Detail: "prev_seg_hash does not chain from previous segment"})
		}
		prevHash = sr.SegHash

		if int64(sr.Seg) > lastCheckpointedSeg {
			unattested = append(unattested, UnattestedSegment{Session: session, Seg: sr.Seg})
		}
	}

	// Checkpoint signatures (check 4, session-local half). A checkpoint's
	// signature MUST be checked whenever one exists to check it against:
	// if no pubkey could be resolved (meta rows and device.key both gone —
	// whether from attacker tampering or operator key loss), that is
	// itself a reportable incompleteness (docs/TRUST.md §6 step 4 is an
	// unconditional check, not a best-effort one) — never a silent
	// downgrade to CodeOK, which would make deleting the means to check a
	// signature cheaper than defeating the signature itself.
	if pub == nil && len(cks) > 0 {
		incompleteNotes = append(incompleteNotes, Finding{Kind: FindingPubkeyUnresolved, Session: session,
			Detail: "session has signed checkpoints but no public key could be resolved (meta pubkey rows and device.key both unavailable); signatures were NOT checked"})
		incomplete = true
	}
	for _, ck := range cks {
		if pub != nil {
			if err := chain.VerifyCheckpoint(pub, ck.Body, ck.Sig); err != nil {
				findings = append(findings, Finding{Kind: FindingSignatureInvalid, Session: session, Detail: err.Error()})
				continue
			}
		}
		// chain_head must match the recomputed hash of the last segment in
		// range.
		var lastSegHash [32]byte
		found := false
		for _, sr := range segs {
			if sr.Seg == ck.SegLast {
				lastSegHash = sr.SegHash
				found = true
				break
			}
		}
		if !found {
			findings = append(findings, Finding{Kind: FindingArchiveMissing, Session: session, Seg: ck.SegLast, Detail: "checkpoint references a segment not present in the ledger"})
			incomplete = true
			continue
		}
		if lastSegHash != ck.ChainHead {
			findings = append(findings, Finding{Kind: FindingCkptHeadMismatch, Session: session, Seg: ck.SegLast, Detail: "checkpoint chain_head does not match recomputed seg_hash of the last segment in range"})
		}
	}

	return findings, incompleteNotes, unattested, incomplete, nil
}

// readSegmentEvents returns the canonical CBOR bytes of every event row in
// [firstRowID, lastRowID] (a sealed segment's authoritative membership
// range per its header, docs/TRUST.md §4), in rowid order.
func readSegmentEvents(db *sql.DB, session string, firstRowID, lastRowID int64) ([][]byte, error) {
	rows, err := db.Query(`SELECT bytes FROM events WHERE session = ? AND rowid >= ? AND rowid <= ? ORDER BY rowid ASC`, session, firstRowID, lastRowID)
	if err != nil {
		return nil, fmt.Errorf("ledger: querying segment events: %w", err)
	}
	defer rows.Close()

	var out [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, fmt.Errorf("ledger: scanning event bytes: %w", err)
		}
		if b == nil {
			continue // GC'd (archived) row: bytes nulled out by design
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// verifyLedgerWideCheckpointChain confirms prev_checkpoint_hash continuity
// across the WHOLE ledger (docs/TRUST.md §5), in checkpoint-id order —
// this is what catches whole-session deletion (plan D12): a deleted
// session's checkpoints vanish from the sequence, breaking the hash link
// between its neighbors.
func verifyLedgerWideCheckpointChain(db *sql.DB) ([]Finding, error) {
	rows, err := db.Query(`SELECT session, seg_last, prev_hash, body FROM checkpoints ORDER BY cid ASC`)
	if err != nil {
		return nil, fmt.Errorf("ledger: querying ledger-wide checkpoints: %w", err)
	}
	defer rows.Close()

	var findings []Finding
	var prevHash [32]byte
	for rows.Next() {
		var session string
		var segLast uint64
		var storedPrev, body []byte
		if err := rows.Scan(&session, &segLast, &storedPrev, &body); err != nil {
			return nil, fmt.Errorf("ledger: scanning checkpoint: %w", err)
		}
		var got [32]byte
		copy(got[:], storedPrev)
		if got != prevHash {
			findings = append(findings, Finding{Kind: FindingCkptChainBroken, Session: session, Seg: segLast,
				Detail: "checkpoint prev_checkpoint_hash does not chain from the previous checkpoint in the ledger"})
		}
		prevHash = chain.CheckpointHash(body)
	}
	return findings, rows.Err()
}

// verifyMirror cross-checks every checkpoint in the ledger against the
// root-owned heads.log at headsPath (docs/TRUST.md §6 step 6, plan D27).
// A checkpoint whose (session, seg_last, chain_head) has no matching
// mirrored HeadReport is reported as a possible post-mirror rewrite —
// this is the ONLY check in the suite that can catch a rewrite-and-
// re-sign performed with the legitimately-stolen device key.
func verifyMirror(db *sql.DB, headsPath string) (findings []Finding, incompleteNotes []Finding, err error) {
	heads, err := chain.ReadHeads(headsPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ledger: reading heads mirror: %w", err)
	}
	mirrored := make(map[string]chain.HeadReport, len(heads))
	for _, h := range heads {
		mirrored[mirrorKey(h.SessionID, h.SegLast)] = h
	}

	rows, err := db.Query(`SELECT session, seg_last, chain_head, body FROM checkpoints ORDER BY cid ASC`)
	if err != nil {
		return nil, nil, fmt.Errorf("ledger: querying checkpoints for mirror check: %w", err)
	}
	defer rows.Close()

	var checkpointCount, matchedCount int
	for rows.Next() {
		checkpointCount++
		var session string
		var segLast uint64
		var chainHeadBytes, body []byte
		if err := rows.Scan(&session, &segLast, &chainHeadBytes, &body); err != nil {
			return nil, nil, fmt.Errorf("ledger: scanning checkpoint for mirror check: %w", err)
		}
		h, ok := mirrored[mirrorKey(session, segLast)]
		if !ok {
			// Not every checkpoint is necessarily mirrored (e.g. ranad was
			// offline); absence alone is not proof of tampering, only a
			// gap in mirror coverage. We only flag an explicit MISMATCH
			// below when a mirrored entry exists and disagrees.
			continue
		}
		matchedCount++
		var chainHead [32]byte
		copy(chainHead[:], chainHeadBytes)
		ckptHash := chain.CheckpointHash(body)
		if h.ChainHead != chainHead || h.CkptHash != ckptHash {
			findings = append(findings, Finding{Kind: FindingMirrorMismatch, Session: session, Seg: segLast,
				Detail: "checkpoint does not match the root-owned heads mirror recorded before any compromise"})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	// P5/P10 honesty: --mirror was explicitly requested, but if not a single
	// checkpoint could be cross-checked against a mirrored head (the mirror at
	// headsPath is absent or empty), the check did not actually run. Reporting
	// OK here would let a user conflate "mirror checked, clean" with "mirror
	// never ran" — exactly the ambiguity a security tool must not have. Surface
	// it as INCOMPLETE (code 3), never a silent success.
	if checkpointCount > 0 && matchedCount == 0 {
		incompleteNotes = append(incompleteNotes, Finding{Kind: FindingMirrorUncheckable,
			Detail: fmt.Sprintf("mirror cross-check requested but no checkpoint matched any entry in the heads mirror at %s (absent or empty); the check could not be performed", headsPath)})
	}
	return findings, incompleteNotes, nil
}

func mirrorKey(session string, segLast uint64) string {
	return fmt.Sprintf("%s#%d", session, segLast)
}
