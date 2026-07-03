package ledger

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/klauspost/compress/zstd"
)

// GC compacts sealed segments older than ttl (measured from each
// segment's SealedAtWall against the current wall clock) into zstd cold
// archives under dir.ArchiveDir, nulls out their event rows' bytes column
// in the hot `events` table, and records the archive's path on the
// segment row (docs/TRUST.md §9, CONTRACTS §internal/ledger). Chain
// continuity is preserved — the segment's header, hashes, and gap summary
// remain in `segments` untouched, so `verify` over live data still
// returns 0, and `verify` that needs an archived range's raw event bytes
// (currently: none of the six docs/TRUST.md §6 checks need the raw bytes
// once a segment is sealed and its merkle_root trusted, EXCEPT the
// standalone-verifier-equivalent leaf recomputation, which is why an
// archived segment is reported as an unattested-tail-shaped INCOMPLETE,
// never a false BROKEN) returns 3.
//
// GC returns the number of segments archived. A ttl of 0 makes every
// currently-sealed segment eligible (useful for tests and an explicit
// "archive everything now" operator action).
func GC(dir Datadir, ttl time.Duration) (int, error) {
	return GCAt(dir, ttl, uint64(time.Now().UnixNano()))
}

// GCAt is GC with an explicit "now" (nanoseconds since Unix epoch)
// instead of the real wall clock, so ttl-boundary behavior is
// deterministically testable against a ledger built with a fakeClock
// (CONTRACTS testing bar: injectable clocks everywhere time matters).
func GCAt(dir Datadir, ttl time.Duration, nowNs uint64) (int, error) {
	if err := dir.Ensure(); err != nil {
		return 0, err
	}
	db, err := openDB(dir.DBPath)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	// Bind as int64: the sqlite driver rejects uint64 query args outright
	// (modernc.org/sqlite has no lossless uint64 binding), and sqlite
	// itself stores INTEGER columns as signed 64-bit regardless — every
	// nanosecond timestamp this package produces comfortably fits well
	// under 1<<63 until the year 2262, so this is a safe, permanent cast,
	// not a truncation risk.
	cutoff := int64(time.Unix(0, int64(nowNs)).Add(-ttl).UnixNano())

	rows, err := db.Query(`SELECT session, seg, first_rowid, last_rowid, sealed_ns FROM segments WHERE archived_path IS NULL AND sealed_ns <= ? ORDER BY session, seg`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("ledger: querying GC-eligible segments: %w", err)
	}
	type target struct {
		session               string
		seg                   uint64
		firstRowID, lastRowID int64
	}
	var targets []target
	for rows.Next() {
		var tgt target
		var sealedNs uint64
		if err := rows.Scan(&tgt.session, &tgt.seg, &tgt.firstRowID, &tgt.lastRowID, &sealedNs); err != nil {
			rows.Close()
			return 0, fmt.Errorf("ledger: scanning GC-eligible segment: %w", err)
		}
		targets = append(targets, tgt)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	rows.Close()

	archived := 0
	for _, tgt := range targets {
		archivePath, err := archiveSegment(db, dir, tgt.session, tgt.seg, tgt.firstRowID, tgt.lastRowID)
		if err != nil {
			return archived, fmt.Errorf("ledger: archiving %s seg %d: %w", tgt.session, tgt.seg, err)
		}

		tx, err := db.Begin()
		if err != nil {
			return archived, fmt.Errorf("ledger: beginning GC transaction: %w", err)
		}
		if _, err := tx.Exec(`UPDATE events SET bytes = NULL WHERE session = ? AND rowid >= ? AND rowid <= ?`, tgt.session, tgt.firstRowID, tgt.lastRowID); err != nil {
			tx.Rollback()
			return archived, fmt.Errorf("ledger: nulling archived event bytes: %w", err)
		}
		if _, err := tx.Exec(`UPDATE segments SET archived_path = ? WHERE session = ? AND seg = ?`, archivePath, tgt.session, int64(tgt.seg)); err != nil {
			tx.Rollback()
			return archived, fmt.Errorf("ledger: recording archived_path: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return archived, fmt.Errorf("ledger: committing GC transaction: %w", err)
		}
		archived++
	}

	return archived, nil
}

// archiveSegment zstd-compresses the ordered concatenation of a segment's
// canonical event byte records (each uvarint-length-prefixed, the same
// framing as Export's .cbor artifacts) to a file under dir.ArchiveDir, and
// returns its path. The archive is written and fsynced before the caller
// nulls the hot copy, so a crash between archiving and the DB update
// leaves the hot data intact (safe to retry) rather than losing it.
func archiveSegment(db *sql.DB, dir Datadir, session string, seg uint64, firstRowID, lastRowID int64) (string, error) {
	evs, err := readSegmentEvents(db, session, firstRowID, lastRowID)
	if err != nil {
		return "", err
	}

	var plain bytes.Buffer
	for _, e := range evs {
		writeUvarintPrefixed(&plain, e)
	}

	enc, err := zstd.NewWriter(nil)
	if err != nil {
		return "", fmt.Errorf("ledger: constructing zstd encoder: %w", err)
	}
	compressed := enc.EncodeAll(plain.Bytes(), nil)
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("ledger: closing zstd encoder: %w", err)
	}

	name := fmt.Sprintf("%s-seg%06d.cbor.zst", session, seg)
	path := filepath.Join(dir.ArchiveDir, name)

	f, err := os.CreateTemp(dir.ArchiveDir, ".archive.tmp-*")
	if err != nil {
		return "", fmt.Errorf("ledger: creating archive temp file: %w", err)
	}
	tmpPath := f.Name()
	if _, err := f.Write(compressed); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("ledger: writing archive: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("ledger: fsyncing archive: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("ledger: closing archive temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("ledger: renaming archive into place: %w", err)
	}

	return path, nil
}
