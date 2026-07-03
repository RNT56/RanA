package ledger

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// segmentRow is a sealed segment as read back from the segments table, for
// test assertions.
type segmentRow struct {
	Session      string
	Seg          uint64
	FirstRowID   int64
	LastRowID    int64
	EventCount   uint64
	MerkleRoot   [32]byte
	PrevSegHash  [32]byte
	SegHash      [32]byte
	GapSummary   map[string]uint64
	SealedNs     uint64
	Header       []byte
	ArchivedPath sql.NullString
}

func readSegments(db *sql.DB, session string) ([]segmentRow, error) {
	rows, err := db.Query(`SELECT session, seg, first_rowid, last_rowid, event_count, merkle_root, prev_seg_hash, seg_hash, gap, sealed_ns, header, archived_path
		FROM segments WHERE session = ? ORDER BY seg ASC`, session)
	if err != nil {
		return nil, fmt.Errorf("ledger: querying segments: %w", err)
	}
	defer rows.Close()

	var out []segmentRow
	for rows.Next() {
		var sr segmentRow
		var merkle, prevHash, segHash, gapBlob []byte
		if err := rows.Scan(&sr.Session, &sr.Seg, &sr.FirstRowID, &sr.LastRowID, &sr.EventCount,
			&merkle, &prevHash, &segHash, &gapBlob, &sr.SealedNs, &sr.Header, &sr.ArchivedPath); err != nil {
			return nil, fmt.Errorf("ledger: scanning segment: %w", err)
		}
		copy(sr.MerkleRoot[:], merkle)
		copy(sr.PrevSegHash[:], prevHash)
		copy(sr.SegHash[:], segHash)
		if len(gapBlob) > 0 {
			if err := json.Unmarshal(gapBlob, &sr.GapSummary); err != nil {
				return nil, fmt.Errorf("ledger: unmarshaling gap summary: %w", err)
			}
		} else {
			sr.GapSummary = map[string]uint64{}
		}
		out = append(out, sr)
	}
	return out, rows.Err()
}

// checkpointRow is a checkpoint as read back from the checkpoints table,
// for test assertions.
type checkpointRow struct {
	CID       int64
	Session   string
	SegFirst  uint64
	SegLast   uint64
	ChainHead [32]byte
	PrevHash  [32]byte
	Body      []byte
	Sig       []byte
	PubkeyID  string
	SignedNs  uint64
}

func readCheckpoints(db *sql.DB, session string) ([]checkpointRow, error) {
	rows, err := db.Query(`SELECT cid, session, seg_first, seg_last, chain_head, prev_hash, body, sig, pubkey_id, signed_ns
		FROM checkpoints WHERE session = ? ORDER BY cid ASC`, session)
	if err != nil {
		return nil, fmt.Errorf("ledger: querying checkpoints: %w", err)
	}
	defer rows.Close()

	var out []checkpointRow
	for rows.Next() {
		var cr checkpointRow
		var chainHead, prevHash []byte
		if err := rows.Scan(&cr.CID, &cr.Session, &cr.SegFirst, &cr.SegLast, &chainHead, &prevHash,
			&cr.Body, &cr.Sig, &cr.PubkeyID, &cr.SignedNs); err != nil {
			return nil, fmt.Errorf("ledger: scanning checkpoint: %w", err)
		}
		copy(cr.ChainHead[:], chainHead)
		copy(cr.PrevHash[:], prevHash)
		out = append(out, cr)
	}
	return out, rows.Err()
}
