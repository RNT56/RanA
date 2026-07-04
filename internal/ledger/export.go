package ledger

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/chain"
)

// ErrSessionNotFound is returned by Export when session does not exist in
// the ledger at dir.
var ErrSessionNotFound = errors.New("ledger: session not found")

// Export writes a portable proof directory for session at outDir, per
// docs/TRUST.md §7: uvarint-length-prefixed canonical-CBOR events.cbor /
// segments.cbor / checkpoints.cbor (the AUTHORITATIVE, hashed artifacts),
// derived human-readable .jsonl siblings (never hashed — see manifest),
// pubkey.pem (the device public key, never the private key or the
// redaction salt), and manifest.json. outDir must be empty or
// not-yet-existing; Export creates it.
func Export(dir Datadir, session, outDir string) error {
	db, err := openDB(dir.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	var exists bool
	row := db.QueryRow(`SELECT 1 FROM sessions WHERE id = ?`, session)
	if err := row.Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrSessionNotFound, session)
		}
		return fmt.Errorf("ledger: checking session: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("ledger: creating export dir: %w", err)
	}

	eventCount, err := exportEvents(db, session, outDir)
	if err != nil {
		return err
	}
	if err := exportSegments(db, session, outDir); err != nil {
		return err
	}
	if err := exportCheckpoints(db, session, outDir); err != nil {
		return err
	}

	pub, err := resolveVerifyPubkey(db, dir)
	if err != nil {
		return err
	}
	if pub != nil {
		pemBytes, err := chain.ExportPubkeyPEM(pub)
		if err != nil {
			return fmt.Errorf("ledger: encoding pubkey.pem: %w", err)
		}
		if err := os.WriteFile(filepath.Join(outDir, "pubkey.pem"), pemBytes, 0o644); err != nil {
			return fmt.Errorf("ledger: writing pubkey.pem: %w", err)
		}
	}

	manifest := map[string]any{
		"format_version": 1,
		"hash":           "blake3",
		"sig":            "ed25519",
		"encoding":       "cbor-rfc8949-cde",
		"session":        session,
		"event_count":    eventCount,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("ledger: encoding manifest.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "manifest.json"), manifestBytes, 0o644); err != nil {
		return fmt.Errorf("ledger: writing manifest.json: %w", err)
	}

	return nil
}

// decodeEventEnvelopeFields extracts the "ts_wall" and "type" top-level
// envelope fields directly from an event's authoritative canonical CBOR
// bytes (the exact bytes hashed into its leaf), for use by exportEvents —
// see that function's comment for why these must never come from the
// events table's mutable, unhashed mirror columns instead. Decoding into
// map[string]any (rather than a struct) deliberately does not exercise
// cborcanon's strict unknown-field rejection: any well-formed envelope
// decodes here regardless of which event type it is.
func decodeEventEnvelopeFields(b []byte) (tsWall uint64, evType string, err error) {
	var env map[string]any
	if err := cborcanon.Decode(b, &env); err != nil {
		return 0, "", fmt.Errorf("decoding event envelope: %w", err)
	}
	if v, ok := env["ts_wall"].(uint64); ok {
		tsWall = v
	}
	if v, ok := env["type"].(string); ok {
		evType = v
	}
	return tsWall, evType, nil
}

// writeUvarintPrefixed appends a single uvarint-length-prefixed record to
// buf and returns the extended buffer (docs/TRUST.md §7: events.cbor /
// segments.cbor / checkpoints.cbor are "length-prefixed canonical-CBOR
// records").
func writeUvarintPrefixed(buf *bytes.Buffer, record []byte) {
	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], uint64(len(record)))
	buf.Write(lenBuf[:n])
	buf.Write(record)
}

func exportEvents(db *sql.DB, session, outDir string) (int, error) {
	// Deliberately select ONLY `bytes`, not the `ts_wall`/`type` mirror
	// columns: those columns exist purely as a query-index convenience
	// (CONTRACTS §internal/ledger: "bytes = full canonical event CBOR" is
	// the sole load-bearing copy) and are never part of any hashed or
	// signed structure, so they can diverge from the authoritative record
	// without Verify ever seeing it. events.jsonl is documented
	// (docs/TRUST.md §7) as "derived from events.cbor" — deriving its
	// human-readable fields from anything else would let an attacker with
	// raw sqlite access forge what an investigator reads in the
	// human-readable artifact while the chain still reports fully intact.
	rows, err := db.Query(`SELECT bytes FROM events WHERE session = ? ORDER BY rowid ASC`, session)
	if err != nil {
		return 0, fmt.Errorf("ledger: querying events for export: %w", err)
	}
	defer rows.Close()

	var cborBuf bytes.Buffer
	var jsonlBuf bytes.Buffer
	count := 0
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return 0, fmt.Errorf("ledger: scanning event for export: %w", err)
		}
		if b == nil {
			continue // archived/GC'd: bytes nulled; not exportable from live events table
		}
		writeUvarintPrefixed(&cborBuf, b)

		tsWall, evType, err := decodeEventEnvelopeFields(b)
		if err != nil {
			return 0, fmt.Errorf("ledger: decoding event envelope for export: %w", err)
		}

		line, err := json.Marshal(map[string]any{
			"ts_wall": tsWall,
			"type":    evType,
			"bytes":   base64.StdEncoding.EncodeToString(b),
		})
		if err != nil {
			return 0, fmt.Errorf("ledger: encoding events.jsonl line: %w", err)
		}
		jsonlBuf.Write(line)
		jsonlBuf.WriteByte('\n')
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	if err := os.WriteFile(filepath.Join(outDir, "events.cbor"), cborBuf.Bytes(), 0o644); err != nil {
		return 0, fmt.Errorf("ledger: writing events.cbor: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "events.jsonl"), jsonlBuf.Bytes(), 0o644); err != nil {
		return 0, fmt.Errorf("ledger: writing events.jsonl: %w", err)
	}
	return count, nil
}

func exportSegments(db *sql.DB, session, outDir string) error {
	segs, err := readSegments(db, session)
	if err != nil {
		return err
	}

	var cborBuf bytes.Buffer
	var jsonlBuf bytes.Buffer
	for _, sr := range segs {
		_, headerCBOR, err := chain.SegHash(chain.SegHeader{
			SessionID: sr.Session, SegIndex: sr.Seg, FirstRowID: sr.FirstRowID, LastRowID: sr.LastRowID,
			EventCount: sr.EventCount, MerkleRoot: sr.MerkleRoot, PrevSegHash: sr.PrevSegHash,
			GapSummary: sr.GapSummary, SealedAtWall: sr.SealedNs,
		})
		if err != nil {
			return fmt.Errorf("ledger: re-deriving segment header for export: %w", err)
		}
		writeUvarintPrefixed(&cborBuf, headerCBOR)

		line, err := json.Marshal(map[string]any{
			"seg":            sr.Seg,
			"first_rowid":    sr.FirstRowID,
			"last_rowid":     sr.LastRowID,
			"event_count":    sr.EventCount,
			"merkle_root":    base64.StdEncoding.EncodeToString(sr.MerkleRoot[:]),
			"prev_seg_hash":  base64.StdEncoding.EncodeToString(sr.PrevSegHash[:]),
			"seg_hash":       base64.StdEncoding.EncodeToString(sr.SegHash[:]),
			"gap_summary":    sr.GapSummary,
			"sealed_at_wall": sr.SealedNs,
		})
		if err != nil {
			return fmt.Errorf("ledger: encoding segments.jsonl line: %w", err)
		}
		jsonlBuf.Write(line)
		jsonlBuf.WriteByte('\n')
	}

	if err := os.WriteFile(filepath.Join(outDir, "segments.cbor"), cborBuf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("ledger: writing segments.cbor: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "segments.jsonl"), jsonlBuf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("ledger: writing segments.jsonl: %w", err)
	}
	return nil
}

func exportCheckpoints(db *sql.DB, session, outDir string) error {
	cks, err := readCheckpoints(db, session)
	if err != nil {
		return err
	}

	var cborBuf bytes.Buffer
	var jsonlBuf bytes.Buffer
	for _, ck := range cks {
		// checkpoints.cbor records the signed body plus its signature, so
		// a standalone verifier can Ed25519-verify without a database
		// (docs/TRUST.md §8 step 4): wrap as a small envelope of
		// [body, sig] uvarint-prefixed sub-fields within one record.
		rec := encodeCheckpointExportRecord(ck.Body, ck.Sig)
		writeUvarintPrefixed(&cborBuf, rec)

		line, err := json.Marshal(map[string]any{
			"session":    ck.Session,
			"seg_first":  ck.SegFirst,
			"seg_last":   ck.SegLast,
			"chain_head": base64.StdEncoding.EncodeToString(ck.ChainHead[:]),
			"prev_hash":  base64.StdEncoding.EncodeToString(ck.PrevHash[:]),
			"body":       base64.StdEncoding.EncodeToString(ck.Body),
			"sig":        base64.StdEncoding.EncodeToString(ck.Sig),
			"pubkey_id":  ck.PubkeyID,
			"signed_ns":  ck.SignedNs,
		})
		if err != nil {
			return fmt.Errorf("ledger: encoding checkpoints.jsonl line: %w", err)
		}
		jsonlBuf.Write(line)
		jsonlBuf.WriteByte('\n')
	}

	if err := os.WriteFile(filepath.Join(outDir, "checkpoints.cbor"), cborBuf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("ledger: writing checkpoints.cbor: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "checkpoints.jsonl"), jsonlBuf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("ledger: writing checkpoints.jsonl: %w", err)
	}
	return nil
}

// encodeCheckpointExportRecord packs (body, sig) as two uvarint-length-
// prefixed sub-fields, matching the simple, no-CBOR-envelope-needed
// approach described by docs/TRUST.md §8: the verifier reads the exact
// bytes that were signed (body) directly, alongside the signature.
func encodeCheckpointExportRecord(body, sig []byte) []byte {
	var buf bytes.Buffer
	writeUvarintPrefixed(&buf, body)
	writeUvarintPrefixed(&buf, sig)
	return buf.Bytes()
}

// decodeCheckpointExportRecord reverses encodeCheckpointExportRecord.
func decodeCheckpointExportRecord(rec []byte) (body, sig []byte, err error) {
	bodyLen, sz := binary.Uvarint(rec)
	if sz <= 0 {
		return nil, nil, errors.New("ledger: malformed checkpoint export record (body length)")
	}
	off := sz
	// Compare the wire-supplied length against the small, bounded remaining
	// space in uint64 BEFORE converting to int — a near-uint64-max length
	// would otherwise wrap to a negative int and defeat the bounds check
	// (same overflow-before-compare pattern hardened in internal/exportverify).
	if bodyLen > uint64(len(rec)-off) {
		return nil, nil, errors.New("ledger: malformed checkpoint export record (body overrun)")
	}
	body = rec[off : off+int(bodyLen)]
	off += int(bodyLen)

	sigLen, sz2 := binary.Uvarint(rec[off:])
	if sz2 <= 0 {
		return nil, nil, errors.New("ledger: malformed checkpoint export record (sig length)")
	}
	off += sz2
	if sigLen > uint64(len(rec)-off) {
		return nil, nil, errors.New("ledger: malformed checkpoint export record (sig overrun)")
	}
	sig = rec[off : off+int(sigLen)]
	return body, sig, nil
}
