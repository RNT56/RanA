package ledger

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/chain"
)

func TestExportProducesExpectedFiles(t *testing.T) {
	d, key := buildCleanLedger(t)
	outDir := t.TempDir()

	session := "01ARZ3NDEKTSV4RRFFQ69G5FC0"
	if err := Export(d, session, outDir); err != nil {
		t.Fatalf("Export: %v", err)
	}

	for _, name := range []string{"events.cbor", "events.jsonl", "segments.cbor", "segments.jsonl", "checkpoints.cbor", "checkpoints.jsonl", "pubkey.pem", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("expected export artifact %s: %v", name, err)
		}
	}

	// pubkey.pem round-trips to the same public key used to sign.
	pemBytes, err := os.ReadFile(filepath.Join(outDir, "pubkey.pem"))
	if err != nil {
		t.Fatalf("reading pubkey.pem: %v", err)
	}
	pub, err := chain.ParsePubkeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePubkeyPEM: %v", err)
	}
	if string(pub) != string(key.PublicKey) {
		t.Fatalf("exported pubkey does not match the signing key's public key")
	}

	// manifest.json has the documented fields (docs/TRUST.md §7).
	manifestBytes, err := os.ReadFile(filepath.Join(outDir, "manifest.json"))
	if err != nil {
		t.Fatalf("reading manifest.json: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("parsing manifest.json: %v", err)
	}
	for _, key := range []string{"format_version", "hash", "sig", "encoding", "session"} {
		if _, ok := manifest[key]; !ok {
			t.Errorf("manifest.json missing field %q: %v", key, manifest)
		}
	}
	if manifest["hash"] != "blake3" {
		t.Errorf("manifest hash = %v, want blake3", manifest["hash"])
	}
	if manifest["sig"] != "ed25519" {
		t.Errorf("manifest sig = %v, want ed25519", manifest["sig"])
	}

	// events.cbor is uvarint-length-prefixed canonical CBOR records.
	raw, err := os.ReadFile(filepath.Join(outDir, "events.cbor"))
	if err != nil {
		t.Fatalf("reading events.cbor: %v", err)
	}
	count := 0
	off := 0
	for off < len(raw) {
		n, sz := binary.Uvarint(raw[off:])
		if sz <= 0 {
			t.Fatalf("malformed uvarint length prefix at offset %d", off)
		}
		off += sz
		if off+int(n) > len(raw) {
			t.Fatalf("record length %d overruns buffer at offset %d", n, off)
		}
		rec := raw[off : off+int(n)]
		ok, err := cborcanon.IsCanonical(rec)
		if err != nil || !ok {
			t.Fatalf("events.cbor record %d is not canonical CBOR: ok=%v err=%v", count, ok, err)
		}
		off += int(n)
		count++
	}
	if count != 15 {
		t.Fatalf("events.cbor record count = %d, want 15", count)
	}
}

// TestExportNeverLeaksPrivateKeyOrSalt is a direct regression guard for
// docs/TRUST.md §7's guarantee ("pubkey.pem ... NOT the private key, NOT
// the ledger salt") and CLAUDE.md P3/§6: an exported proof directory is
// handed to third parties, so it must never contain the raw bytes of the
// device's Ed25519 private key or the per-ledger redaction/CRC salt — the
// salt is load-bearing for correlating a marker's typed-replacement CRC
// back to a real secret (docs/REDACTION.md §4), so its presence in an
// export would defeat redaction's whole purpose for every marker ever
// produced by this ledger, not just one event.
func TestExportNeverLeaksPrivateKeyOrSalt(t *testing.T) {
	d, key := buildCleanLedger(t)
	salt, err := d.LoadOrCreateSalt()
	if err != nil {
		t.Fatalf("LoadOrCreateSalt: %v", err)
	}
	if len(key.PrivateKey) == 0 {
		t.Fatalf("test fixture key has no private key half; test would be vacuous")
	}
	if len(salt) == 0 {
		t.Fatalf("test fixture salt is empty; test would be vacuous")
	}

	outDir := t.TempDir()
	session := "01ARZ3NDEKTSV4RRFFQ69G5FC0"
	if err := Export(d, session, outDir); err != nil {
		t.Fatalf("Export: %v", err)
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("ReadDir(outDir): %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(outDir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading exported file %s: %v", path, err)
		}
		if bytes.Contains(b, key.PrivateKey) {
			t.Fatalf("exported file %s contains the device PRIVATE key bytes", e.Name())
		}
		if bytes.Contains(b, salt) {
			t.Fatalf("exported file %s contains the ledger redaction salt bytes", e.Name())
		}
	}
}

func TestExportUnknownSession(t *testing.T) {
	d, _ := buildCleanLedger(t)
	outDir := t.TempDir()
	err := Export(d, "nonexistent-session", outDir)
	if err == nil {
		t.Fatalf("expected error exporting an unknown session")
	}
}

// TestExportJSONLDerivesFromAuthoritativeBytesNotMirrorColumns proves
// events.jsonl's "type"/"ts_wall" fields are derived from the same
// authoritative canonical CBOR bytes that events.cbor hashes and Verify
// checks — NOT from the events table's `type`/`ts_wall` columns, which are
// a mutable, unhashed query-index convenience (CONTRACTS §internal/ledger:
// "bytes = full canonical event CBOR"; docs/TRUST.md §7: "events.jsonl ...
// derived from events.cbor"). An attacker with raw sqlite access who edits
// only the mirror columns (leaving `bytes` — and therefore the chain —
// untouched) must NOT be able to make the human-readable export lie about
// what actually happened.
func TestExportJSONLDerivesFromAuthoritativeBytesNotMirrorColumns(t *testing.T) {
	d, _ := buildCleanLedger(t)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FC0"

	db, err := openDB(d.DBPath)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	var rowid int64
	row := db.QueryRow(`SELECT rowid FROM events WHERE session = ? ORDER BY rowid ASC LIMIT 1`, session)
	if err := row.Scan(&rowid); err != nil {
		t.Fatalf("selecting first event: %v", err)
	}
	// Forge the mirror columns only; `bytes` (the hashed record) is
	// untouched, so the chain must still verify OK.
	if _, err := db.Exec(`UPDATE events SET type = 'alert.cgroup_escape', ts_wall = 999999999 WHERE rowid = ?`, rowid); err != nil {
		t.Fatalf("forging mirror columns: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing db: %v", err)
	}

	res, err := Verify(d, VerifyOptions{Session: session})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Code != CodeOK {
		t.Fatalf("precondition failed: forging only the mirror columns should still verify OK; got code=%d findings=%+v", res.Code, res.Findings)
	}

	outDir := t.TempDir()
	if err := Export(d, session, outDir); err != nil {
		t.Fatalf("Export: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(outDir, "events.jsonl"))
	if err != nil {
		t.Fatalf("reading events.jsonl: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var first map[string]any
	if err := dec.Decode(&first); err != nil {
		t.Fatalf("decoding first events.jsonl line: %v", err)
	}
	if first["type"] == "alert.cgroup_escape" {
		t.Fatalf("events.jsonl reports the FORGED mirror-column type %v; it must reflect the authoritative bytes instead", first["type"])
	}
	if first["type"] != "proc.exec" {
		t.Fatalf("events.jsonl type = %v, want proc.exec (from the authoritative canonical bytes)", first["type"])
	}
	if ts, ok := first["ts_wall"].(float64); !ok || ts == 999999999 {
		t.Fatalf("events.jsonl ts_wall = %v, want the authoritative value (not the forged mirror column 999999999)", first["ts_wall"])
	}
}
