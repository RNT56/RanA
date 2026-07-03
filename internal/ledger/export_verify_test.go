package ledger

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/RNT56/RanA/internal/chain"
)

// TestExportedCheckpointsVerifyStandalone proves the exported
// checkpoints.cbor artifact carries everything a third-party verifier
// needs (docs/TRUST.md §8 step 4) with NO database and NO ledger package
// internals beyond what Export wrote to disk: read each uvarint-prefixed
// record, split it into (body, sig), and Ed25519-verify against
// pubkey.pem.
func TestExportedCheckpointsVerifyStandalone(t *testing.T) {
	d, key := buildCleanLedger(t)
	outDir := t.TempDir()
	session := "01ARZ3NDEKTSV4RRFFQ69G5FC0"
	if err := Export(d, session, outDir); err != nil {
		t.Fatalf("Export: %v", err)
	}

	pemBytes, err := os.ReadFile(filepath.Join(outDir, "pubkey.pem"))
	if err != nil {
		t.Fatalf("reading pubkey.pem: %v", err)
	}
	pub, err := chain.ParsePubkeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePubkeyPEM: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(outDir, "checkpoints.cbor"))
	if err != nil {
		t.Fatalf("reading checkpoints.cbor: %v", err)
	}

	count := 0
	off := 0
	for off < len(raw) {
		n, sz := binary.Uvarint(raw[off:])
		if sz <= 0 {
			t.Fatalf("malformed uvarint length prefix at offset %d", off)
		}
		off += sz
		rec := raw[off : off+int(n)]
		off += int(n)

		body, sig, err := decodeCheckpointExportRecord(rec)
		if err != nil {
			t.Fatalf("decodeCheckpointExportRecord: %v", err)
		}
		if err := chain.VerifyCheckpoint(pub, body, sig); err != nil {
			t.Fatalf("checkpoint %d does not verify against exported pubkey: %v", count, err)
		}
		count++
	}
	if count == 0 {
		t.Fatalf("expected at least one exported checkpoint")
	}
	_ = key
}
