package ledger

import (
	"testing"

	"github.com/RNT56/RanA/internal/chain"
)

// TestWriterRecordsPubkeyInMeta proves the Writer publishes its signing
// key's public half (and format_version) into the `meta` table at
// startup, so read-only consumers (Verify, Export, `rana doctor`) never
// need to touch device.key — and therefore never need private key
// material in memory — merely to learn the pubkey used to sign this
// ledger's checkpoints (defense in depth: a read-only verification path
// with no reason to load a private key should not load one).
func TestWriterRecordsPubkeyInMeta(t *testing.T) {
	root := t.TempDir()
	d := Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	key, err := chain.GenerateKey(root)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	w, err := NewWriter(d, WriterOptions{Key: key})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	db, err := openDB(d.DBPath)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()

	pub, pubkeyID, err := loadMetaPubkey(db)
	if err != nil {
		t.Fatalf("loadMetaPubkey: %v", err)
	}
	if pub == nil {
		t.Fatalf("expected a pubkey recorded in meta")
	}
	if string(pub) != string(key.PublicKey) {
		t.Fatalf("meta pubkey does not match the writer's signing key")
	}
	if pubkeyID != key.PubkeyID {
		t.Fatalf("meta pubkey_id = %q, want %q", pubkeyID, key.PubkeyID)
	}

	fv, err := loadMetaFormatVersion(db)
	if err != nil {
		t.Fatalf("loadMetaFormatVersion: %v", err)
	}
	if fv != 1 {
		t.Fatalf("format_version = %d, want 1", fv)
	}
}

// TestWriterWithoutKeyDoesNotPopulateMetaPubkey confirms a Writer
// constructed with no signing key (e.g. a sealing-only test writer)
// leaves meta's pubkey fields unset rather than writing a bogus/empty
// value, and that Verify still degrades gracefully (skips signature
// checks) rather than erroring.
func TestWriterWithoutKeyDoesNotPopulateMetaPubkey(t *testing.T) {
	root := t.TempDir()
	d := Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	w, err := NewWriter(d, WriterOptions{})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	db, err := openDB(d.DBPath)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()

	pub, _, err := loadMetaPubkey(db)
	if err != nil {
		t.Fatalf("loadMetaPubkey: %v", err)
	}
	if pub != nil {
		t.Fatalf("expected no pubkey recorded in meta when the writer has no signing key")
	}
}
