package ledger

import (
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"

	"github.com/RNT56/RanA/internal/chain"
)

// meta table keys (CONTRACTS §internal/ledger: "meta(k TEXT PK, v BLOB)
// -- format_version, salt, pubkey_id, pubkey_pem"). Populated at writer
// startup so read-only consumers (Verify, Export, `rana doctor`) can learn
// the format version and the signing key's PUBLIC half without ever
// touching device.key — a read-only path has no reason to load private
// key material into memory, even transiently.
const (
	metaKeyFormatVersion = "format_version"
	metaKeyPubkeyID      = "pubkey_id"
	metaKeyPubkeyPEM     = "pubkey_pem"
)

// ledgerFormatVersion is RanA's current on-disk ledger format version
// (docs/TRUST.md §7 manifest.json's format_version).
const ledgerFormatVersion = 1

// ensureMeta writes format_version (always) and, if key carries a public
// key, pubkey_id/pubkey_pem (idempotent: INSERT OR IGNORE — the first
// writer to touch a fresh ledger wins; later writers/restarts with the
// same key are no-ops, and CLAUDE.md's "never silently overwrite" spirit
// means a DIFFERENT key on a later restart is left as a mismatch for
// `rana doctor` to surface rather than silently rewritten here).
func ensureMeta(db *sql.DB, key chain.KeyInfo) error {
	if _, err := db.Exec(`INSERT OR IGNORE INTO meta(k, v) VALUES (?, ?)`, metaKeyFormatVersion, []byte{ledgerFormatVersion}); err != nil {
		return fmt.Errorf("ledger: recording format_version in meta: %w", err)
	}
	if len(key.PublicKey) == 0 {
		return nil
	}
	pemBytes, err := chain.ExportPubkeyPEM(key.PublicKey)
	if err != nil {
		return fmt.Errorf("ledger: encoding pubkey_pem for meta: %w", err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO meta(k, v) VALUES (?, ?)`, metaKeyPubkeyID, []byte(key.PubkeyID)); err != nil {
		return fmt.Errorf("ledger: recording pubkey_id in meta: %w", err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO meta(k, v) VALUES (?, ?)`, metaKeyPubkeyPEM, pemBytes); err != nil {
		return fmt.Errorf("ledger: recording pubkey_pem in meta: %w", err)
	}
	return nil
}

// loadMetaPubkey reads the device public key and its id from meta,
// returning (nil, "", nil) if no key has ever been recorded (a ledger
// with no signing key configured — segments seal but nothing is
// checkpointed).
func loadMetaPubkey(db *sql.DB) (ed25519.PublicKey, string, error) {
	var pemBytes []byte
	row := db.QueryRow(`SELECT v FROM meta WHERE k = ?`, metaKeyPubkeyPEM)
	if err := row.Scan(&pemBytes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("ledger: reading pubkey_pem from meta: %w", err)
	}
	pub, err := chain.ParsePubkeyPEM(pemBytes)
	if err != nil {
		return nil, "", fmt.Errorf("ledger: parsing pubkey_pem from meta: %w", err)
	}

	var idBytes []byte
	row = db.QueryRow(`SELECT v FROM meta WHERE k = ?`, metaKeyPubkeyID)
	if err := row.Scan(&idBytes); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, "", fmt.Errorf("ledger: reading pubkey_id from meta: %w", err)
	}

	return pub, string(idBytes), nil
}

// loadMetaFormatVersion reads format_version from meta, defaulting to
// ledgerFormatVersion if unset (an empty/never-written ledger).
func loadMetaFormatVersion(db *sql.DB) (int, error) {
	var v []byte
	row := db.QueryRow(`SELECT v FROM meta WHERE k = ?`, metaKeyFormatVersion)
	if err := row.Scan(&v); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ledgerFormatVersion, nil
		}
		return 0, fmt.Errorf("ledger: reading format_version from meta: %w", err)
	}
	if len(v) != 1 {
		return 0, fmt.Errorf("ledger: malformed format_version in meta (%d bytes)", len(v))
	}
	return int(v[0]), nil
}
