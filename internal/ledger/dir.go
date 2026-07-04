// Package ledger implements RanA's tamper-evident, secret-free SQLite
// ledger: single-writer group-commit ingestion, segment sealing, signed
// ledger-wide checkpointing, verification, export, and cold-archive GC
// (docs/TRUST.md). It is part of the trust core and
// held to the strictest testing bar (CLAUDE.md §3.1).
package ledger

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// saltSize is the size in bytes of the per-ledger redaction/CRC salt
// (docs/REDACTION.md §4) persisted at Datadir.SaltPath.
const saltSize = 32

// Datadir is the on-disk layout of a RanA user data directory
// (CONTRACTS §internal/ledger): root/ledger.db, root/device.key, root/salt,
// root/archives/.
type Datadir struct {
	Root       string
	DBPath     string
	KeyPath    string
	SaltPath   string
	ArchiveDir string
}

// Dir computes the Datadir layout rooted at root. It performs no I/O.
func Dir(root string) Datadir {
	return Datadir{
		Root:       root,
		DBPath:     filepath.Join(root, "ledger.db"),
		KeyPath:    filepath.Join(root, "device.key"),
		SaltPath:   filepath.Join(root, "salt"),
		ArchiveDir: filepath.Join(root, "archives"),
	}
}

// Ensure creates the data directory and its archives/ subdirectory if they
// do not already exist. It is idempotent.
func (d Datadir) Ensure() error {
	if err := os.MkdirAll(d.Root, 0o700); err != nil {
		return fmt.Errorf("ledger: creating datadir %s: %w", d.Root, err)
	}
	if err := os.MkdirAll(d.ArchiveDir, 0o700); err != nil {
		return fmt.Errorf("ledger: creating archive dir %s: %w", d.ArchiveDir, err)
	}
	return nil
}

// LoadOrCreateSalt reads the per-ledger redaction/CRC salt from d.SaltPath,
// generating and persisting a fresh random one (0600) if none exists yet.
// The salt is never exported (docs/TRUST.md §7, docs/REDACTION.md §4).
func (d Datadir) LoadOrCreateSalt() ([]byte, error) {
	existing, err := os.ReadFile(d.SaltPath)
	if err == nil {
		return existing, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("ledger: reading salt %s: %w", d.SaltPath, err)
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("ledger: generating salt: %w", err)
	}

	if err := writeFileExclusive0600(d.SaltPath, salt); err != nil {
		if os.IsExist(err) {
			// Lost a race with a concurrent creator; read back the winner's
			// salt rather than erroring.
			return os.ReadFile(d.SaltPath)
		}
		return nil, err
	}
	return salt, nil
}

// writeFileExclusive0600 atomically writes data to path with mode 0600,
// failing with an os.IsExist-satisfying error if path already exists.
func writeFileExclusive0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".salt.tmp-*")
	if err != nil {
		return fmt.Errorf("ledger: creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("ledger: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("ledger: writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("ledger: closing temp file: %w", err)
	}
	if err := os.Link(tmpPath, path); err != nil {
		return err
	}
	return nil
}
