package ledger

import (
	"path/filepath"
	"testing"
)

func TestOpenDBCreatesSchema(t *testing.T) {
	root := t.TempDir()
	d := Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	db, err := openDB(d.DBPath)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()

	tables := []string{"sessions", "events", "segments", "checkpoints", "digests", "paths", "event_paths", "meta"}
	for _, tbl := range tables {
		var name string
		row := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl)
		if err := row.Scan(&name); err != nil {
			t.Errorf("table %s missing: %v", tbl, err)
		}
	}
}

func TestOpenDBIsIdempotent(t *testing.T) {
	root := t.TempDir()
	d := Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	db1, err := openDB(d.DBPath)
	if err != nil {
		t.Fatalf("first openDB: %v", err)
	}
	db1.Close()

	db2, err := openDB(d.DBPath)
	if err != nil {
		t.Fatalf("second openDB: %v", err)
	}
	defer db2.Close()
}

func TestOpenDBPragmas(t *testing.T) {
	root := t.TempDir()
	d := Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	db, err := openDB(d.DBPath)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()

	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}

	var sync int
	if err := db.QueryRow(`PRAGMA synchronous`).Scan(&sync); err != nil {
		t.Fatalf("synchronous: %v", err)
	}
	// NORMAL == 1
	if sync != 1 {
		t.Errorf("synchronous = %d, want 1 (NORMAL)", sync)
	}
}

func TestOpenDBBadPath(t *testing.T) {
	root := t.TempDir()
	// Make a regular file where openDB needs a directory component, so
	// opening ledger.db underneath it must fail.
	blocker := filepath.Join(root, "blocker")
	if err := writeFileExclusive0600(blocker, []byte("x")); err != nil {
		t.Fatalf("writing blocker file: %v", err)
	}

	_, err := openDB(filepath.Join(blocker, "ledger.db"))
	if err == nil {
		t.Fatalf("expected error opening invalid path")
	}
}
