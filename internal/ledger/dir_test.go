package ledger

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirLayout(t *testing.T) {
	root := t.TempDir()
	d := Dir(root)

	if got, want := d.Root, root; got != want {
		t.Fatalf("Root = %q, want %q", got, want)
	}
	if got, want := d.DBPath, filepath.Join(root, "ledger.db"); got != want {
		t.Fatalf("DBPath = %q, want %q", got, want)
	}
	if got, want := d.KeyPath, filepath.Join(root, "device.key"); got != want {
		t.Fatalf("KeyPath = %q, want %q", got, want)
	}
	if got, want := d.SaltPath, filepath.Join(root, "salt"); got != want {
		t.Fatalf("SaltPath = %q, want %q", got, want)
	}
	if got, want := d.ArchiveDir, filepath.Join(root, "archives"); got != want {
		t.Fatalf("ArchiveDir = %q, want %q", got, want)
	}
}

func TestDirEnsure(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "nested", "datadir")
	d := Dir(sub)

	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	info, err := os.Stat(sub)
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("root is not a directory")
	}

	archInfo, err := os.Stat(d.ArchiveDir)
	if err != nil {
		t.Fatalf("stat archive dir: %v", err)
	}
	if !archInfo.IsDir() {
		t.Fatalf("archive dir is not a directory")
	}

	// Ensure is idempotent.
	if err := d.Ensure(); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
}

func TestLoadOrCreateSalt(t *testing.T) {
	root := t.TempDir()
	d := Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	salt1, err := d.LoadOrCreateSalt()
	if err != nil {
		t.Fatalf("LoadOrCreateSalt: %v", err)
	}
	if len(salt1) < 16 {
		t.Fatalf("salt too short: %d bytes", len(salt1))
	}

	// Second call must return the SAME salt (persisted, not regenerated).
	salt2, err := d.LoadOrCreateSalt()
	if err != nil {
		t.Fatalf("second LoadOrCreateSalt: %v", err)
	}
	if string(salt1) != string(salt2) {
		t.Fatalf("salt changed across calls: %x != %x", salt1, salt2)
	}

	info, err := os.Stat(d.SaltPath)
	if err != nil {
		t.Fatalf("stat salt path: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("salt file mode = %v, want 0600", info.Mode().Perm())
	}
}
