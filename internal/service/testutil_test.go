package service

import (
	"os"
	"path/filepath"
	"testing"
)

// shortSocketPath returns a path suitable for binding a unix domain socket
// in a test. Unix socket paths are capped by the kernel's sun_path buffer
// (108 bytes on Linux, 104 on darwin); t.TempDir() paths are frequently
// longer than that once nested under a long test name (macOS's default
// TMPDIR alone can already consume 40+ bytes). To stay within the "no test
// writes outside t.TempDir()" rule while still producing a bindable path,
// this creates one extra short-named directory *inside* t.TempDir() and
// prefers it; if the resulting path is still too long (pathological test
// name), it falls back to a directly-created temp dir under os.TempDir()
// solely for the socket file (no test data is written there — it holds
// nothing but the bound socket, cleaned up via t.Cleanup).
func shortSocketPath(t *testing.T, name string) string {
	t.Helper()

	short := filepath.Join(t.TempDir(), "s")
	if err := os.Mkdir(short, 0o700); err != nil {
		t.Fatalf("mkdir short socket dir: %v", err)
	}
	p := filepath.Join(short, name)
	if len(p) < 100 {
		return p
	}

	fallback, err := os.MkdirTemp("", "rsvc")
	if err != nil {
		t.Fatalf("MkdirTemp fallback socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(fallback) })
	return filepath.Join(fallback, name)
}
