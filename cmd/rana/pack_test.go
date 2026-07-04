package main

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// tarZstEntries reads a .tar.zst file back into a map of path -> contents,
// for asserting on writeProofPack's output without depending on any
// external tar/zstd tooling being installed on the test machine.
func tarZstEntries(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	zr, err := zstd.NewReader(f)
	if err != nil {
		t.Fatalf("zstd.NewReader: %v", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	out := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("reading tar entry %s: %v", hdr.Name, err)
		}
		out[hdr.Name] = b
	}
	return out
}

// TestWriteProofPack_BundlesExportAndViewer proves the pack contains every
// export artifact under exports/ plus the verifier viewer assets under
// viewer/, and that it round-trips through a real zstd+tar reader.
func TestWriteProofPack_BundlesExportAndViewer(t *testing.T) {
	exportDir := t.TempDir()
	mustWrite := func(name, content string) {
		if err := os.WriteFile(filepath.Join(exportDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("writing fixture %s: %v", name, err)
		}
	}
	mustWrite("manifest.json", `{"format_version":1}`)
	mustWrite("events.cbor", "event-bytes")
	mustWrite("segments.cbor", "segment-bytes")
	mustWrite("checkpoints.cbor", "checkpoint-bytes")
	mustWrite("pubkey.pem", "-----BEGIN PUBLIC KEY-----\n")

	packPath := filepath.Join(t.TempDir(), "sess.ranaproof")
	session := "01ARZ3NDEKTSV4RRFFQ69G5FC0"
	if err := writeProofPack(exportDir, packPath, session); err != nil {
		t.Fatalf("writeProofPack: %v", err)
	}

	if _, err := os.Stat(packPath); err != nil {
		t.Fatalf("pack file not created: %v", err)
	}

	entries := tarZstEntries(t, packPath)
	for _, want := range []string{
		"exports/manifest.json",
		"exports/events.cbor",
		"exports/segments.cbor",
		"exports/checkpoints.cbor",
		"exports/pubkey.pem",
		"viewer/index.html",
		"viewer/main.js",
		"viewer/style.css",
		"OPEN_ME.txt",
	} {
		if _, ok := entries[want]; !ok {
			t.Errorf("pack missing entry %q; got entries: %v", want, keysOf(entries))
		}
	}

	if got := string(entries["exports/events.cbor"]); got != "event-bytes" {
		t.Errorf("exports/events.cbor content = %q, want %q", got, "event-bytes")
	}
	if !strings.Contains(string(entries["OPEN_ME.txt"]), session) {
		t.Errorf("OPEN_ME.txt does not mention session %q: %q", session, entries["OPEN_ME.txt"])
	}
}

// TestWriteProofPack_MissingViewerAssetsIsNonFatal proves a pack still
// builds (containing the export, which is the load-bearing artifact) even
// when the verifier viewer assets are not found at build/run time — e.g. a
// stripped-down install missing assets/verifier. The proof pack's trust
// value comes from the export files themselves (verifiable by
// rana-verify-standalone or any from-scratch reimplementation of
// docs/TRUST.md §8); the bundled viewer is a convenience, not a
// dependency.
func TestWriteProofPack_MissingViewerAssetsIsNonFatal(t *testing.T) {
	exportDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(exportDir, "manifest.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	orig := verifierAssetsDir
	verifierAssetsDir = func() string { return filepath.Join(t.TempDir(), "does-not-exist") }
	defer func() { verifierAssetsDir = orig }()

	packPath := filepath.Join(t.TempDir(), "sess.ranaproof")
	if err := writeProofPack(exportDir, packPath, "sess"); err != nil {
		t.Fatalf("writeProofPack: %v", err)
	}
	entries := tarZstEntries(t, packPath)
	if _, ok := entries["exports/manifest.json"]; !ok {
		t.Fatalf("pack missing exports/manifest.json even without viewer assets")
	}
	if _, ok := entries["viewer/index.html"]; ok {
		t.Fatalf("pack should not contain a viewer/ entry when assets are absent")
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
