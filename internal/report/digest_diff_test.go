package report

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
	"lukechampine.com/blake3"
)

func blake3Hex(data []byte) string {
	h := blake3.New(32, nil)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func mustSettleEvent(t *testing.T, path string, prevDigest, newDigest []byte) schema.Event {
	t.Helper()
	ev := schema.NewFsSettle("sess-1", 0, 1, 100, 100, 0,
		redact.Literal(path), prevDigest, newDigest, 0, 100)
	return ev
}

func TestDigestDiff_MatchesOnDisk(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "workspace", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	content := []byte("hello world, this is a settled file\n")
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	newDigestHex := blake3Hex(content)
	newDigest, _ := hex.DecodeString(newDigestHex)

	ev := mustSettleEvent(t, p, nil, newDigest)

	res, err := DigestDiff(identityTranslator{}, ev)
	if err != nil {
		t.Fatalf("DigestDiff: %v", err)
	}
	if res.Path != p {
		t.Errorf("Path = %q, want %q", res.Path, p)
	}
	if !res.HaveNew {
		t.Errorf("HaveNew = false, want true (on-disk content matches new_digest)")
	}
	if res.NewDigest != newDigestHex {
		t.Errorf("NewDigest = %q, want %q", res.NewDigest, newDigestHex)
	}
	if res.PrevDigest != "" {
		t.Errorf("PrevDigest = %q, want empty (no prev_digest on event)", res.PrevDigest)
	}
	if res.Note == "" {
		t.Errorf("Note should explain the match")
	}
}

func TestDigestDiff_MismatchOnDisk(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "changed.txt")
	if err := os.WriteFile(p, []byte("current content on disk"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Event claims a digest that does not match what's actually on disk now
	// (file has since changed again).
	staleDigest := make([]byte, 32) // all zero — will never match a real hash
	ev := mustSettleEvent(t, p, nil, staleDigest)

	res, err := DigestDiff(identityTranslator{}, ev)
	if err != nil {
		t.Fatalf("DigestDiff: %v", err)
	}
	if res.HaveNew {
		t.Errorf("HaveNew = true, want false (on-disk content differs from recorded new_digest)")
	}
	if res.NewDigest != hex.EncodeToString(staleDigest) {
		t.Errorf("NewDigest mismatch")
	}
	if res.Note == "" {
		t.Errorf("Note should explain the mismatch")
	}
}

func TestDigestDiff_FileGone(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "deleted.txt")
	// never created

	ev := mustSettleEvent(t, p, nil, make([]byte, 32))

	res, err := DigestDiff(identityTranslator{}, ev)
	if err != nil {
		t.Fatalf("DigestDiff: %v", err)
	}
	if res.HaveNew {
		t.Errorf("HaveNew = true, want false (file does not exist)")
	}
	if res.Note == "" {
		t.Errorf("Note should explain the file is gone")
	}
}

func TestDigestDiff_PrevDigestSurfaced(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	content := []byte("v2 content")
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	newDigestHex := blake3Hex(content)
	newDigest, _ := hex.DecodeString(newDigestHex)
	prevDigest := []byte{1, 2, 3, 4}

	ev := mustSettleEvent(t, p, prevDigest, newDigest)

	res, err := DigestDiff(identityTranslator{}, ev)
	if err != nil {
		t.Fatalf("DigestDiff: %v", err)
	}
	if res.PrevDigest != hex.EncodeToString(prevDigest) {
		t.Errorf("PrevDigest = %q, want %q", res.PrevDigest, hex.EncodeToString(prevDigest))
	}
}

// TestDigestDiff_RefusesNonRegularFile guards against a path that
// currently resolves to a FIFO (or other special file) on local disk: a
// naive os.Open+io.Copy would block forever waiting for a writer that will
// never come, turning report/diff generation into a denial of service on
// attacker-influenced or merely coincidental on-disk state. DigestDiff must
// notice this via a stat-first check and return promptly with an
// explanatory Note instead of hanging.
func TestDigestDiff_RefusesNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "evil.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Skipf("mkfifo unsupported on this platform: %v", err)
	}
	ev := mustSettleEvent(t, fifoPath, nil, make([]byte, 32))

	done := make(chan struct{})
	var res DigestDiffResult
	var err error
	go func() {
		res, err = DigestDiff(identityTranslator{}, ev)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("DigestDiff hung reading a non-regular file (FIFO) instead of refusing it")
	}
	if err != nil {
		t.Fatalf("DigestDiff: %v", err)
	}
	if res.HaveNew {
		t.Errorf("HaveNew = true, want false for a refused non-regular file")
	}
	if res.Note == "" {
		t.Errorf("Note should explain the file was refused")
	}
}

func TestDigestDiff_WrongEventType(t *testing.T) {
	ev := schema.NewFsUnlink("sess-1", 0, 1, 100, 100, 0, redact.Literal("/tmp/x"), schema.PathSourceResolved)
	if _, err := DigestDiff(identityTranslator{}, ev); err == nil {
		t.Fatal("expected error for non-fs.settle event, got nil")
	}
}

func TestDigestDiff_TranslatesPath(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real.txt")
	content := []byte("guest content")
	if err := os.WriteFile(realPath, content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	newDigestHex := blake3Hex(content)
	newDigest, _ := hex.DecodeString(newDigestHex)

	guestPath := "/mnt/host/tag/real.txt"
	ev := mustSettleEvent(t, guestPath, nil, newDigest)

	tr := fakeTranslator{guestPath: guestPath, hostPath: realPath}
	res, err := DigestDiff(tr, ev)
	if err != nil {
		t.Fatalf("DigestDiff: %v", err)
	}
	if !res.HaveNew {
		t.Errorf("HaveNew = false, want true after translation")
	}
	if res.Path != realPath {
		t.Errorf("Path = %q, want translated host path %q", res.Path, realPath)
	}
}

// identityTranslator is a PathTranslator that returns its input unchanged,
// for tests that use real host-native paths directly (no vm involved).
type identityTranslator struct{}

func (identityTranslator) Translate(p string) (string, error) { return p, nil }

// fakeTranslator maps exactly one guest path to one host path, for testing
// that DigestDiff consults the translator rather than reading the raw event
// path directly off disk.
type fakeTranslator struct {
	guestPath string
	hostPath  string
}

func (f fakeTranslator) Translate(p string) (string, error) {
	if p == f.guestPath {
		return f.hostPath, nil
	}
	return p, nil
}
