package vm

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"lukechampine.com/blake3"
)

func blake3Sum(b []byte) [32]byte {
	return blake3.Sum256(b)
}

func TestVerifyEmbeddedBaseLayerOK(t *testing.T) {
	data := []byte("fake buildroot base image bytes")
	sum := blake3Sum(data)

	layer := BaseLayer{Bytes: data, Checksum: sum}
	if err := layer.Verify(); err != nil {
		t.Fatalf("Verify() = %v, want nil", err)
	}
}

func TestVerifyEmbeddedBaseLayerMismatch(t *testing.T) {
	data := []byte("fake buildroot base image bytes")
	var badSum [32]byte
	copy(badSum[:], "not the right checksum at all!!")

	layer := BaseLayer{Bytes: data, Checksum: badSum}
	err := layer.Verify()
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("Verify() = %v, want ErrChecksumMismatch", err)
	}
}

func TestVerifyEmbeddedBaseLayerEmpty(t *testing.T) {
	layer := BaseLayer{}
	err := layer.Verify()
	if err == nil {
		t.Fatal("Verify() on empty BaseLayer should fail")
	}
}

// fakeFetcher implements RuntimeLayerFetcher entirely in-memory / against
// t.TempDir() files — no real network (CONTRACTS: "fetch is an injected
// interface, file-based test, NO real network").
type fakeFetcher struct {
	payload   []byte
	sig       []byte
	fetchErr  error
	fetchCall int
}

func (f *fakeFetcher) Fetch(dstPath string) error {
	f.fetchCall++
	if f.fetchErr != nil {
		return f.fetchErr
	}
	return os.WriteFile(dstPath, f.payload, 0o644)
}

func (f *fakeFetcher) FetchSignature() ([]byte, error) {
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return f.sig, nil
}

func genRuntimeKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

func TestRuntimeLayerFetchOnceVerifiesSignature(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genRuntimeKey(t)

	payload := []byte("fake node LTS + git + coreutils tarball")
	sig := ed25519.Sign(priv, payload)

	fetcher := &fakeFetcher{payload: payload, sig: sig}
	resolver := NewRuntimeLayerResolver(RuntimeLayerConfig{
		DestPath:  filepath.Join(dir, "runtime.tar"),
		PublicKey: pub,
		Fetcher:   fetcher,
	})

	path, err := resolver.Ensure()
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if path != filepath.Join(dir, "runtime.tar") {
		t.Fatalf("Ensure() path = %q, want %q", path, filepath.Join(dir, "runtime.tar"))
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("written payload mismatch")
	}
	if fetcher.fetchCall != 1 {
		t.Fatalf("fetchCall = %d, want 1", fetcher.fetchCall)
	}
}

func TestRuntimeLayerFetchOnceIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genRuntimeKey(t)

	payload := []byte("fake node LTS + git + coreutils tarball")
	sig := ed25519.Sign(priv, payload)

	fetcher := &fakeFetcher{payload: payload, sig: sig}
	resolver := NewRuntimeLayerResolver(RuntimeLayerConfig{
		DestPath:  filepath.Join(dir, "runtime.tar"),
		PublicKey: pub,
		Fetcher:   fetcher,
	})

	if _, err := resolver.Ensure(); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	if _, err := resolver.Ensure(); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}

	// "fetch-once": a second Ensure() call with the file already
	// present and valid must not re-fetch.
	if fetcher.fetchCall != 1 {
		t.Fatalf("fetchCall = %d after two Ensure() calls, want 1 (fetch-once)", fetcher.fetchCall)
	}
}

func TestRuntimeLayerRejectsBadSignature(t *testing.T) {
	dir := t.TempDir()
	pub, _ := genRuntimeKey(t)
	_, otherPriv := genRuntimeKey(t)

	payload := []byte("fake node LTS + git + coreutils tarball")
	// Signed with the WRONG key.
	sig := ed25519.Sign(otherPriv, payload)

	fetcher := &fakeFetcher{payload: payload, sig: sig}
	resolver := NewRuntimeLayerResolver(RuntimeLayerConfig{
		DestPath:  filepath.Join(dir, "runtime.tar"),
		PublicKey: pub,
		Fetcher:   fetcher,
	})

	_, err := resolver.Ensure()
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("Ensure() = %v, want ErrSignatureInvalid", err)
	}

	// The unverified payload must not be left on disk for later use.
	if _, statErr := os.Stat(filepath.Join(dir, "runtime.tar")); statErr == nil {
		t.Fatal("unverified payload was left on disk after signature failure")
	}
}

func TestRuntimeLayerRejectsTamperedPayloadOnDisk(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genRuntimeKey(t)

	payload := []byte("fake node LTS + git + coreutils tarball")
	sig := ed25519.Sign(priv, payload)

	dst := filepath.Join(dir, "runtime.tar")
	fetcher := &fakeFetcher{payload: payload, sig: sig}
	resolver := NewRuntimeLayerResolver(RuntimeLayerConfig{
		DestPath:  dst,
		PublicKey: pub,
		Fetcher:   fetcher,
	})

	if _, err := resolver.Ensure(); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}

	// Tamper with the already-fetched file on disk.
	if err := os.WriteFile(dst, []byte("corrupted!!"), 0o644); err != nil {
		t.Fatalf("tamper WriteFile: %v", err)
	}

	// A later Ensure() must detect the tamper (re-verify against
	// signature) rather than trusting presence-on-disk blindly, and
	// should re-fetch to recover.
	path, err := resolver.Ensure()
	if err != nil {
		t.Fatalf("Ensure after tamper: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("Ensure did not repair tampered payload via re-fetch")
	}
	if fetcher.fetchCall != 2 {
		t.Fatalf("fetchCall = %d, want 2 (initial + repair)", fetcher.fetchCall)
	}
}

func TestRuntimeLayerFetchErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	pub, _ := genRuntimeKey(t)

	fetcher := &fakeFetcher{fetchErr: errors.New("network unreachable (should never happen in this test)")}
	resolver := NewRuntimeLayerResolver(RuntimeLayerConfig{
		DestPath:  filepath.Join(dir, "runtime.tar"),
		PublicKey: pub,
		Fetcher:   fetcher,
	})

	_, err := resolver.Ensure()
	if err == nil {
		t.Fatal("expected error to propagate from Fetcher")
	}
}

func TestRuntimeLayerRejectsNilFetcherOrEmptyKey(t *testing.T) {
	dir := t.TempDir()
	pub, _ := genRuntimeKey(t)

	t.Run("nil fetcher", func(t *testing.T) {
		resolver := NewRuntimeLayerResolver(RuntimeLayerConfig{
			DestPath:  filepath.Join(dir, "runtime.tar"),
			PublicKey: pub,
			Fetcher:   nil,
		})
		if _, err := resolver.Ensure(); err == nil {
			t.Fatal("expected error for nil Fetcher")
		}
	})

	t.Run("empty public key", func(t *testing.T) {
		resolver := NewRuntimeLayerResolver(RuntimeLayerConfig{
			DestPath:  filepath.Join(dir, "runtime.tar"),
			PublicKey: nil,
			Fetcher:   &fakeFetcher{},
		})
		if _, err := resolver.Ensure(); err == nil {
			t.Fatal("expected error for empty PublicKey")
		}
	})
}
