package chain

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// TestGenerateKey_CreatesFileWith0600Permissions confirms the device key
// file is created with mode 0600 (docs/TRUST.md §5: "stored 0600").
func TestGenerateKey_CreatesFileWith0600Permissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file-mode semantics only")
	}
	dir := t.TempDir()

	info, err := GenerateKey(dir)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	keyPath := filepath.Join(dir, "device.key")
	st, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat device.key: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("device.key mode = %o, want 0600", perm)
	}

	if info.PubkeyID == "" {
		t.Fatalf("KeyInfo.PubkeyID must not be empty")
	}
	if len(info.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("PublicKey size = %d, want %d", len(info.PublicKey), ed25519.PublicKeySize)
	}
}

// TestGenerateKey_UnwrappedLoadRoundTrip: a key generated without a
// passphrase can be loaded back and used to sign/verify.
func TestGenerateKey_UnwrappedLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()

	genInfo, err := GenerateKey(dir)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	loaded, err := LoadKey(dir, "")
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	if loaded.PubkeyID != genInfo.PubkeyID {
		t.Fatalf("PubkeyID mismatch: loaded=%s generated=%s", loaded.PubkeyID, genInfo.PubkeyID)
	}

	msg := []byte("test message")
	sig := ed25519.Sign(loaded.PrivateKey, msg)
	if !ed25519.Verify(genInfo.PublicKey, msg, sig) {
		t.Fatalf("signature from loaded key does not verify against generated public key")
	}
}

// TestGenerateKey_PassphraseWrapped: a key generated with a passphrase
// cannot be loaded with the wrong passphrase or no passphrase, but loads
// correctly with the right one.
func TestGenerateKey_PassphraseWrapped(t *testing.T) {
	dir := t.TempDir()

	genInfo, err := GenerateKey(dir)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := Wrap(dir, "correct horse battery staple"); err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	if _, err := LoadKey(dir, ""); err == nil {
		t.Fatalf("LoadKey with empty passphrase succeeded on a wrapped key")
	}
	if _, err := LoadKey(dir, "wrong passphrase"); err == nil {
		t.Fatalf("LoadKey with wrong passphrase succeeded")
	}

	loaded, err := LoadKey(dir, "correct horse battery staple")
	if err != nil {
		t.Fatalf("LoadKey with correct passphrase: %v", err)
	}
	if loaded.PubkeyID != genInfo.PubkeyID {
		t.Fatalf("PubkeyID mismatch after passphrase-wrapped round trip")
	}

	msg := []byte("another message")
	sig := ed25519.Sign(loaded.PrivateKey, msg)
	if !ed25519.Verify(genInfo.PublicKey, msg, sig) {
		t.Fatalf("signature from unwrapped key does not verify")
	}
}

// TestGenerateKey_RawKeyFileNeverContainsPlaintextWhenWrapped: when a
// passphrase is supplied, the on-disk key file must not contain the raw
// private key bytes in the clear.
func TestGenerateKey_RawKeyFileNeverContainsPlaintextWhenWrapped(t *testing.T) {
	dir := t.TempDir()

	genInfo, err := GenerateKey(dir)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := Wrap(dir, "s3cr3t-passphrase"); err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "device.key"))
	if err != nil {
		t.Fatalf("read device.key: %v", err)
	}

	loaded, err := LoadKey(dir, "s3cr3t-passphrase")
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	if containsSubslice(raw, loaded.PrivateKey.Seed()) {
		t.Fatalf("device.key file appears to contain the raw private key seed in the clear")
	}
	_ = genInfo
}

func containsSubslice(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// TestPubkeyID_DerivationAndStability: PubkeyID = hex(BLAKE3(pub)[:8]),
// stable across GenerateKey/LoadKey, and distinct for distinct keys.
func TestPubkeyID_DerivationAndStability(t *testing.T) {
	dir := t.TempDir()
	info, err := GenerateKey(dir)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	want := PubkeyID(info.PublicKey)
	if info.PubkeyID != want {
		t.Fatalf("KeyInfo.PubkeyID = %s, want %s (PubkeyID(pub))", info.PubkeyID, want)
	}
	if len(info.PubkeyID) != 16 { // hex of 8 bytes = 16 hex chars
		t.Fatalf("PubkeyID length = %d, want 16 hex chars", len(info.PubkeyID))
	}

	dir2 := t.TempDir()
	info2, err := GenerateKey(dir2)
	if err != nil {
		t.Fatalf("GenerateKey 2: %v", err)
	}
	if info2.PubkeyID == info.PubkeyID {
		t.Fatalf("two independently generated keys produced the same PubkeyID")
	}
}

// TestExportPubkeyPEM_RoundTrip: the exported PEM contains only the public
// key (never the private key), and can be parsed back to the same
// ed25519.PublicKey bytes.
func TestExportPubkeyPEM_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	info, err := GenerateKey(dir)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pemBytes, err := ExportPubkeyPEM(info.PublicKey)
	if err != nil {
		t.Fatalf("ExportPubkeyPEM: %v", err)
	}

	block, rest := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("ExportPubkeyPEM output is not valid PEM")
	}
	if len(rest) != 0 {
		t.Fatalf("trailing data after PEM block")
	}

	// The private key seed must never appear in the exported PEM bytes.
	if containsSubslice(pemBytes, info.PrivateKey.Seed()) {
		t.Fatalf("exported pubkey PEM contains private key material")
	}

	parsedPub, err := ParsePubkeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePubkeyPEM: %v", err)
	}
	if !parsedPub.Equal(info.PublicKey) {
		t.Fatalf("parsed pubkey does not match original")
	}
}

// TestGenerateKey_RefusesToOverwriteExistingKey ensures a second call to
// GenerateKey in the same directory does not silently clobber the existing
// device key (which would sever the chain of custody for existing
// checkpoints).
func TestGenerateKey_RefusesToOverwriteExistingKey(t *testing.T) {
	dir := t.TempDir()
	first, err := GenerateKey(dir)
	if err != nil {
		t.Fatalf("first GenerateKey: %v", err)
	}

	_, err = GenerateKey(dir)
	if err == nil {
		t.Fatalf("second GenerateKey in same dir succeeded, expected refusal")
	}

	// Confirm the original key is untouched.
	loaded, err := LoadKey(dir, "")
	if err != nil {
		t.Fatalf("LoadKey after refused overwrite: %v", err)
	}
	if loaded.PubkeyID != first.PubkeyID {
		t.Fatalf("original key was modified by the refused GenerateKey call")
	}
}

// TestGenerateKey_ConcurrentCallsNeverClobber: GenerateKey's existence
// check (os.Stat) and its final placement are two separate steps, which is
// a classic TOCTOU race window — two callers (e.g. `rana` and `ranad` both
// racing to bootstrap the device key on a machine's very first run) can
// both observe "no key file yet" before either has written. The contract
// (docs/TRUST.md §5, ErrKeyExists's doc comment) is that RanA never
// silently overwrites an existing signing key; that guarantee must hold
// even when GenerateKey is called concurrently from multiple goroutines
// against the same dir, not merely when called sequentially. Exactly one
// call must win; every other call must fail with ErrKeyExists (or at
// least: must NOT silently replace the winner's key), and the on-disk key
// afterward must be loadable and must match exactly one of the generated
// KeyInfos.
func TestGenerateKey_ConcurrentCallsNeverClobber(t *testing.T) {
	dir := t.TempDir()

	const n = 8
	type result struct {
		info KeyInfo
		err  error
	}
	results := make(chan result, n)

	var start sync.WaitGroup
	start.Add(1)
	for i := 0; i < n; i++ {
		go func() {
			start.Wait() // line up all goroutines to maximize race pressure
			info, err := GenerateKey(dir)
			results <- result{info, err}
		}()
	}
	start.Done()

	var successes []KeyInfo
	for i := 0; i < n; i++ {
		r := <-results
		if r.err == nil {
			successes = append(successes, r.info)
		} else if !errors.Is(r.err, ErrKeyExists) {
			t.Errorf("GenerateKey failed with an error other than ErrKeyExists: %v", r.err)
		}
	}

	if len(successes) != 1 {
		t.Fatalf("exactly one concurrent GenerateKey call must succeed, got %d successes: %+v", len(successes), successes)
	}

	// The on-disk key must match the sole winner — i.e. nothing clobbered it
	// after the fact.
	loaded, err := LoadKey(dir, "")
	if err != nil {
		t.Fatalf("LoadKey after concurrent GenerateKey race: %v", err)
	}
	if loaded.PubkeyID != successes[0].PubkeyID {
		t.Fatalf("on-disk key (pubkey_id=%s) does not match the sole reported winner (pubkey_id=%s) — the key was silently replaced after GenerateKey returned",
			loaded.PubkeyID, successes[0].PubkeyID)
	}
}

// TestLoadKey_MissingFile confirms a clear error when there is no key yet.
func TestLoadKey_MissingFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadKey(dir, ""); err == nil {
		t.Fatalf("LoadKey on empty dir succeeded, expected error")
	}
}

// TestWrap_EmptyPassphraseRejected: Wrap requires a non-empty passphrase
// (an empty-passphrase "wrap" would be a no-op that could mislead a caller
// into believing their key is protected).
func TestWrap_EmptyPassphraseRejected(t *testing.T) {
	dir := t.TempDir()
	if _, err := GenerateKey(dir); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := Wrap(dir, ""); err == nil {
		t.Fatalf("Wrap with empty passphrase succeeded, expected error")
	}
}

// TestWrap_MissingKeyFile: Wrap on a directory with no existing key fails
// clearly rather than creating one.
func TestWrap_MissingKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := Wrap(dir, "some passphrase"); err == nil {
		t.Fatalf("Wrap on missing key file succeeded, expected error")
	}
}

// TestWrap_AlreadyWrappedFails: calling Wrap a second time on an
// already-wrapped key fails cleanly (it cannot read the seed without the
// original passphrase, which Wrap does not take).
func TestWrap_AlreadyWrappedFails(t *testing.T) {
	dir := t.TempDir()
	if _, err := GenerateKey(dir); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := Wrap(dir, "first passphrase"); err != nil {
		t.Fatalf("first Wrap: %v", err)
	}
	if err := Wrap(dir, "second passphrase"); err == nil {
		t.Fatalf("second Wrap on already-wrapped key succeeded, expected error")
	}

	// Original passphrase must still work — the failed re-wrap must not
	// have corrupted the file.
	if _, err := LoadKey(dir, "first passphrase"); err != nil {
		t.Fatalf("LoadKey with original passphrase after failed re-wrap: %v", err)
	}
}
