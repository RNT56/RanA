package vm

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"lukechampine.com/blake3"
)

// ErrChecksumMismatch is returned when a layer's bytes do not hash to its
// expected checksum.
var ErrChecksumMismatch = errors.New("vm: checksum mismatch")

// ErrSignatureInvalid is returned when a fetched runtime layer's signature
// does not verify against the configured public key.
var ErrSignatureInvalid = errors.New("vm: signature invalid")

// ErrEmptyLayer is returned by BaseLayer.Verify when Bytes is empty.
var ErrEmptyLayer = errors.New("vm: layer has no bytes")

// BaseLayer is RanA's embedded base guest image: a reproducible,
// checksum-pinned Buildroot Linux build (BTF kernel, virtiofs, overlayfs,
// ranad + guest service baked in), embedded directly in the host `rana`
// binary (docs/MACOS.md §1 "Base layer"; plan D15/§6.2: "≤60MB,
// reproducible, checksum-pinned. Embedded in the rana binary").
//
// Because it is embedded (not fetched), verification is a pure local
// checksum check with no network or filesystem I/O of its own — Bytes is
// expected to come from a go:embed'd asset at the call site.
type BaseLayer struct {
	// Bytes is the raw embedded base image content.
	Bytes []byte

	// Checksum is the expected BLAKE3-256 digest of Bytes, pinned at
	// build time.
	Checksum [32]byte
}

// Verify checks that Bytes hashes to Checksum. It returns ErrEmptyLayer if
// Bytes is empty (an embedded asset should never be empty; treat that as a
// build-time failure rather than silently "verifying" nothing), or
// ErrChecksumMismatch if the hash does not match.
func (b BaseLayer) Verify() error {
	if len(b.Bytes) == 0 {
		return ErrEmptyLayer
	}
	got := blake3.Sum256(b.Bytes)
	if got != b.Checksum {
		return fmt.Errorf("%w: got %x, want %x", ErrChecksumMismatch, got, b.Checksum)
	}
	return nil
}

// RuntimeLayerFetcher retrieves the runtime layer (Node.js LTS + git +
// POSIX toolchain, docs/MACOS.md §1 "Runtime layer") and its detached
// signature. Production implementations perform real network I/O; test
// implementations are file-based fakes with no network dependency
// (CONTRACTS §internal/vm: "fetch is an injected interface, file-based
// test, NO real network").
type RuntimeLayerFetcher interface {
	// Fetch downloads the runtime layer payload to dstPath.
	Fetch(dstPath string) error

	// FetchSignature returns the detached signature (ed25519.Sign over
	// the payload's raw bytes) covering the layer Fetch would produce.
	FetchSignature() ([]byte, error)
}

// RuntimeLayerConfig configures a RuntimeLayerResolver.
type RuntimeLayerConfig struct {
	// DestPath is where the verified runtime layer is stored on disk
	// (docs/MACOS.md §1: "Fetched once, signature-checked, to
	// ~/Library/Application Support/rana/").
	DestPath string

	// PublicKey verifies the signature returned by Fetcher.FetchSignature.
	PublicKey ed25519.PublicKey

	// Fetcher performs the actual fetch. Must not be nil.
	Fetcher RuntimeLayerFetcher
}

// RuntimeLayerResolver ensures the runtime layer is present at DestPath,
// fetching it at most once per call to Ensure and verifying its signature
// before trusting it — "fetch-once-with-signature" (CONTRACTS
// §internal/vm; plan D15: "fetched once, signature-checked").
type RuntimeLayerResolver struct {
	cfg RuntimeLayerConfig
}

// NewRuntimeLayerResolver constructs a RuntimeLayerResolver. Validation of
// cfg happens lazily in Ensure, so construction itself cannot fail — this
// keeps call sites that build a resolver before they have a fetcher ready
// (e.g. wiring at startup) simple.
func NewRuntimeLayerResolver(cfg RuntimeLayerConfig) *RuntimeLayerResolver {
	return &RuntimeLayerResolver{cfg: cfg}
}

// Ensure guarantees a signature-verified runtime layer exists at
// DestPath, returning its path.
//
// If a file already exists at DestPath, Ensure re-verifies it against a
// freshly fetched signature before trusting it in place (no re-download in
// the common case: "fetch-once"). If that file has been tampered with (or
// the on-disk bytes otherwise fail verification), Ensure re-fetches the
// payload itself and verifies the result, so a corrupted cache repairs
// itself rather than wedging the guest boot path.
//
// A payload that fails signature verification is never left on disk
// (P4/P10: an unattested runtime layer must not silently become
// load-bearing) — Ensure removes any partially-written file before
// returning ErrSignatureInvalid.
func (r *RuntimeLayerResolver) Ensure() (string, error) {
	if r.cfg.Fetcher == nil {
		return "", errors.New("vm: RuntimeLayerConfig.Fetcher must not be nil")
	}
	if len(r.cfg.PublicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("vm: RuntimeLayerConfig.PublicKey must be %d bytes, got %d", ed25519.PublicKeySize, len(r.cfg.PublicKey))
	}

	sig, err := r.cfg.Fetcher.FetchSignature()
	if err != nil {
		return "", fmt.Errorf("vm: fetching runtime layer signature: %w", err)
	}

	if existing, err := os.ReadFile(r.cfg.DestPath); err == nil {
		if ed25519.Verify(r.cfg.PublicKey, existing, sig) {
			return r.cfg.DestPath, nil
		}
		// Present but no longer verifies (tampered, truncated, or a
		// stale payload the current signature doesn't cover) — fall
		// through to a fresh fetch rather than trusting it.
	}

	if err := r.cfg.Fetcher.Fetch(r.cfg.DestPath); err != nil {
		return "", fmt.Errorf("vm: fetching runtime layer: %w", err)
	}

	fetched, err := os.ReadFile(r.cfg.DestPath)
	if err != nil {
		return "", fmt.Errorf("vm: reading fetched runtime layer: %w", err)
	}

	if !ed25519.Verify(r.cfg.PublicKey, fetched, sig) {
		_ = os.Remove(r.cfg.DestPath)
		return "", ErrSignatureInvalid
	}

	return r.cfg.DestPath, nil
}
