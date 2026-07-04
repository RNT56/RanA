package redact

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
)

// The structural-pattern set is a denylist, and a denylist always trails
// real-world credential formats (LIMITS.md §4). A signed pattern pack is the
// architecturally-clean way to extend it WITHOUT loosening the closed trust
// core: a pack can only ADD structural patterns (more redaction, never less —
// enforced by routing through WithExtraPatterns), it is Ed25519-signed so an
// operator loads only packs from a key they trust, and its patterns compile to
// Go's RE2 engine, which is linear-time by construction (no catastrophic-
// backtracking / ReDoS risk from an attacker-supplied pattern).
//
// This is deliberately NOT a way to change classes, loosen entropy, or disable
// redaction (P3): a pack is additive structural patterns and nothing else.

// PackFormatVersion is the only pattern-pack schema version this build accepts.
const PackFormatVersion = 1

// ErrPackSignature is returned when a pack's Ed25519 signature does not verify
// against the supplied trusted public key.
var ErrPackSignature = errors.New("redact: pattern pack signature does not verify")

// ErrPackFormat is returned for a malformed or wrong-version pack body.
var ErrPackFormat = errors.New("redact: malformed pattern pack")

// ErrPackKey is returned when the supplied public key is not a valid Ed25519
// key size (defense in depth against a caller passing a truncated key).
var ErrPackKey = errors.New("redact: invalid pattern-pack public key")

// PatternPack is the on-disk shape of a signed extension pack. The signature
// (supplied alongside, not inside) is computed over the exact JSON bytes.
type PatternPack struct {
	// Version must equal PackFormatVersion.
	Version int `json:"version"`
	// Name identifies the pack for diagnostics (e.g. "extra-providers-2026q3").
	Name string `json:"name"`
	// Patterns are structural regexes added to the built-in set. Each is
	// applied like WithExtraPatterns (class=entropy, additive-only). An empty
	// list is valid (a no-op pack).
	Patterns []string `json:"patterns"`
}

// VerifyAndLoadPack verifies packBytes against sig using the trusted Ed25519
// public key pub, parses the pack, and returns a redact.Option that adds its
// patterns to a Pipeline (via WithExtraPatterns, so the additive-only and
// compile-validation guarantees are inherited). It performs NO I/O — the
// caller reads the pack and detached signature from wherever it trusts (a
// pinned file, a fetched-and-checked artifact) and passes the bytes in.
//
// The signature is checked BEFORE the body is parsed, so a tampered or
// unsigned pack never reaches the regex compiler.
func VerifyAndLoadPack(packBytes, sig []byte, pub ed25519.PublicKey) (Option, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrPackKey, len(pub), ed25519.PublicKeySize)
	}
	if !ed25519.Verify(pub, packBytes, sig) {
		return nil, ErrPackSignature
	}

	var pack PatternPack
	if err := json.Unmarshal(packBytes, &pack); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPackFormat, err)
	}
	if pack.Version != PackFormatVersion {
		return nil, fmt.Errorf("%w: version %d, want %d", ErrPackFormat, pack.Version, PackFormatVersion)
	}

	// WithExtraPatterns compiles each expression (rejecting an invalid regex)
	// and appends it additively as class=entropy — a pack can only ever
	// increase what is redacted.
	return WithExtraPatterns(pack.Patterns), nil
}

// SignPack returns the detached Ed25519 signature over packBytes, for tooling
// that produces packs (a signer CLI, a release step). It is the inverse of the
// verification VerifyAndLoadPack performs. Kept here so the signing and
// verifying conventions cannot drift apart.
func SignPack(packBytes []byte, priv ed25519.PrivateKey) []byte {
	return ed25519.Sign(priv, packBytes)
}
