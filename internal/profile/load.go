package profile

import (
	"embed"
	"fmt"
	"os"
	"sort"
)

// embeddedPacks embeds RanA's shipped profile packs.
//
// CONTRACTS.md conflict note (see final report): the canonical source of
// truth for shipped packs is profiles/*.toml at the repo root, but Go's
// go:embed directive can only embed files within the embedding file's own
// directory subtree — it cannot reach ../../profiles from
// internal/profile. Rather than move profiles/ (out of scope for this
// package, and it is referenced by path from docs/PROFILES.md and other
// packages/tooling) or invent a build-time copy step (no Makefile access,
// no new deps), this package keeps a same-content mirror under
// internal/profile/embedded/ and TestEmbeddedPacksMatchCanonicalSource
// (load_test.go) fails the build if the mirror ever drifts from
// profiles/*.toml. This should be revisited by the platform agent owning
// the Makefile — a `go generate` or Makefile copy step would remove the
// need for a manually-kept mirror.
//
//go:embed embedded/*.toml
var embeddedPacks embed.FS

// shippedPackNames lists the shipped Tier-1 (plan D17) and Tier-2 packs, in
// the order Available() returns them.
var shippedPackNames = []string{
	"generic", "claude-code", "codex", "openclaw",
	"aider", "cursor", "generic-ci",
}

// Load loads and validates a shipped profile pack by name (one of
// Available()). Load never touches the filesystem beyond the embedded FS.
func Load(name string) (*Profile, error) {
	data, err := embeddedPacks.ReadFile("embedded/" + name + ".toml")
	if err != nil {
		return nil, fmt.Errorf("profile: unknown built-in profile %q", name)
	}
	return Parse(string(data), name)
}

// LoadFile loads and validates a profile pack from an arbitrary filesystem
// path (a user-authored custom profile, docs/PROFILES.md).
func LoadFile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("profile: reading %s: %w", path, err)
	}
	return Parse(string(data), path)
}

// Available returns the names of the shipped built-in profile packs, sorted
// alphabetically.
func Available() []string {
	out := make([]string, len(shippedPackNames))
	copy(out, shippedPackNames)
	sort.Strings(out)
	return out
}
