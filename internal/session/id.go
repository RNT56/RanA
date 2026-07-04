// Package session implements RanA's attribution primitive: one cgroup v2
// leaf per session (docs/ARCHITECTURE.md §1, §3). It provides the
// portable pieces — session id generation, systemd drop-in generation for
// `rana adopt`, adopt-mode caveat strings, and a platform-agnostic Driver
// interface — plus (behind //go:build linux) the real cgroup2/systemd
// drivers. The portable core is fully testable on darwin; only the linux
// files require a Linux kernel to run (though they still compile-check
// cross-platform).
package session

import "github.com/RNT56/RanA/internal/schema"

// Clock supplies the current time in Unix milliseconds, injectable for
// deterministic tests. It is an alias of schema.Clock so callers can pass
// the same clock implementation to both packages.
type Clock = schema.Clock

// NewSessionID generates a 26-character Crockford-base32 ULID-format
// session id (48-bit millisecond timestamp || 80 bits crypto/rand
// randomness). This package does not reimplement ULID generation — the
// canonical implementation lives in internal/schema (schema.NewSessionID,
// since schema.Event.Session is typed as this exact format) and session
// depends on schema per the CONTRACTS package graph. This wrapper exists so
// callers working with internal/session do not need to import schema
// directly for the one function they need from it.
func NewSessionID(clk Clock) string {
	return schema.NewSessionID(clk)
}
