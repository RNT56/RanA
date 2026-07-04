package main

import (
	"testing"

	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// TestHostFingerprintEncodesInSessionStart is the regression guard for the
// audit finding that hostFingerprint() returned plain Go strings in a
// map[string]any, so the session.start event built from it failed to encode
// with cborcanon.ErrRawString and was silently dropped on every real run —
// while every existing session.start test used an empty or redact.Literal
// host map and so never exercised the production shape. This drives the
// actual hostFingerprint() through the real NewSessionStart -> EncodeEvent
// path and asserts it round-trips.
func TestHostFingerprintEncodesInSessionStart(t *testing.T) {
	host := hostFingerprint()
	if len(host) == 0 {
		t.Fatal("hostFingerprint returned an empty map")
	}

	ev := schema.NewSessionStart(
		"01ARZ3NDEKTSV4RRFFQ69G5FAV", 0, 1, 0, 0, 1,
		redact.Literal("generic"), nil, host, nil,
	)

	if _, err := cborcanon.EncodeEvent(ev); err != nil {
		t.Fatalf("session.start built from hostFingerprint() failed to encode: %v "+
			"(a plain string in Data[\"host\"] trips ErrRawString and drops the "+
			"session-anchoring event)", err)
	}
}
