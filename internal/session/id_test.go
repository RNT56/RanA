package session

import (
	"strings"
	"testing"
)

// fixedClock is an injectable schema.Clock for deterministic tests
// (CONTRACTS testing bar: no real sleeps, injectable clocks).
type fixedClock struct{ ms int64 }

func (c fixedClock) Now() int64 { return c.ms }

// incClock returns a strictly increasing sequence of millisecond
// timestamps, one per call to Now — used to test monotonic-ish ordering
// without a real sleep.
type incClock struct{ ms int64 }

func (c *incClock) Now() int64 {
	c.ms++
	return c.ms
}

func TestNewSessionID_Length(t *testing.T) {
	id := NewSessionID(fixedClock{ms: 1_700_000_000_000})
	if len(id) != 26 {
		t.Fatalf("NewSessionID: got length %d, want 26 (id=%q)", len(id), id)
	}
}

func TestNewSessionID_CrockfordCharset(t *testing.T) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	id := NewSessionID(fixedClock{ms: 1_700_000_000_000})
	for i, r := range id {
		if !strings.ContainsRune(alphabet, r) {
			t.Fatalf("NewSessionID: char %d (%q) not in Crockford base32 alphabet", i, r)
		}
	}
}

func TestNewSessionID_ExcludesAmbiguousChars(t *testing.T) {
	// Crockford base32 deliberately excludes I, L, O, U to avoid visual
	// confusion with 1/1/0/V.
	const excluded = "ILOU"
	for trial := 0; trial < 200; trial++ {
		id := NewSessionID(fixedClock{ms: int64(trial)})
		for _, bad := range excluded {
			if strings.ContainsRune(id, bad) {
				t.Fatalf("NewSessionID: id %q contains excluded char %q", id, bad)
			}
		}
	}
}

func TestNewSessionID_MonotonicTimestampPrefix(t *testing.T) {
	// IDs generated at increasing millisecond timestamps must sort
	// lexicographically in the same order (the ULID monotonic-ish
	// property derives from the timestamp being the most-significant
	// bits, encoded first).
	idLow := NewSessionID(fixedClock{ms: 1000})
	idHigh := NewSessionID(fixedClock{ms: 2000})
	if idLow >= idHigh {
		t.Fatalf("NewSessionID: expected id(ts=1000) < id(ts=2000) lexicographically, got %q >= %q", idLow, idHigh)
	}
}

func TestNewSessionID_MonotonicAcrossIncreasingClock(t *testing.T) {
	clk := &incClock{ms: 1_700_000_000_000}
	prev := NewSessionID(clk)
	for i := 0; i < 50; i++ {
		next := NewSessionID(clk)
		if next <= prev {
			t.Fatalf("NewSessionID: id %d (%q) did not sort after previous (%q)", i, next, prev)
		}
		prev = next
	}
}

func TestNewSessionID_UniqueAtSameTimestamp(t *testing.T) {
	clk := fixedClock{ms: 42}
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := NewSessionID(clk)
		if seen[id] {
			t.Fatalf("NewSessionID: duplicate id %q generated at same timestamp (iteration %d)", id, i)
		}
		seen[id] = true
	}
}

func TestNewSessionID_ZeroAndNegativeClock(t *testing.T) {
	for _, ms := range []int64{0, -1, -1_000_000} {
		id := NewSessionID(fixedClock{ms: ms})
		if len(id) != 26 {
			t.Fatalf("NewSessionID(ms=%d): got length %d, want 26", ms, len(id))
		}
	}
}
