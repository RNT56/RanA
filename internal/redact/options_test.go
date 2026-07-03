package redact

import (
	"regexp"
	"testing"
)

func TestNewPipelineDefaults(t *testing.T) {
	p, err := NewPipeline([]byte("test-salt"))
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	if p.minLen != defaultMinLen {
		t.Errorf("minLen = %d, want %d", p.minLen, defaultMinLen)
	}
	if p.bitsPerChar != defaultBitsPerChar {
		t.Errorf("bitsPerChar = %v, want %v", p.bitsPerChar, defaultBitsPerChar)
	}
	if len(p.patterns) == 0 {
		t.Error("expected non-empty compiled pattern set")
	}
}

func TestWithExtraPatterns(t *testing.T) {
	p, err := NewPipeline([]byte("salt"), WithExtraPatterns([]string{`custom-[0-9]{6}`}))
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	if len(p.patterns) != len(builtinPatterns())+1 {
		t.Errorf("expected builtin+1 patterns, got %d", len(p.patterns))
	}
}

func TestWithExtraPatternsInvalidRegexErrors(t *testing.T) {
	_, err := NewPipeline([]byte("salt"), WithExtraPatterns([]string{`(unterminated`}))
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
}

// Stricter per docs/REDACTION.md: "lower length, higher entropy" — a
// stricter threshold is a shorter minLen (catches shorter tokens too) and/or
// a higher bitsPerChar bar is NOT what makes it stricter on its own; the doc
// pairs them as "lower length, higher entropy" describing the direction each
// individual knob must move to only ever catch a superset... Concretely:
// minLen must be <= current (shorter-or-equal qualifies more tokens) and
// bitsPerChar must be >= current (WAIT: a higher entropy bar catches FEWER
// tokens). Re-reading docs/REDACTION.md's literal phrase "lower length,
// higher entropy" describes typical stricter profile values, not a
// monotonic requirement on entropy. The enforceable, unambiguous half is
// minLen: stricter must never raise it. bitsPerChar accompanies "higher"
// per the doc text, so stricter requires bitsPerChar >= current too.
func TestWithStricterEntropyAcceptsStricter(t *testing.T) {
	p, err := NewPipeline([]byte("salt"), WithStricterEntropy(10, 4.5))
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	if p.minLen != 10 {
		t.Errorf("minLen = %d, want 10", p.minLen)
	}
	if p.bitsPerChar != 4.5 {
		t.Errorf("bitsPerChar = %v, want 4.5", p.bitsPerChar)
	}
}

func TestWithStricterEntropyRejectsLooserLength(t *testing.T) {
	_, err := NewPipeline([]byte("salt"), WithStricterEntropy(30, 4.5))
	if err == nil {
		t.Fatal("expected error: longer minLen is looser (fewer tokens qualify)")
	}
}

func TestWithStricterEntropyRejectsLowerBits(t *testing.T) {
	_, err := NewPipeline([]byte("salt"), WithStricterEntropy(10, 3.0))
	if err == nil {
		t.Fatal("expected error for lower bits-per-char (looser per doc's \"higher entropy\" direction)")
	}
}

func TestWithStricterEntropyAcceptsEqual(t *testing.T) {
	_, err := NewPipeline([]byte("salt"), WithStricterEntropy(defaultMinLen, defaultBitsPerChar))
	if err != nil {
		t.Fatalf("equal thresholds should be accepted as non-looser: %v", err)
	}
}

func TestNewPipelineRequiresSalt(t *testing.T) {
	_, err := NewPipeline(nil)
	if err == nil {
		t.Fatal("expected error for empty salt")
	}
	_, err = NewPipeline([]byte{})
	if err == nil {
		t.Fatal("expected error for empty salt")
	}
}

func TestMultipleOptionsCompose(t *testing.T) {
	p, err := NewPipeline([]byte("salt"),
		WithExtraPatterns([]string{`foo-[0-9]{4}`}),
		WithStricterEntropy(15, 4.2),
	)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	if p.minLen != 15 || p.bitsPerChar != 4.2 {
		t.Errorf("options did not both apply: minLen=%d bits=%v", p.minLen, p.bitsPerChar)
	}
	found := false
	for _, pat := range p.patterns {
		if pat.re.String() == regexp.MustCompile(`foo-[0-9]{4}`).String() {
			found = true
		}
	}
	if !found {
		t.Error("extra pattern not present in compiled set")
	}
}
