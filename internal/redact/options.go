package redact

import (
	"errors"
	"fmt"
	"regexp"
)

// Default Stage 3 entropy thresholds per docs/REDACTION.md Stage 3: a token
// of length >= 20 with Shannon entropy >= 4.0 bits/char (and not a
// dictionary word) is redacted.
const (
	defaultMinLen      = 20
	defaultBitsPerChar = 4.0
)

// ErrEmptySalt is returned by NewPipeline when the caller supplies a nil or
// zero-length salt. The salt is load-bearing for the typed-replacement CRC
// (docs/REDACTION.md §4) and must never be empty.
var ErrEmptySalt = errors.New("redact: salt must not be empty")

// ErrLooserEntropy is returned by WithStricterEntropy when the requested
// thresholds would redact strictly less than the pipeline default, which
// docs/REDACTION.md forbids: "Thresholds are tunable stricter per profile
// (lower length, higher entropy) — never looser."
var ErrLooserEntropy = errors.New("redact: entropy thresholds must be stricter than default, never looser")

// ErrInvalidPattern is returned by WithExtraPatterns when one of the
// supplied regular expressions fails to compile.
var ErrInvalidPattern = errors.New("redact: invalid extra pattern")

// Option configures a Pipeline at construction time. Options are applied in
// the order passed to NewPipeline.
type Option func(*Pipeline) error

// WithExtraPatterns adds caller-supplied structural regular expressions to
// the built-in pattern set (Stage 2). Per docs/REDACTION.md, the built-in
// set is additive-only: extra patterns are appended, never replace or
// remove a built-in. Matches from extra patterns are labeled with the
// "entropy" class (the closed §4 class enum has no slot for arbitrary
// caller-defined provider names).
func WithExtraPatterns(exprs []string) Option {
	return func(p *Pipeline) error {
		for _, expr := range exprs {
			re, err := regexp.Compile(expr)
			if err != nil {
				return fmt.Errorf("%w: %q: %v", ErrInvalidPattern, expr, err)
			}
			p.patterns = append(p.patterns, pattern{
				name:  "extra:" + expr,
				class: classEntropy,
				re:    re,
			})
		}
		return nil
	}
}

// WithStricterEntropy overrides the Stage 3 entropy thresholds. Per
// docs/REDACTION.md, thresholds may only be tuned stricter, never looser:
// minLen must be <= the pipeline's current minLen (a shorter minimum
// qualifies a superset of tokens) and bitsPerChar must be >= the current
// value (a higher entropy bar is the "higher entropy" half of the documented
// "lower length, higher entropy" stricter direction). At least one of the
// two must strictly tighten; supplying both unchanged is accepted as a
// no-op. Any other combination returns ErrLooserEntropy.
func WithStricterEntropy(minLen int, bitsPerChar float64) Option {
	return func(p *Pipeline) error {
		if minLen > p.minLen {
			return fmt.Errorf("%w: minLen %d looser than current %d", ErrLooserEntropy, minLen, p.minLen)
		}
		if bitsPerChar < p.bitsPerChar {
			return fmt.Errorf("%w: bitsPerChar %v looser than current %v", ErrLooserEntropy, bitsPerChar, p.bitsPerChar)
		}
		p.minLen = minLen
		p.bitsPerChar = bitsPerChar
		return nil
	}
}
