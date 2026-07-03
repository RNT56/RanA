package profile

import (
	"errors"
	"fmt"

	"github.com/RNT56/RanA/internal/redact"
)

// Named validation errors (docs/PROFILES.md: "A profile that tries [to
// loosen] is rejected at load with a named error."). Wrap these with %w so
// callers can errors.Is against a specific failure kind.
var (
	// ErrMissingProfileSection is returned when a pack has no [profile]
	// table at all.
	ErrMissingProfileSection = errors.New("profile: missing [profile] section")
	// ErrMissingName is returned when [profile].name is empty or absent.
	ErrMissingName = errors.New("profile: [profile].name is required")
	// ErrCaptureDisabled is returned when a profile sets capture=false for
	// exec, network_connect, or sensitive-read — the D7 baseline classes
	// docs/PROFILES.md freezes as always-on.
	ErrCaptureDisabled = errors.New("profile: exec/network_connect/sensitive-read capture cannot be disabled")
	// ErrLooserEntropy is returned when [redaction] requests entropy
	// thresholds looser than docs/REDACTION.md's defaults.
	ErrLooserEntropy = errors.New("profile: entropy thresholds must be stricter than default, never looser")
	// ErrInvalidPattern is returned when an extra_patterns regex fails to
	// compile.
	ErrInvalidPattern = errors.New("profile: invalid extra_patterns regex")
	// ErrInvalidGlob is returned when a digest/sensitive_read glob is
	// malformed.
	ErrInvalidGlob = errors.New("profile: invalid glob pattern")
	// ErrInvalidTimelineLens is returned when [timeline].lens is set to a
	// value other than "tree" or "causality".
	ErrInvalidTimelineLens = errors.New("profile: timeline lens must be \"tree\" or \"causality\"")
	// ErrInvalidRetention is returned when [retention].ttl_days is negative.
	ErrInvalidRetention = errors.New("profile: retention ttl_days must be >= 0")
	// ErrMarkerForbiddenField is returned when carry_fields allowlists a
	// field on the permanent P7 denylist (message/prompt/completion text
	// and friends) — belt-and-suspenders enforced at validate time, not
	// only at runtime ingest.
	ErrMarkerForbiddenField = errors.New("profile: marker carry_fields includes a permanently forbidden field")
)

// forbiddenMarkerFields is the permanent P7 denylist: no profile, however
// authored, may allowlist any of these into carry_fields. This is enforced
// independent of (and in addition to) each profile's own forbid_fields.
var forbiddenMarkerFields = []string{
	"text", "prompt", "completion", "message", "content", "summary",
}

func isForbiddenMarkerField(f string) bool {
	for _, b := range forbiddenMarkerFields {
		if f == b {
			return true
		}
	}
	return false
}

// validate applies the additive-only invariants (docs/PROFILES.md) to a
// parsed Profile. doc is the decoded TOML document, used to distinguish "key
// absent" from "key explicitly false" for the capture freeze check (the DTO
// carries [capture] booleans as *bool for exactly this reason).
func validate(doc *decodeDoc, p *Profile) error {
	if err := validateCapture(doc); err != nil {
		return err
	}
	if err := validateEntropy(p); err != nil {
		return err
	}
	if err := validateExtraPatterns(p); err != nil {
		return err
	}
	if err := validateGlobs(p); err != nil {
		return err
	}
	if err := validateTimeline(p); err != nil {
		return err
	}
	if p.Retention.TTLDays < 0 {
		return fmt.Errorf("%w: got %d", ErrInvalidRetention, p.Retention.TTLDays)
	}
	if err := validateMarkers(p); err != nil {
		return err
	}
	return nil
}

// validateCapture rejects capture=false for the three classes
// docs/PROFILES.md freezes as always-on: exec, network_connect, and
// sensitive-read. Sensitive-read has no [capture] toggle at all (it is
// controlled solely by the watchlist, additive-only by construction), so
// only exec and network_connect need an explicit key check here. A nil *bool
// means the key was absent (defaults on, allowed); only an explicit
// "= false" is rejected.
func validateCapture(doc *decodeDoc) error {
	if p := doc.Capture.Exec; p != nil && !*p {
		return fmt.Errorf("%w: capture.exec", ErrCaptureDisabled)
	}
	if p := doc.Capture.NetworkConnect; p != nil && !*p {
		return fmt.Errorf("%w: capture.network_connect", ErrCaptureDisabled)
	}
	return nil
}

// validateEntropy confirms [redaction] entropy overrides, if present, are
// stricter than the redact package's own defaults — by attempting the same
// WithStricterEntropy call the ledger/collector will make at runtime, so
// this check can never drift from the real enforcement point.
func validateEntropy(p *Profile) error {
	if p.Redaction.EntropyMinLen == 0 && p.Redaction.EntropyThreshold == 0 {
		return nil // not set
	}
	minLen := p.Redaction.EntropyMinLen
	bits := p.Redaction.EntropyThreshold
	if minLen == 0 {
		minLen = defaultEntropyMinLen
	}
	if bits == 0 {
		bits = defaultEntropyBitsPerChar
	}
	_, err := redact.NewPipeline(validationSalt, redact.WithStricterEntropy(minLen, bits))
	if err != nil {
		if errors.Is(err, redact.ErrLooserEntropy) {
			return fmt.Errorf("%w: %v", ErrLooserEntropy, err)
		}
		return err
	}
	return nil
}

// validationSalt is a fixed, non-secret salt used only to construct a
// throwaway redact.Pipeline for validating a profile's entropy/pattern
// overrides at parse time. It is never used to redact real data.
var validationSalt = []byte("rana-profile-validation-salt")

// defaultEntropyMinLen and defaultEntropyBitsPerChar mirror
// docs/REDACTION.md Stage 3's defaults (20 chars, 4.0 bits/char), used only
// to fill in the "other" threshold when a profile sets just one of the two
// [redaction] entropy fields.
const (
	defaultEntropyMinLen      = 20
	defaultEntropyBitsPerChar = 4.0
)

// validateExtraPatterns confirms every [redaction].extra_patterns regex
// compiles, by handing them to redact.WithExtraPatterns — the same
// construction the runtime pipeline uses.
func validateExtraPatterns(p *Profile) error {
	if len(p.Redaction.ExtraPatterns) == 0 {
		return nil
	}
	_, err := redact.NewPipeline(validationSalt, redact.WithExtraPatterns(p.Redaction.ExtraPatterns))
	if err != nil {
		if errors.Is(err, redact.ErrInvalidPattern) {
			return fmt.Errorf("%w: %v", ErrInvalidPattern, err)
		}
		return err
	}
	return nil
}

// validateGlobs confirms every glob pattern the profile supplies (digest
// scopes/exclude, sensitive_read extra) compiles under compileGlob
// (glob.go).
func validateGlobs(p *Profile) error {
	all := make([]string, 0, len(p.Digest.Scopes)+len(p.Digest.Exclude)+len(p.SensitiveRead.Extra))
	all = append(all, p.Digest.Scopes...)
	all = append(all, p.Digest.Exclude...)
	all = append(all, p.SensitiveRead.Extra...)
	for _, g := range all {
		if _, err := compileGlob(g); err != nil {
			return fmt.Errorf("%w: %q: %v", ErrInvalidGlob, g, err)
		}
	}
	return nil
}

func validateTimeline(p *Profile) error {
	switch p.Timeline.Lens {
	case "", "tree", "causality":
		return nil
	default:
		return fmt.Errorf("%w: got %q", ErrInvalidTimelineLens, p.Timeline.Lens)
	}
}

// validateMarkers enforces the permanent P7 denylist against carry_fields
// regardless of what the profile author put in forbid_fields.
func validateMarkers(p *Profile) error {
	for _, f := range p.Markers.CarryFields {
		if isForbiddenMarkerField(f) {
			return fmt.Errorf("%w: %q", ErrMarkerForbiddenField, f)
		}
	}
	return nil
}
