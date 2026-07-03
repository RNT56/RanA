package redact

import (
	"strings"
	"testing"
)

// TestStructuralWinsOverLongerEntropySpan verifies the documented overlap
// rule: "structural class wins over entropy" when both a structural pattern
// and the entropy pass are eligible to claim overlapping text. Uses an
// unbounded-length structural pattern (Anthropic key, `{20,}`) glued to
// trailing high-entropy characters with no delimiter, so the structural
// regex's own match is free to extend across the whole run and its `\b`
// trailing boundary is satisfiable — isolating the overlap-priority rule
// from the separate word-boundary/fixed-length gap covered by
// TestFixedLengthStructuralPatternLosesClassWhenGluedNoLeak below.
func TestStructuralWinsOverLongerEntropySpan(t *testing.T) {
	p := testPipeline(t)
	in := "sk-ant-abcdefghijklmnopqrstuvwx1234suffixmoreentropyhere"
	out := string(p.Redact(in))
	if strings.Contains(out, "sk-ant-abcdefghijklmnopqrstuvwx1234suffixmoreentropyhere") {
		t.Errorf("raw Anthropic key leaked despite structural-wins rule: %q", out)
	}
	m := markerRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no marker found: %q", out)
	}
	if m[1] != classAnthropicKey {
		t.Errorf("marker class = %q, want %q: out=%q", m[1], classAnthropicKey, out)
	}
}

// TestFixedLengthStructuralPatternLosesClassWhenGluedNoLeak documents a
// real, narrow classification-precision gap found during adversarial
// testing: the AWS-key and GCP-key structural patterns use a FIXED-count
// quantifier (`{16}`, `{35}`) with a trailing `\b` boundary. If the real
// key is directly glued (no delimiter) to more word characters on the
// right — e.g. a key embedded mid-token in some larger blob — the trailing
// `\b` cannot match (no transition between two \w characters), so the
// structural pattern silently fails to fire at that position.
//
// This does NOT leak the raw secret: the whole glued run still clears the
// Stage 3 entropy bar and is redacted (recall is preserved), but the
// redaction marker's class is "entropy" rather than "awskey"/"gcpkey" — a
// precision/labeling gap, not a P3 confidentiality violation. Documented
// here rather than silently fixed because widening the AWS/GCP patterns to
// `{16,}`/`{35,}` (matching the unbounded style used by every other
// provider pattern) is a structural change to a security-relevant regex
// that deserves its own reviewed change, not a drive-by edit during
// verification.
func TestFixedLengthStructuralPatternLosesClassWhenGluedNoLeak(t *testing.T) {
	p := testPipeline(t)
	awsKey := "AKIAIOSFODNN7EXAMPLE"
	in := awsKey + "zZ9xQ7mK2pL8vN4wT6yU1" // glued, no delimiter
	out := string(p.Redact(in))
	if strings.Contains(out, awsKey) {
		t.Fatalf("raw AWS key leaked: %q", out)
	}
	m := markerRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("expected a redaction marker (entropy catch-all) even though structural class is lost: %q", out)
	}
	t.Logf("KNOWN GAP (tracked, not fixed): glued AWS key redacted via class %q instead of %q (no raw leak; recall preserved)", m[1], classAWSKey)
}
