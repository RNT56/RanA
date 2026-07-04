package redact

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func mustPackBytes(t *testing.T, p PatternPack) []byte {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal pack: %v", err)
	}
	return b
}

// TestSignedPack_RoundTripAddsPatterns signs a pack, loads it into a Pipeline,
// and confirms its pattern redacts a value the built-in set would miss, while
// leaving a benign near-miss alone (additive, not a wildcard).
func TestSignedPack_RoundTripAddsPatterns(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// A fictional provider format not in the built-in set.
	pack := PatternPack{
		Version:  PackFormatVersion,
		Name:     "test-provider",
		Patterns: []string{`\bZZP-[A-Z0-9]{20}\b`},
	}
	body := mustPackBytes(t, pack)
	sig := SignPack(body, priv)

	opt, err := VerifyAndLoadPack(body, sig, pub)
	if err != nil {
		t.Fatalf("VerifyAndLoadPack: %v", err)
	}
	p, err := NewPipeline(auditSalt, opt)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}

	const secret = "ZZP-ABCDE12345FGHIJ6789"
	out := string(p.Redact("apitoken " + secret + " end"))
	if strings.Contains(out, secret) {
		t.Errorf("pack pattern did not redact %q: %q", secret, out)
	}
	// A benign value that does not match the pack pattern is untouched.
	if got := string(p.Redact("just a normal sentence")); got != "just a normal sentence" {
		t.Errorf("pack over-redacted benign text: %q", got)
	}
}

// TestSignedPack_RejectsTamperedBodyAndSig is the load-bearing guard: a pack
// whose body or signature was altered must NOT load.
func TestSignedPack_RejectsTamperedBodyAndSig(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := mustPackBytes(t, PatternPack{Version: PackFormatVersion, Patterns: []string{`\bAAA[0-9]{8}\b`}})
	sig := SignPack(body, priv)

	// Tampered body (attacker adds a wildcard-ish pattern) with the original sig.
	tampered := mustPackBytes(t, PatternPack{Version: PackFormatVersion, Patterns: []string{`.*`}})
	if _, err := VerifyAndLoadPack(tampered, sig, pub); err == nil {
		t.Error("tampered pack body must be rejected")
	}
	// Tampered signature.
	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0xFF
	if _, err := VerifyAndLoadPack(body, badSig, pub); err == nil {
		t.Error("tampered signature must be rejected")
	}
	// Wrong key.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifyAndLoadPack(body, sig, otherPub); err == nil {
		t.Error("a pack signed by a different key must be rejected")
	}
}

// TestSignedPack_RejectsBadInputs covers version mismatch, malformed JSON,
// invalid regex, and a truncated public key.
func TestSignedPack_RejectsBadInputs(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Wrong version.
	body := mustPackBytes(t, PatternPack{Version: 99, Patterns: nil})
	if _, err := VerifyAndLoadPack(body, SignPack(body, priv), pub); err == nil {
		t.Error("wrong pack version must be rejected")
	}

	// Malformed JSON (still correctly signed).
	junk := []byte(`{not json`)
	if _, err := VerifyAndLoadPack(junk, SignPack(junk, priv), pub); err == nil {
		t.Error("malformed pack body must be rejected")
	}

	// Invalid regex: WithExtraPatterns (applied at NewPipeline) must reject it.
	badRe := mustPackBytes(t, PatternPack{Version: PackFormatVersion, Patterns: []string{`[unterminated`}})
	opt, err := VerifyAndLoadPack(badRe, SignPack(badRe, priv), pub)
	if err != nil {
		t.Fatalf("verify (regex checked at pipeline build): %v", err)
	}
	if _, err := NewPipeline(auditSalt, opt); err == nil {
		t.Error("a pack with an invalid regex must fail pipeline construction")
	}

	// Truncated public key.
	if _, err := VerifyAndLoadPack(body, SignPack(body, priv), pub[:16]); err == nil {
		t.Error("a truncated public key must be rejected")
	}
}
