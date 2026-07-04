package redact

import (
	"strings"
	"testing"
)

// auditSalt is a fixed salt for the audit regression cases; the value of the
// CRC is irrelevant to these tests (they check presence/absence of the raw
// secret in the output, not the marker bytes).
var auditSalt = []byte("audit-regression-fixed-salt-not-for-prod")

func auditPipeline(t *testing.T) *Pipeline {
	t.Helper()
	p, err := NewPipeline(auditSalt)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	return p
}

// TestAuditRegression_StructuralSecretsRedacted covers the confirmed
// recall-gap findings from the redaction end-to-end audit: each input carries
// a secret substring that MUST NOT survive in the output. These are permanent
// regression guards — a real secret reaching the output here is a build
// failure.
func TestAuditRegression_StructuralSecretsRedacted(t *testing.T) {
	p := auditPipeline(t)
	cases := []struct {
		name   string
		input  string
		secret string // exact substring that must be absent from output
	}{
		// kv-keyword-list-too-narrow: labelled short/low-entropy credentials.
		{"passphrase", "passphrase=hunter2forever", "hunter2forever"},
		{"credential", "credential=abc123def", "abc123def"},
		{"pin-kv", "pin=4829", "4829"},
		{"otp-kv", "otp: 583920", "583920"},
		{"access_code", "access_code=A1B2C3", "A1B2C3"},
		{"authkey", "authkey=zzTopSecretVal", "zzTopSecretVal"},
		{"client_secret", "client_secret=GOCSPX-abcDEF123ghi", "GOCSPX-abcDEF123ghi"},
		{"passcode", "passcode=778812", "778812"},

		// conn-string-scheme-required + mongodb-srv-plus-scheme-fragility.
		{"redis-empty-user", "redis://:s3cr3tAuthPass@10.0.0.1:6379", "s3cr3tAuthPass"},
		{"mongodb-srv", "mongodb+srv://dbuser:MyMongoPw9@cluster0.mongodb.net", "MyMongoPw9"},
		{"oci8-scheme", "oci8://scott:tigerpw@dbhost/orcl", "tigerpw"},
		{"pg-with-port", "postgres://u:P%40ssw0rd@db.host:5432/app", "P%40ssw0rd"},
		// semicolon connection string via the KV keyword (Password=).
		{"ado-semicolon", "Server=h;Database=d;Password=Sq1SecretPw;Trusted=no", "Sq1SecretPw"},

		// numeric-secrets: Luhn-valid test PANs (publicly documented test
		// numbers) and long numeric account values.
		{"card-pure", "card 4242424242424242 exp", "4242424242424242"},
		{"card-grouped", "pan 4000 0566 5566 5556 cvv", "4000 0566 5566 5556"},
		{"long-account", "acct=123456789012345678", "123456789012345678"},

		// short/sub-32 high-entropy tokens (entropy recalibration).
		{"hex-24", "tok 7dcef58168aa53f9d9a06afe end", "7dcef58168aa53f9d9a06afe"},
		{"hex-16", "id a1b2c3d4e5f60718 x", "a1b2c3d4e5f60718"},
		// dotted-dilution: a hex secret glued to benign labels by '.' must
		// still be caught now that '.' is a token delimiter.
		{"dotted-dilution", "cache.7dcef58168aa53f9d9a06afe.tmp", "7dcef58168aa53f9d9a06afe"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := string(p.Redact(c.input))
			if strings.Contains(out, c.secret) {
				t.Errorf("secret %q survived redaction of %q -> %q", c.secret, c.input, out)
			}
		})
	}
}

// TestAuditRegression_ArgvSplitCredential covers split-across-argv-and-path:
// a credential flag and its value split across two argv elements
// (["--password", "s3cr3t"]) must not leak the value element, and the
// redaction must be idempotent.
func TestAuditRegression_ArgvSplitCredential(t *testing.T) {
	p := auditPipeline(t)
	argv := []string{"mysql", "--user", "admin", "--password", "S3cr3tPass", "--token", "aB9xTokenVal"}
	out := p.RedactArgv(argv)

	joined := ""
	for _, r := range out {
		joined += string(r) + " "
	}
	for _, secret := range []string{"S3cr3tPass", "aB9xTokenVal"} {
		if strings.Contains(joined, secret) {
			t.Errorf("argv credential value %q leaked: %v", secret, out)
		}
	}
	// Benign operands must survive: "admin" follows "--user" (not a credential
	// flag), and the flags/command themselves are untouched.
	if string(out[2]) != "admin" {
		t.Errorf("benign operand over-redacted: --user value = %q, want admin", out[2])
	}
	if string(out[0]) != "mysql" {
		t.Errorf("command element changed: %q", out[0])
	}

	// Idempotency: redacting the already-redacted argv must be a no-op.
	again := p.RedactArgv(stringsOf(out))
	for i := range out {
		if string(out[i]) != string(again[i]) {
			t.Errorf("RedactArgv not idempotent at %d: %q -> %q", i, out[i], again[i])
		}
	}
}

func stringsOf(rs []Redacted) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return out
}

// TestAuditRegression_StricterEntropyZeroValue covers the option zero-value
// coupling finding: a profile that tightens only ONE of (minLen, threshold)
// passes 0 for the other, which must be treated as "leave unchanged" — never
// collapsing the length gate to 0 and never failing construction.
func TestAuditRegression_StricterEntropyZeroValue(t *testing.T) {
	// Only minLen tightened; threshold=0 must NOT fail as "looser".
	p1, err := NewPipeline(auditSalt, WithStricterEntropy(16, 0))
	if err != nil {
		t.Fatalf("WithStricterEntropy(16, 0) failed: %v", err)
	}
	if p1.minLen != 16 || p1.bitsPerChar != defaultBitsPerChar {
		t.Errorf("minLen=%d bitsPerChar=%v, want 16 and %v (threshold unchanged)", p1.minLen, p1.bitsPerChar, defaultBitsPerChar)
	}

	// Only threshold tightened; minLen=0 must NOT collapse the length gate.
	p2, err := NewPipeline(auditSalt, WithStricterEntropy(0, 5.0))
	if err != nil {
		t.Fatalf("WithStricterEntropy(0, 5.0) failed: %v", err)
	}
	if p2.minLen != defaultMinLen || p2.bitsPerChar != 5.0 {
		t.Errorf("minLen=%d bitsPerChar=%v, want %d (unchanged) and 5.0", p2.minLen, p2.bitsPerChar, defaultMinLen)
	}

	// A genuinely looser threshold is still rejected.
	if _, err := NewPipeline(auditSalt, WithStricterEntropy(0, 3.0)); err == nil {
		t.Error("WithStricterEntropy(0, 3.0) should be rejected as looser than the 4.0 default")
	}
}

// TestAuditRegression_PathProvenanceGatesAllowlist covers the path-context
// allowlist blind spot, resolved via kernel provenance: the SAME
// hash-shaped path segment is spared when the path is kernel-RESOLVED (a real
// content hash, must not be shredded) but REDACTED when the path is
// agent-CLAIMED (a segment an attacker crafted to smuggle a secret past
// redaction). This is what makes the allowlist safe without the ~18% precision
// loss that tightening its shape rules would cause.
func TestAuditRegression_PathProvenanceGatesAllowlist(t *testing.T) {
	p := auditPipeline(t)
	// A 40-hex segment under an "objects" directory — indistinguishable by
	// shape from a real git/nix content hash.
	const hexSecret = "deadbeefcafebabe0123456789abcdef01234567"
	path := "/tmp/cache/objects/" + hexSecret

	// Resolved: the kernel vouches this file exists here → allowlisted, spared.
	if out := string(p.RedactPath(path, PathResolved)); out != path {
		t.Errorf("resolved content-hash path should be spared, got %q", out)
	}
	// Claimed: agent-influenced → no allowlist → the crafted secret is redacted.
	out := string(p.RedactPath(path, PathClaimed))
	if strings.Contains(out, hexSecret) {
		t.Errorf("claimed crafted-hash secret leaked: %q", out)
	}
	if out == path {
		t.Errorf("claimed crafted-hash path was not redacted at all: %q", out)
	}

	// The zero value of PathTrust is the safe default (PathClaimed): a caller
	// that forgets to vouch for provenance gets the stricter behavior.
	var zero PathTrust
	if zero != PathClaimed {
		t.Errorf("zero-value PathTrust = %d, want PathClaimed (safe default)", zero)
	}
}

// TestAuditRegression_PEMBlockFullyRedacted covers pem-body-tail-line-leaks:
// the entire private-key block (including the short final wrapped line) must
// be redacted, not just the BEGIN header.
func TestAuditRegression_PEMBlockFullyRedacted(t *testing.T) {
	p := auditPipeline(t)
	// A synthetic PEM with a deliberately SHORT final body line — the exact
	// shape that leaked when only the header was matched.
	pem := "-----BEGIN EC PRIVATE KEY-----\n" +
		"MHcCAQEEIQDwZ1Yg3nHkQ2vN8xR4tLpM6sK9jF3hG7bV5cW1nZ0aQoAoGCCqGSM49\n" +
		"AwEHoUQDQgAEkQ2vN8xR4tLpM6sK9jF3hG7bV5cW1nZ0\n" +
		"kQ2vN8xR4t==\n" +
		"-----END EC PRIVATE KEY-----"
	out := string(p.Redact(pem))
	for _, frag := range []string{"MHcCAQEEIQDw", "kQ2vN8xR4t==", "AwEHoUQDQgAE"} {
		if strings.Contains(out, frag) {
			t.Errorf("PEM key-material fragment %q survived: %q", frag, out)
		}
	}
}

// TestAuditRegression_BenignNotOverRedacted guards precision: these benign
// strings must pass through unchanged. A regression here means the broadened
// rules over-redact and destroy forensic value.
func TestAuditRegression_BenignNotOverRedacted(t *testing.T) {
	p := auditPipeline(t)
	cases := []struct {
		name  string
		input string
	}{
		{"spin-not-pin", "spin=fast"},           // must not match KV via "pin"
		{"benign-url", "http://example.com/a"},  // no credentials
		{"short-number", "count=12345"},         // 5-digit benign number
		{"benign-13-digit", "id 1234567890123"}, // 13 digits, not Luhn card
		{"version-str", "version=1.2.3"},
		{"plain-word", "password rotation policy"}, // prose, no assignment
		// dotted FQDN: must tokenize into benign labels and survive whole, so
		// the qname a net.dns/net.connect event records is not destroyed.
		{"fqdn", "internal-service.prod.us-east-1.example.com"},
		{"repeated-hex-run", "aaaaaaaaaaaaaaaa"}, // 16 hex chars but ~0 entropy (Shannon floor spares it)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := string(p.Redact(c.input))
			if out != c.input {
				t.Errorf("benign input over-redacted: %q -> %q", c.input, out)
			}
		})
	}
}
