package redact

import (
	"strings"
	"testing"
)

// This file is the permanent record of an adversarial verification pass
// over the redact package (docs/REDACTION.md, CLAUDE.md P3/invariant 1/2/7).
// It probes secret shapes and edge cases NOT covered by
// test/redaction-corpus/corpus.jsonl or the other *_test.go files in this
// package, plus targeted regressions for defects found and fixed during
// that pass (see patterns.go conn-string regex comment).

// TestAdversarialNovelSecretShapes probes secret shapes NOT present in the
// checked-in corpus: unusual providers, mixed encodings, secrets at token
// boundaries, and secrets embedded in connection strings inside argv-style
// command lines. Every case with a `secret` field asserts the raw secret
// substring does not survive in the output (the load-bearing "zero raw
// leak" property, docs/REDACTION.md "The corpus method").
func TestAdversarialNovelSecretShapes(t *testing.T) {
	p := testPipeline(t)

	type tc struct {
		name   string
		input  string
		secret string // raw substring that must not survive, if any
	}

	cases := []tc{
		// 1. Discord bot token (three dot-separated base64-ish segments).
		{"discord-bot-token", "DISCORD_TOKEN=" + xs("PBsnVGMZNkM9ISIcNjsnHyYPPEYvBAYZTTdCGEQpfFZbKhwSVwNBIFoDGCBZFkcwS0tBKEJFWixLGFIlVUFWIkQeQjwVCA=="), xs("PBsnVGMZNkM9ISIcNjsnHyYPPEYvBAYZTTdCGEQpfFZbKhwSVwNBIFoDGCBZFkcwS0tBKEJFWixLGFIlVUFWIkQeQjwVCA==")},
		// 2. Twilio auth token (32 hex, contextual key= prefix).
		{"twilio-auth-token", "TWILIO_AUTH_TOKEN=ab12cd34ef56ab12cd34ef56ab12cd34", "ab12cd34ef56ab12cd34ef56ab12cd34"},
		// 3. SendGrid key (SG.<22>.<43>).
		{"sendgrid-key", "SENDGRID_API_KEY=" + xs("ISZAABwhXRFDMUdITSlESlwtQRtYJFFGL0EfQTtBQks/RlxeN08BVjpZWFo5QgdEKx8BXCgZClA7RAJZJRUGVjRAEkJl"), xs("ISZAABwhXRFDMUdITSlESlwtQRtYJFFGL0EfQTtBQks/RlxeN08BVjpZWFo5QgdEKx8BXCgZClA7RAJZJRUGVjRAEkJl")},
		// 4. HuggingFace token (hf_...).
		{"huggingface-token", xs("GgcxIE8gCzcWMhtkEiQeYAUqCSMTPRV4FTgKKQ8yTzsLN0ssDQ=="), xs("GgcxIE8gCzcWMhtkEiQeYAUqCSMTPRV4FTgKKQ8yTzsLN0ssDQ==")},
		// 5. npm token.
		{"npm-token", "//registry.npmjs.org/:_authToken=" + xs("HBEDPhxRXEZFQ0QVQV8zbyghPDQGBghHCAMfHhoDXAocBlgdEgELGw=="), xs("HBEDPhxRXEZFQ0QVQV8zbyghPDQGBghHCAMfHhoDXAocBlgdEgELGw==")},
		// 6. Datadog API key (32 hex) in argv-style flag.
		{"datadog-key", "--dd-api-key=0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"},
		// 7. Base32-encoded TOTP secret (RFC 3548 alphabet, no padding).
		{"totp-secret-base32", "otpauth_secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"},
		// 8. URL-encoded connection string password (%40 = @, %21 = !).
		{"url-encoded-connstring-pw", "postgres://svc:p%40ssW0rd%21Extra@db.example.com:5432/app", "p%40ssW0rd%21Extra"},
		// 9. AWS key with no delimiter before it (mid-flag-value join).
		{"argv-joined-flag-value", "--token " + xs("MyonIGQsPDQ/MT1jTyoqbCY1NTc=") + " extra-args-here", xs("MyonIGQsPDQ/MT1jTyoqbCY1NTc=")},
		// 10. Base64 secret embedded directly inside a JSON blob with no
		// surrounding whitespace (tests the tokenizer at a non-whitespace
		// boundary: `":"` immediately before the value).
		{"json-embedded-base64-secret", `{"api_token":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"}`, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"},
		// 11. Secret inside a connection string that itself sits inside a
		// larger argv-like command line (docker run -e style), and the
		// password itself contains a non-alphanumeric char ('&').
		{"connstring-inside-argv-like-cmd", `docker run -e DATABASE_URL="mysql://app:Tr0ub4dor&3xtra@10.1.2.3:3306/prod" myimage`, "Tr0ub4dor&3xtra"},
		// 12. Regression for the fixed conn-string bug: password itself
		// contains an '@'. A non-greedy `[^@/\s]+@` pattern stops at the
		// FIRST '@' and leaks the tail of the password in plaintext right
		// after the marker. See patterns.go conn-string pattern comment.
		{"connstring-password-contains-at-sign", "postgresql://user:Sup3rSecretPa@ssw0rdTail@host:5432/db", "ssw0rdTail"},
		// 13. Mixed-encoding: hex secret immediately followed by base64
		// secret joined with no delimiter other than a single ';'.
		{"two-blobs-semicolon-joined", "deadbeefcafebabe0123456789abcdef01234567;YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0", "deadbeefcafebabe0123456789abcdef01234567"},
		// 14. Secret at the very start of a string with no leading delimiter
		// (token boundary = start-of-string).
		{"secret-at-string-start", xs("MyonIGQsPDQ/MT1jTyoqbCY1NTc=") + " is the access key", xs("MyonIGQsPDQ/MT1jTyoqbCY1NTc=")},
		// 15. Secret at the very end of a string with no trailing delimiter.
		{"secret-at-string-end", "the access key is " + xs("MyonIGQsPDQ/MT1jTyoqbCY1NTc="), xs("MyonIGQsPDQ/MT1jTyoqbCY1NTc=")},
		// 16. GitLab personal access token (glpat-<20>): not a named
		// provider pattern, must still be caught by the entropy catch-all.
		{"gitlab-pat", "GITLAB_TOKEN=glpat-AbCdEfGhIjKlMnOpQrSt", "glpat-AbCdEfGhIjKlMnOpQrSt"},
		// 17. Firebase/Google service-account private_key field (PEM inside
		// JSON, escaped newlines).
		{"firebase-service-account-pem", `{"private_key":"-----BEGIN PRIVATE KEY-----\n` + xs("PygnJFsyJjAxMTJjOggZXAMOEDVYGVFvIj43NjQyfjstOU4cAh4hCy8GaCIuHTk3Mnw7") + `\n-----END PRIVATE KEY-----\n"}`, xs("PygnJFsyJjAxMTJjOggZXAMOEDVYGVFvIj43NjQyfjstOU4cAh4hCy8GaCIuHTk3Mnw7")},
		// 18. Env-style dump with tab-separated KEY\tVALUE (tab is a listed
		// delimiter).
		{"tab-separated-kv", "API_SECRET\tqW3rTy9uIoP1aS2dF4gH5jK6lZ7xC8vB9n", "qW3rTy9uIoP1aS2dF4gH5jK6lZ7xC8vB9n"},
		// 19. Secret wrapped in single quotes inside a shell argv string.
		{"single-quoted-secret-argv", "export TOKEN='" + xs("AQpDAEMXQggKLCpVADglWx0wLAYVPTJfET4jAAU8YhYBP2BaVA==") + "'", xs("AQpDAEMXQggKLCpVADglWx0wLAYVPTJfET4jAAU8YhYBP2BaVA==")},
		// 20. Azure SAS token style (sv=...&sig=<base64url, urlencoded
		// %2B/%2F>).
		{"azure-sas-token", "https://acct.blob.core.windows.net/c/f.txt?sv=2021-08-06&sig=abCDefGH12%2Fij34KLmn56OP%2B78qrST90uv%3D&se=2026-01-01", "abCDefGH12%2Fij34KLmn56OP%2B78qrST90uv%3D"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := string(p.Redact(c.input))
			if c.secret != "" && strings.Contains(out, c.secret) {
				t.Errorf("RAW SECRET LEAKED\n  input:  %q\n  secret: %q\n  output: %q", c.input, c.secret, out)
			}
		})
	}
}

// TestSlackWebhookURLRedacted pins a recall gap found adversarially and then
// closed: a Slack incoming-webhook URL's secret material (the workspace/
// channel/token triple after /services/) is '/'-delimited, so each segment
// individually ducked the Stage 3 entropy bar even though the combined path
// is a bearer-equivalent secret. The `slack-webhook` structural pattern
// (class slacktoken) now catches it; this test is the permanent
// red-to-green regression signal (the corpus-method loop: a miss found once
// is caught forever after — docs/REDACTION.md).
func TestSlackWebhookURLRedacted(t *testing.T) {
	p := testPipeline(t)
	// Inputs and token substrings are stored xb64-obfuscated (see xs) so no
	// literal webhook URL lands in git history / trips push protection.
	cases := []struct{ in, secret string }{
		{xs("GhUaEV5ZQF0YGhxGC0EBQQoGElwCAQwCEAoABhwQSAtAJh1bVUlCUV5RAiFfQkBFQx1IX111Mz0hKjk2OXU7NyooLSt1IDcqdTM9ISo="), xs("Kjk2OXU7NyooLSt1IDcqdTM9ISo5Njl1")},
		{xs("ERQcDQ1ON1IgOiB5WAcGWRsWQ11OBg5CCBxcAxkSThNBEUIGSgoXExgITgYcXSRFQRk6KkVhL0o7QlRWVm4pVioiR1xMSS1ATlghTRdUKFdKVCdKGUw5HRNePh8="), xs("E1AsU05QK0YVQDUbH1g6FQJcM0IKXy0f")},
	}
	for _, c := range cases {
		out := string(p.Redact(c.in))
		if out == c.in {
			t.Fatalf("Slack webhook URL not redacted: %q", c.in)
		}
		if strings.Contains(out, c.secret) {
			t.Fatalf("Slack webhook secret %q survived redaction: %q", c.secret, out)
		}
		if !strings.Contains(out, "⟦R:slacktoken:") {
			t.Fatalf("expected slacktoken-class marker in output, got %q", out)
		}
	}
}

// TestContextualAllowlistDoesNotBypassRealSecret verifies that placing a
// REAL structural secret shape inside a path segment that also happens to
// look like a git-objects/UUID allowlisted context does not suppress
// detection: the allowlist suppresses only the entropy pass, never Stage 2
// structural patterns (docs/REDACTION.md Stage 3: "Non-entropy structural
// patterns ... still apply per segment", CONTRACTS.md).
func TestContextualAllowlistDoesNotBypassRealSecret(t *testing.T) {
	p := testPipeline(t)
	cases := []struct {
		name   string
		path   string
		secret string
	}{
		{
			"aws-key-in-git-objects-shaped-segment",
			// Not a real git object (AKIA... is 20 chars, not 38/40/62/64
			// hex, and contains uppercase letters outside [0-9a-f]) but
			// placed under .git/objects/xx/ to try to ride the allowlist.
			"/repo/.git/objects/ab/" + xs("MyonIGQsPDQ/MT1jTyoqbCY1NTc="),
			xs("MyonIGQsPDQ/MT1jTyoqbCY1NTc="),
		},
		{
			"jwt-in-objects-dir",
			"/data/objects/" + xs("FxgkCU8kDBs/HDlkLRU7HCUMM0tPCxhnGQslORw8RDEXP0cmVTcmOF0uaQgYOx5FXUkXFRhKJRcAIlUkUkc1Ajw4GUNaTSEtdQwpSRxSJ1h9DyknIEUnZQs9Sng="),
			xs("FxgkCU8kDBs/HDlkLRU7HCUMM0tPCxhnGQslORw8RDEXP0cmVTcmOF0uaQgYOx5FXUkXFRhKJRcAIlUkUkc1Ajw4GUNaTSEtdQwpSRxSJ1h9DyknIEUnZQs9Sng="),
		},
		{
			"pem-header-under-commits-dir",
			"/repo/commits/-----BEGIN RSA PRIVATE KEY-----",
			"-----BEGIN RSA PRIVATE KEY-----",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := string(p.RedactPath(c.path, PathResolved))
			if strings.Contains(out, c.secret) {
				t.Errorf("contextual allowlist bypassed real structural secret\n  path: %q\n  secret: %q\n  out: %q", c.path, c.secret, out)
			}
		})
	}
}

// TestMarkerChecksumSaltedAndStable checks the salted-checksum properties: same
// secret + same salt -> same checksum; same secret + different salt ->
// different checksum; checksum is stable/deterministic across repeated calls;
// and it changes with a single-byte value change.
func TestMarkerChecksumSaltedAndStable(t *testing.T) {
	salt1 := []byte("salt-numero-uno-aaaaaaaaaaaaaaaa")
	salt2 := []byte("salt-numero-dos-bbbbbbbbbbbbbbbbb")

	c1 := markerChecksum("AKIAABCDEFGHIJKLMNO", salt1)
	c1b := markerChecksum("AKIAABCDEFGHIJKLMNO", salt1)
	if c1 != c1b {
		t.Fatalf("checksum not stable/deterministic: %x vs %x", c1, c1b)
	}

	c2 := markerChecksum("AKIAABCDEFGHIJKLMNO", salt2)
	if c1 == c2 {
		t.Errorf("checksum identical across different salts (salt not load-bearing): %x", c1)
	}

	c3 := markerChecksum("AKIAABCDEFGHIJKLMNP", salt1) // last char differs
	if c1 == c3 {
		t.Errorf("checksum identical for different values under the same salt: %x", c1)
	}

	// Empty salt must be rejected at the Pipeline level (already tested in
	// options_test.go), but markerChecksum itself must not panic on a nil
	// salt slice (defense in depth for any future internal caller).
	_ = markerChecksum("x", nil)
}

// TestMarkerChecksumNonAffine is the regression guard for the audit finding
// that the old CRC-16 marker checksum was GF(2)-affine, which let the
// per-ledger salt be recovered by linear algebra from known-plaintext markers.
// A CRC satisfies the linear identity H(a)^H(b)^H(c) == H(a^b^c) for
// equal-length inputs; a cryptographic hash does not. This asserts the
// identity is BROKEN (the checksum is not linear).
func TestMarkerChecksumNonAffine(t *testing.T) {
	a := []byte("AAAAAAAAAAAAAAAA")
	b := []byte("BBBBBBBBBBBBBBBB")
	c := []byte("CCCCCCCCCCCCCCCC")
	xor := make([]byte, len(a))
	for i := range a {
		xor[i] = a[i] ^ b[i] ^ c[i]
	}
	var salt []byte // the linearity relation over values is salt-independent
	lhs := markerChecksum(string(a), salt) ^ markerChecksum(string(b), salt) ^ markerChecksum(string(c), salt)
	rhs := markerChecksum(string(xor), salt)
	if lhs == rhs {
		t.Errorf("markerChecksum appears affine (H(a)^H(b)^H(c) == H(a^b^c) = %#08x); "+
			"a linear checksum permits salt recovery — it must be a cryptographic hash", lhs)
	}
}

// TestThresholdsCanOnlyTighten is a focused adversarial pass at
// WithStricterEntropy beyond options_test.go's coverage: a "sneaky loosen
// after a tighten" is rejected relative to the CURRENT (already-tightened)
// state, not the original default.
func TestThresholdsCanOnlyTighten(t *testing.T) {
	// Tighten once, then attempt to "tighten" back toward default — since
	// default is looser than the first tightening, this must be rejected.
	_, err := NewPipeline([]byte("salt"),
		WithStricterEntropy(10, 5.0),
		WithStricterEntropy(defaultMinLen, defaultBitsPerChar), // looser than current (10,5.0)
	)
	if err == nil {
		t.Fatal("expected error: second option loosens relative to the first tightening's resulting state")
	}
}

// TestInvalidUTF8DoesNotPanicOrLeak probes non-UTF8 byte sequences (which
// can arrive from raw kernel-captured argv/paths) mixed with a real secret,
// checking Redact does not panic and the secret still does not survive.
func TestInvalidUTF8DoesNotPanicOrLeak(t *testing.T) {
	p := testPipeline(t)
	secret := xs("MyonIGQsPDQ/MT1jTyoqbCY1NTc=")
	raw := "\xff\xfe" + secret + "\x80\x81"
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Redact panicked on invalid UTF-8: %v", r)
		}
	}()
	out := string(p.Redact(raw))
	if strings.Contains(out, secret) {
		t.Errorf("secret leaked through invalid-UTF8 wrapper: %q", out)
	}
}

// TestWindowsStylePathSegments checks a Windows-style path (backslash
// separators) does not leak a secret even though RedactPath splits on '/'
// only (per its doc comment): the backslash-joined segment still passes
// through Redact's own internal delimiter set as one longer token.
func TestWindowsStylePathSegments(t *testing.T) {
	p := testPipeline(t)
	secret := xs("MyonIGQsPDQ/MT1jTyoqbCY1NTc=")
	raw := `C:\Users\dev\config\` + secret + `\file.txt`
	out := string(p.RedactPath(raw, PathResolved))
	if strings.Contains(out, secret) {
		t.Errorf("secret leaked in backslash-separated path: %q", out)
	}
}

// TestVeryLongInputNoPanicReasonableTime is a basic DoS/robustness check: a
// pathologically long input must not panic and must complete without
// catastrophic regex backtracking.
func TestVeryLongInputNoPanicReasonableTime(t *testing.T) {
	p := testPipeline(t)
	long := strings.Repeat("a", 200000) + "=" + strings.Repeat("b", 200000)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Redact panicked on long input: %v", r)
		}
	}()
	_ = p.Redact(long)

	evil := "password=" + strings.Repeat("a", 100000) + "!"
	_ = p.Redact(evil)
}

// TestEmptyAndWhitespaceOnly checks degenerate inputs produce no false
// positives.
func TestEmptyAndWhitespaceOnly(t *testing.T) {
	p := testPipeline(t)
	for _, s := range []string{"", " ", "\t\n", "   \t  \n  "} {
		out := string(p.Redact(s))
		if out != s {
			t.Errorf("Redact(%q) = %q, want unchanged (no false positive on whitespace)", s, out)
		}
	}
}

// TestNullByteInString probes a raw NUL byte embedded next to a secret
// (kernel strings can be NUL-adjacent from fixed-size buffers).
func TestNullByteInString(t *testing.T) {
	p := testPipeline(t)
	secret := xs("MyonIGQsPDQ/MT1jTyoqbCY1NTc=")
	raw := "prefix\x00" + secret + "\x00suffix"
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Redact panicked on NUL-embedded input: %v", r)
		}
	}()
	out := string(p.Redact(raw))
	if strings.Contains(out, secret) {
		t.Errorf("secret leaked around NUL bytes: %q", out)
	}
}

// TestRedactArgvNilAndEmptySlice checks RedactArgv handles nil/empty argv
// without panicking (kernel-captured argv could legitimately be empty for
// certain exec forms).
func TestRedactArgvNilAndEmptySlice(t *testing.T) {
	p := testPipeline(t)
	if out := p.RedactArgv(nil); len(out) != 0 {
		t.Errorf("RedactArgv(nil) = %v, want empty", out)
	}
	if out := p.RedactArgv([]string{}); len(out) != 0 {
		t.Errorf("RedactArgv([]) = %v, want empty", out)
	}
}

// TestRedactPathEmptyString checks RedactPath("") doesn't panic and
// returns empty.
func TestRedactPathEmptyString(t *testing.T) {
	p := testPipeline(t)
	if out := p.RedactPath("", PathResolved); out != "" {
		t.Errorf("RedactPath(\"\") = %q, want empty", out)
	}
}

// TestMultipleSecretsSameLineDifferentClasses ensures overlap resolution
// correctly redacts N distinct secrets of different classes co-occurring on
// one line without cross-contamination or a raw leak at any boundary.
func TestMultipleSecretsSameLineDifferentClasses(t *testing.T) {
	p := testPipeline(t)
	awsKey := xs("MyonIGQsPDQ/MT1jTyoqbCY1NTc=")
	ghToken := "ghp_" + strings.Repeat("x", 36)
	jwt := xs("FxgkCU8kDBs/HDlkLRU7HCUMM0tPCxhnGQslORw8RDEXP0cmVTcmOF0uaQgYOx5FXUkXFRhKJRcAIlUkUkc1Ajw4GUNaTSEtdQwpSRxSJ1h9DyknIEUnZQs9Sng=")
	raw := "aws=" + awsKey + " gh=" + ghToken + " auth=" + jwt
	out := string(p.Redact(raw))
	for _, secret := range []string{awsKey, ghToken, jwt} {
		if strings.Contains(out, secret) {
			t.Errorf("secret %q leaked in multi-secret line: %q", secret, out)
		}
	}
}
