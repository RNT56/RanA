package redact

import "regexp"

// luhnValid reports whether the digit string d (already stripped of any
// separators) satisfies the Luhn checksum, the check every real credit-card
// PAN passes. It is used to keep the numeric-card pattern high-precision: a
// 13-19 digit run is only treated as a card if it actually checks out, so
// benign long numbers (IDs, counters) are not redacted by that rule.
func luhnValid(d string) bool {
	if len(d) < 12 {
		return false
	}
	var sum int
	alt := false
	for i := len(d) - 1; i >= 0; i-- {
		c := d[i]
		if c < '0' || c > '9' {
			return false
		}
		n := int(c - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// onlyDigits returns s with every non-digit byte removed. Used to normalize a
// separated card number ("4539 1488 0343 6467") before Luhn validation.
func onlyDigits(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

// isCardNumber validates a possibly-separated 13-19 digit run as a Luhn-valid
// payment card number (the numeric-card pattern's validator).
func isCardNumber(match string) bool {
	d := onlyDigits(match)
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	return luhnValid(d)
}

// Class labels per docs/REDACTION.md §4. This set is FROZEN and closed:
// "class ∈ { awskey, gcpkey, openaikey, anthropickey, ghtoken, slacktoken,
// stripekey, jwt, pem, bearer, connstring, entropy }". Structural patterns
// for providers not named in §4 (Azure, Google OAuth) are folded into the
// nearest existing bucket rather than inventing a new class:
//   - Azure storage/connection-string secrets -> connstring (same shape:
//     a credential embedded in a connection-string-style KEY=value pair).
//   - Google OAuth bearer tokens (ya29.*) -> gcpkey (same provider family
//     as the GCP API key pattern).
//   - Generic "password=/secret:/token=/api_key=" inline credentials with
//     no more specific provider shape -> entropy (a credential-shaped value
//     was found structurally, but it isn't attributable to a named
//     provider; entropy is the documented catch-all class).
const (
	classAWSKey       = "awskey"
	classGCPKey       = "gcpkey"
	classOpenAIKey    = "openaikey"
	classAnthropicKey = "anthropickey"
	classGHToken      = "ghtoken"
	classSlackToken   = "slacktoken"
	classStripeKey    = "stripekey"
	classJWT          = "jwt"
	classPEM          = "pem"
	classBearer       = "bearer"
	classConnString   = "connstring"
	classEntropy      = "entropy"
)

// pattern is one compiled structural rule. group, when > 0, identifies a
// capture group whose span (rather than the whole match) is the redaction
// target — used for connection strings (user:pass@) and generic KEY=value
// assignments (the value only).
type pattern struct {
	name  string
	class string
	re    *regexp.Regexp
	// group selects which submatch span to redact; 0 means "the whole match".
	group int
	// validate, when non-nil, is called with the candidate span text; the
	// match is discarded if it returns false. This lets a structurally-shaped
	// rule (e.g. a 13-19 digit run) add a semantic check (Luhn) so it stays
	// high-precision — a regex alone cannot express "and it passes Luhn".
	validate func(string) bool
}

// builtinPatterns returns RanA's built-in structural pattern set, ordered as
// documented (cheap/high-precision first). The set is additive-only: callers
// may append extra patterns (see Option WithExtraPatterns) but must never
// remove entries from this slice.
func builtinPatterns() []pattern {
	return []pattern{
		// Cloud / provider keys.
		{name: "aws-access-key", class: classAWSKey, re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
		{name: "aws-secret-contextual", class: classAWSKey, re: regexp.MustCompile(`(?i)(?:aws_secret(?:_access_key)?|SecretAccessKey)\s*[=:]\s*['"]?([A-Za-z0-9/+]{40})['"]?`), group: 1},
		{name: "gcp-api-key", class: classGCPKey, re: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
		{name: "azure-connstring-secret", class: classConnString, re: regexp.MustCompile(`(?i)(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{20,}`)},
		// Anthropic keys are more specific than the generic OpenAI "sk-"
		// shape, so they must be tried first (leftmost-longest at the
		// pattern-set level: the more specific/longer prefix wins).
		{name: "anthropic-key", class: classAnthropicKey, re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9\-]{20,}\b`)},
		{name: "openai-key", class: classOpenAIKey, re: regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`)},
		{name: "github-token", class: classGHToken, re: regexp.MustCompile(`\bgh[posru]_[A-Za-z0-9]{36,}\b`)},
		{name: "slack-token", class: classSlackToken, re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
		// Slack incoming-webhook URLs are bearer-equivalent secrets whose
		// '/'-delimited segments individually duck the entropy bar; found
		// adversarially (see the corresponding regression test) and closed
		// here. The workspace/channel/token triple is the secret span.
		{name: "slack-webhook", class: classSlackToken, re: regexp.MustCompile(`\bhooks\.slack\.com/services/([A-Z0-9]{5,16}/[A-Z0-9]{5,16}/[A-Za-z0-9]{16,})`), group: 1},
		{name: "stripe-key", class: classStripeKey, re: regexp.MustCompile(`\b[sr]k_live_[A-Za-z0-9]{24,}\b`)},
		{name: "google-oauth", class: classGCPKey, re: regexp.MustCompile(`\bya29\.[0-9A-Za-z\-_]+`)},

		// Tokens & structured secrets.
		{name: "jwt", class: classJWT, re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)},
		// Redact the ENTIRE private-key block (BEGIN..END), not just the
		// header line. The header-only rule left the base64 body to the
		// entropy pass, whose per-line tokenization leaks the short final
		// wrapped line (< the blob floor) in cleartext — a key-material leak.
		// (?s) makes '.' cross newlines; non-greedy stops at the first END.
		{name: "pem-block", class: classPEM, re: regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)},
		// Fallback: a BEGIN delimiter with no matching END (truncated capture)
		// still gets its header redacted so the block is never silently
		// treated as ordinary text.
		{name: "pem-header", class: classPEM, re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)},
		{name: "bearer-header", class: classBearer, re: regexp.MustCompile(`(?i)authorization:\s*bearer\s+\S+`)},

		// Payment-card numbers: a 13-19 digit run (optionally single-space or
		// single-dash separated) that passes Luhn. The validator keeps this
		// high-precision — benign long numbers are not redacted unless they
		// actually check out as a card. Class=entropy per the closed §4 enum.
		{name: "numeric-card", class: classEntropy, re: regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`), validate: isCardNumber},
		// Long pure-digit runs (>= 16 digits with no separators) — account
		// numbers, non-Luhn PANs, long numeric secrets. 16+ consecutive
		// digits are effectively never benign in captured argv/prose (event
		// timestamps are numeric FIELDS, not redacted strings), and
		// over-redacting a raw long number is the safe direction.
		{name: "numeric-long", class: classEntropy, re: regexp.MustCompile(`\b\d{16,}\b`)},

		// Generic inline credentials (catch-all; class=entropy per the closed
		// §4 enum — see const block doc comment above). The keyword set is
		// broad on purpose: a labelled credential whose value is short or
		// low-entropy (the case the entropy net misses) must still be caught by
		// its own key. These "strong" keywords are unambiguous enough to match
		// as a substring, so compound keys like "otpauth_secret=", "x_api_key="
		// and camelCase "MyPassword=" are caught (matching a real credential is
		// more important than the rare benign word that ends in one of these).
		// The value stops at whitespace and the structural separators ';' and
		// '&' (connection-string / URL-query delimiters) so "Password=p;Host=h"
		// and "token=abc&next=/home" redact only the secret, not the trailing
		// benign key=value that follows it.
		{name: "generic-credential-kv", class: classEntropy, re: regexp.MustCompile(`(?i)(?:passphrase|password|passwd|passcode|secret[_-]?key|secret|client[_-]?secret|private[_-]?key|api[_-]?key|apikey|access[_-]?key|access[_-]?token|access[_-]?code|auth[_-]?token|auth[_-]?key|authkey|bearer[_-]?token|credentials?|token)\s*[=:]\s*['"]?([^\s;&'"]+)`), group: 1},
		// Short/ambiguous credential keys (pwd, pin, otp) that ARE common
		// substrings of benign words ("spin", "crypto"): require a leading
		// non-alphanumeric boundary so "pin=" / "user_pin=" / " otp:" match but
		// "spin=fast" does not. Catches short numeric PIN/OTP values that no
		// other rule sees (the entropy net cannot, by design, catch a bare
		// 4-6 digit value). group 1 is the value.
		{name: "short-credential-kv", class: classEntropy, re: regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:pwd|pin|otp)\s*[=:]\s*['"]?([^\s;&'"]+)`), group: 1},
		// The password segment is matched greedily up to the LAST '@' before
		// the end of the authority component (i.e. up to the next '/' or
		// whitespace, not the first '@'). Passwords legitimately contain '@'
		// (e.g. "user:Pa@ssw0rd@host:5432/db"); a non-greedy `[^@/\s]+@` here
		// would stop at the first '@' and leak the raw password tail in
		// plaintext immediately after the marker — a P3 violation caught by
		// adversarial testing (raw secret bytes must never reach the output).
		// The scheme allows digits/'+' after the first letter (mongodb+srv,
		// s3, oci8), and the username may be EMPTY so redis-style
		// "redis://:pass@host" (no user) is still caught.
		{name: "conn-string", class: classConnString, re: regexp.MustCompile(`[a-z][a-z0-9+.\-]*://([^:/\s@]*:[^/\s]+@)`), group: 1},
	}
}
