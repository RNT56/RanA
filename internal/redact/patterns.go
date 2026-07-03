package redact

import "regexp"

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
		{name: "pem-header", class: classPEM, re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`)},
		{name: "bearer-header", class: classBearer, re: regexp.MustCompile(`(?i)authorization:\s*bearer\s+\S+`)},

		// Generic inline credentials (catch-all; class=entropy per the
		// closed §4 enum — see const block doc comment above).
		{name: "generic-credential-kv", class: classEntropy, re: regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*(\S+)`), group: 1},
		// The password segment is matched greedily up to the LAST '@' before
		// the end of the authority component (i.e. up to the next '/' or
		// whitespace, not the first '@'). Passwords legitimately contain '@'
		// (e.g. "user:Pa@ssw0rd@host:5432/db"); a non-greedy
		// `[^@/\s]+@` here would stop at the first '@' and leak the raw
		// password tail in plaintext immediately after the marker — a P3
		// violation caught by adversarial testing (raw secret bytes must
		// never reach the output).
		{name: "conn-string", class: classConnString, re: regexp.MustCompile(`[a-z]+://([^:/\s]+:[^/\s]+@)`), group: 1},
	}
}
