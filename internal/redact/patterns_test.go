package redact

import "testing"

func TestBuiltinPatternsCompile(t *testing.T) {
	pats := builtinPatterns()
	if len(pats) == 0 {
		t.Fatal("expected non-empty builtin pattern set")
	}
	seen := make(map[string]bool)
	for _, p := range pats {
		if p.class == "" {
			t.Errorf("pattern %q has empty class", p.name)
		}
		if p.re == nil {
			t.Errorf("pattern %q has nil regexp", p.name)
		}
		if seen[p.name] {
			t.Errorf("duplicate pattern name %q", p.name)
		}
		seen[p.name] = true
	}
}

func TestStructuralPatternMatches(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantClass string
		wantMatch string // exact substring expected to match (empty = don't check)
	}{
		{"aws-access-key", xs("MyonIGQsPDQ/MT1jTyoqbCY1NTc="), classAWSKey, xs("MyonIGQsPDQ/MT1jTyoqbCY1NTc=")},
		{"aws-access-key-asia", xs("MzInIGQsPDQ/MT1jTyoqbCY1NTc="), classAWSKey, xs("MzInIGQsPDQ/MT1jTyoqbCY1NTc=")},
		{"gcp-api-key", xs("MygUAH4aK19JASBfEwpFHzsKDCMsACx1Tg5FFS8gekgFGWsmJy4r"), classGCPKey, ""},
		{"openai-key", xs("AQpDAE8ACxcWEhtEEgQeQAUKCQMTHRVYFRgKQUdAGQ=="), classOpenAIKey, ""},
		{"anthropic-key", xs("AQpDAEMXQhMSFhdIHggaRAEOFR8PARFcERwGBQMEVUldQRk="), classAnthropicKey, ""},
		{"github-token-pat", xs("FQkePhxRXEZFQ0QVQV8TTwgBHBQGBghHCAMfHhoDXAocBlgdEgELGw=="), classGHToken, ""},
		{"github-token-oauth", xs("FQkBPhxRXEZFQ0QVQV8TTwgBHBQGBghHCAMfHhoDXAocBlgdEgELGw=="), classGHToken, ""},
		{"slack-token", xs("Cg4WAwBSXUFEQEUaQFZCAAoHGhYECAZFCgU="), classSlackToken, ""},
		{"stripe-live-secret", xs("AQoxDUQVCi0RFxBJHQkVRQIPEh4MAA5dEh0BBAAFWgA="), classStripeKey, ""},
		{"stripe-live-restricted", xs("AAoxDUQVCi0RFxBJHQkVRQIPEh4MAA5dEh0BBAAFWgA="), classStripeKey, ""},
		{"google-oauth", xs("CwBcWAMCXzMWPUV+NS0KHFlWTUdXWVkUUw4QExEWSx8="), classGCPKey, ""},
		{"jwt", xs("FxgkCU8kDBs/HDlkLRU7HCUMM0tPCxhnGQslORw8RDEXP0cmVTcmOF0uaQgYOx5FXUkXFRhKJRcAIlUkUkc1Ajw4GUNaTSEtdQwpSRxSJ1h9DyknIEUnZQs9Sng="), classJWT, ""},
		{"pem-rsa", "-----BEGIN RSA PRIVATE KEY-----", classPEM, ""},
		{"pem-plain", "-----BEGIN PRIVATE KEY-----", classPEM, ""},
		{"pem-openssh", "-----BEGIN OPENSSH PRIVATE KEY-----", classPEM, ""},
		{"bearer-header", "Authorization: Bearer abc123def456ghi789", classBearer, ""},
		{"generic-password-eq", "password=hunter2extraentropyval", classEntropy, "hunter2extraentropyval"},
		{"generic-secret-colon", "secret: mysupersecretvalue123", classEntropy, "mysupersecretvalue123"},
		{"generic-api-key", "api_key=abcdef0123456789", classEntropy, "abcdef0123456789"},
		{"conn-string", "postgres://myuser:mypass@localhost:5432/db", classConnString, "myuser:mypass@"},
	}
	pats := builtinPatterns()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var matched bool
			var matchedClass string
			var matchedText string
			for _, p := range pats {
				loc := p.re.FindStringSubmatchIndex(tt.input)
				if loc != nil {
					matched = true
					matchedClass = p.class
					start, end := loc[0], loc[1]
					if p.group > 0 && p.group*2+1 < len(loc) && loc[p.group*2] >= 0 {
						start, end = loc[p.group*2], loc[p.group*2+1]
					}
					matchedText = tt.input[start:end]
					break
				}
			}
			if !matched {
				t.Fatalf("no pattern matched %q", tt.input)
			}
			if matchedClass != tt.wantClass {
				t.Errorf("matched class = %q, want %q (matched text %q)", matchedClass, tt.wantClass, matchedText)
			}
			if tt.wantMatch != "" && matchedText != tt.wantMatch {
				t.Errorf("matched text = %q, want %q", matchedText, tt.wantMatch)
			}
		})
	}
}

func TestBenignStringsDoNotMatchStructural(t *testing.T) {
	benign := []string{
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"hello world this is a normal sentence",
		"/home/user/projects/rana/README.md",
		"550e8400-e29b-41d4-a716-446655440000",
	}
	pats := builtinPatterns()
	for _, s := range benign {
		for _, p := range pats {
			if p.re.MatchString(s) {
				t.Errorf("pattern %q (class %s) unexpectedly matched benign string %q", p.name, p.class, s)
			}
		}
	}
}
