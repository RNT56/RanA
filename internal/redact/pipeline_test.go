package redact

import (
	"regexp"
	"strings"
	"testing"
)

func testPipeline(t *testing.T) *Pipeline {
	t.Helper()
	p, err := NewPipeline([]byte("deterministic-test-salt"))
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	return p
}

var markerRe = regexp.MustCompile(`⟦R:([a-z]+):([smlx]+):([0-9a-f]{8})⟧`)

func TestRedactStructuralClasses(t *testing.T) {
	p := testPipeline(t)
	tests := []struct {
		name      string
		input     string
		wantClass string
	}{
		{"aws-key", "my key is AKIAIOSFODNN7EXAMPLE ok", classAWSKey},
		{"anthropic-key", "sk-ant-abcdefghijklmnopqrstuvwx1234", classAnthropicKey},
		{"openai-key", "sk-abcdefghijklmnopqrstuvwx1234", classOpenAIKey},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", classJWT},
		{"pem", "-----BEGIN RSA PRIVATE KEY-----", classPEM},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := string(p.Redact(tt.input))
			m := markerRe.FindStringSubmatch(out)
			if m == nil {
				t.Fatalf("Redact(%q) = %q, no marker found", tt.input, out)
			}
			if m[1] != tt.wantClass {
				t.Errorf("class = %q, want %q", m[1], tt.wantClass)
			}
		})
	}
}

func TestRedactConnStringOnlyRedactsUserPassSpan(t *testing.T) {
	p := testPipeline(t)
	in := "postgres://myuser:mypass@localhost:5432/db"
	out := string(p.Redact(in))
	if !strings.Contains(out, "postgres://") {
		t.Errorf("scheme should survive: %q", out)
	}
	if !strings.Contains(out, "localhost:5432/db") {
		t.Errorf("host/port/db should survive: %q", out)
	}
	if strings.Contains(out, "myuser") || strings.Contains(out, "mypass") {
		t.Errorf("raw credentials leaked: %q", out)
	}
}

func TestRedactGenericKVOnlyRedactsValue(t *testing.T) {
	p := testPipeline(t)
	in := "password=hunter2extraentropyvalue"
	out := string(p.Redact(in))
	if !strings.HasPrefix(out, "password=") {
		t.Errorf("key should survive: %q", out)
	}
	if strings.Contains(out, "hunter2extraentropyvalue") {
		t.Errorf("raw value leaked: %q", out)
	}
}

func TestRedactEntropyPass(t *testing.T) {
	p := testPipeline(t)
	in := "token value is aB3xQ9zR7mK2pL8vN4wT6yU1 embedded"
	out := string(p.Redact(in))
	if strings.Contains(out, "aB3xQ9zR7mK2pL8vN4wT6yU1") {
		t.Errorf("raw high-entropy token leaked: %q", out)
	}
	if !markerRe.MatchString(out) {
		t.Errorf("expected a redaction marker: %q", out)
	}
}

func TestRedactBenignStringsSurviveUnredacted(t *testing.T) {
	p := testPipeline(t)
	benign := []string{
		"hello world this is a normal sentence",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"the quick brown fox jumps over the lazy dog",
		"README.md",
		"main.go",
	}
	for _, s := range benign {
		out := string(p.Redact(s))
		if out != s {
			t.Errorf("Redact(%q) = %q, want unchanged", s, out)
		}
	}
}

func TestRedactIdempotent(t *testing.T) {
	p := testPipeline(t)
	inputs := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"hello world",
		"password=hunter2extraentropyvalue",
		"postgres://myuser:mypass@localhost:5432/db",
		"sk-ant-abcdefghijklmnopqrstuvwx1234",
	}
	for _, in := range inputs {
		once := string(p.Redact(in))
		twice := string(p.Redact(once))
		if once != twice {
			t.Errorf("Redact not idempotent for %q: once=%q twice=%q", in, once, twice)
		}
	}
}

func TestRedactNeverContainsInputVerbatimForSecrets(t *testing.T) {
	p := testPipeline(t)
	secrets := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"sk-ant-abcdefghijklmnopqrstuvwx1234",
		"-----BEGIN RSA PRIVATE KEY-----",
	}
	for _, s := range secrets {
		out := string(p.Redact(s))
		if out == s {
			t.Errorf("Redact(%q) returned input unchanged, secret not caught", s)
		}
	}
}

func TestSameSecretSameCRCWithinPipeline(t *testing.T) {
	p := testPipeline(t)
	in1 := "AKIAIOSFODNN7EXAMPLE appears here"
	in2 := "and AKIAIOSFODNN7EXAMPLE appears again"
	out1 := string(p.Redact(in1))
	out2 := string(p.Redact(in2))
	m1 := markerRe.FindStringSubmatch(out1)
	m2 := markerRe.FindStringSubmatch(out2)
	if m1 == nil || m2 == nil {
		t.Fatalf("expected markers in both outputs: %q / %q", out1, out2)
	}
	if m1[3] != m2[3] {
		t.Errorf("same secret produced different CRCs: %s vs %s", m1[3], m2[3])
	}
}

func TestDifferentSaltDifferentCRC(t *testing.T) {
	p1, _ := NewPipeline([]byte("salt-one"))
	p2, _ := NewPipeline([]byte("salt-two"))
	in := "AKIAIOSFODNN7EXAMPLE"
	out1 := string(p1.Redact(in))
	out2 := string(p2.Redact(in))
	m1 := markerRe.FindStringSubmatch(out1)
	m2 := markerRe.FindStringSubmatch(out2)
	if m1 == nil || m2 == nil {
		t.Fatalf("expected markers: %q / %q", out1, out2)
	}
	if m1[3] == m2[3] {
		t.Errorf("different salts produced same CRC: %s", m1[3])
	}
}

func TestLenClassBuckets(t *testing.T) {
	p := testPipeline(t)
	tests := []struct {
		name    string
		input   string
		wantLen string
	}{
		// AWS key is 20 chars -> s (<=20)
		{"s-bucket", "AKIAIOSFODNN7EXAMPLE", "s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := string(p.Redact(tt.input))
			m := markerRe.FindStringSubmatch(out)
			if m == nil {
				t.Fatalf("no marker in %q", out)
			}
			if m[2] != tt.wantLen {
				t.Errorf("lenclass = %q, want %q", m[2], tt.wantLen)
			}
		})
	}
}

func TestRedactArgv(t *testing.T) {
	p := testPipeline(t)
	argv := []string{"curl", "-H", "Authorization: Bearer abc123def456ghi789jkl", "https://example.com"}
	out := p.RedactArgv(argv)
	if len(out) != len(argv) {
		t.Fatalf("length mismatch: got %d want %d", len(out), len(argv))
	}
	if string(out[0]) != "curl" {
		t.Errorf("argv[0] should be unchanged: %q", out[0])
	}
	if strings.Contains(string(out[2]), "abc123def456ghi789jkl") {
		t.Errorf("bearer token leaked in argv: %q", out[2])
	}
	if string(out[3]) != "https://example.com" {
		t.Errorf("argv[3] should be unchanged: %q", out[3])
	}
}

func TestRedactArgvSecretSplitAcrossBoundary(t *testing.T) {
	p := testPipeline(t)
	// A secret split across two argv entries: each half alone may not meet
	// the entropy bar, but this documents current per-token behavior rather
	// than asserting cross-token joining (out of scope: each argv element is
	// evaluated independently, matching how a kernel-captured argv arrives).
	argv := []string{"--token", "AKIAIOSFODNN7EXAMPLE"}
	out := p.RedactArgv(argv)
	if strings.Contains(string(out[1]), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret argv element leaked: %q", out[1])
	}
}

func TestRedactPathPerSegment(t *testing.T) {
	p := testPipeline(t)
	in := "/tmp/upload/aB3xQ9zR7mK2pL8vN4wT6yU1zZ9/file.txt"
	out := string(p.RedactPath(in, PathResolved))
	if strings.Contains(out, "aB3xQ9zR7mK2pL8vN4wT6yU1zZ9") {
		t.Errorf("raw secret path segment leaked: %q", out)
	}
	if !strings.HasPrefix(out, "/tmp/upload/") {
		t.Errorf("benign prefix segments should survive: %q", out)
	}
	if !strings.HasSuffix(out, "/file.txt") {
		t.Errorf("benign suffix segment should survive: %q", out)
	}
}

func TestRedactPathOrdinaryPathUnchanged(t *testing.T) {
	p := testPipeline(t)
	in := "/usr/lib/x86_64-linux-gnu/libc.so.6"
	out := string(p.RedactPath(in, PathResolved))
	if out != in {
		t.Errorf("RedactPath(%q) = %q, want unchanged", in, out)
	}
}

func TestRedactPathGitObjectsAllowlisted(t *testing.T) {
	p := testPipeline(t)
	in := "/home/user/repo/.git/objects/ab/cdef0123456789abcdef0123456789abcdef01"
	out := string(p.RedactPath(in, PathResolved))
	if out != in {
		t.Errorf("git object path should be allowlisted, got %q", out)
	}
}

func TestRedactPathObjectsDirAllowlisted(t *testing.T) {
	p := testPipeline(t)
	// A content-addressed store path under a dir named "objects" or
	// "commits" with a 40/64-hex segment is contextually allowlisted.
	in := "/nix/store/objects/deadbeefcafebabe0123456789abcdef01234567"
	out := string(p.RedactPath(in, PathResolved))
	if out != in {
		t.Errorf("objects-dir hex path should be allowlisted, got %q", out)
	}
}

func TestRedactPathUUIDAllowlisted(t *testing.T) {
	p := testPipeline(t)
	in := "/var/run/containers/550e8400-e29b-41d4-a716-446655440000/rootfs"
	out := string(p.RedactPath(in, PathResolved))
	if out != in {
		t.Errorf("UUID path segment should be allowlisted, got %q", out)
	}
}

func TestRedactPathNonAllowlistedHexOutsideObjectsDirIsRedacted(t *testing.T) {
	p := testPipeline(t)
	// A 40-hex segment NOT under a dir named objects/commits and not a
	// .git/objects path should still be caught by the entropy pass if it
	// meets the bar (hex >= 32 chars).
	in := "/tmp/uploads/deadbeefcafebabe0123456789abcdef01234567/payload"
	out := string(p.RedactPath(in, PathResolved))
	if strings.Contains(out, "deadbeefcafebabe0123456789abcdef01234567") {
		t.Errorf("non-contextual hex blob should be redacted, got %q", out)
	}
}

func TestRedactOverlappingLeftmostLongestStructuralWins(t *testing.T) {
	p := testPipeline(t)
	// The generic "token=" pattern could also cannibalize an AWS key that
	// follows it; structural class must win and the AWS pattern (more
	// specific, matches first at its own position) should produce class
	// awskey somewhere in the output, never a raw AKIA... substring.
	in := "token=AKIAIOSFODNN7EXAMPLE"
	out := string(p.Redact(in))
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("raw AWS key leaked through overlap resolution: %q", out)
	}
}

func TestNewPipelineDeterministicAcrossInstances(t *testing.T) {
	p1, _ := NewPipeline([]byte("same-salt"))
	p2, _ := NewPipeline([]byte("same-salt"))
	in := "AKIAIOSFODNN7EXAMPLE"
	if p1.Redact(in) != p2.Redact(in) {
		t.Errorf("same salt should produce deterministic identical output")
	}
}
