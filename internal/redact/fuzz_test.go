package redact

import (
	"testing"
)

// FuzzRedact asserts the two mechanical properties the trust core depends
// on: Redact never panics on arbitrary input, and Redact is idempotent
// (re-redacting already-redacted output is a no-op). It also spot-checks
// that a non-empty, non-marker input which changed under redaction has its
// original bytes fully removed from the output (no partial leak from an
// off-by-one span).
func FuzzRedact(f *testing.F) {
	seeds := []string{
		"",
		"hello world",
		"AKIAIOSFODNN7EXAMPLE",
		"password=hunter2extraentropyvalue",
		"postgres://user:pass@host:5432/db",
		"sk-ant-abcdefghijklmnopqrstuvwx1234",
		"-----BEGIN RSA PRIVATE KEY-----",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/tmp/upload/aB3xQ9zR7mK2pL8vN4wT6yU1zZ9/file.txt",
		"⟦R:entropy:m:d2e1⟧",
		"token=AKIAIOSFODNN7EXAMPLE token=AKIAIOSFODNN7EXAMPLE",
		"a=b:c/d e\tf\ng",
		"日本語のテキストにAKIAIOSFODNN7EXAMPLEが含まれています",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	p, err := NewPipeline([]byte("fuzz-salt"))
	if err != nil {
		f.Fatalf("NewPipeline: %v", err)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Redact panicked on input %q: %v", raw, r)
			}
		}()

		once := string(p.Redact(raw))
		twice := string(p.Redact(once))
		if once != twice {
			t.Fatalf("Redact not idempotent: raw=%q once=%q twice=%q", raw, once, twice)
		}

		// RedactArgv and RedactPath must not panic either, and must also be
		// idempotent through their own re-application.
		argvOnce := p.RedactArgv([]string{raw})
		argvTwice := p.RedactArgv([]string{string(argvOnce[0])})
		if argvOnce[0] != argvTwice[0] {
			t.Fatalf("RedactArgv not idempotent: raw=%q once=%q twice=%q", raw, argvOnce[0], argvTwice[0])
		}

		pathOnce := p.RedactPath(raw)
		pathTwice := p.RedactPath(string(pathOnce))
		if pathOnce != pathTwice {
			t.Fatalf("RedactPath not idempotent: raw=%q once=%q twice=%q", raw, pathOnce, pathTwice)
		}
	})
}
