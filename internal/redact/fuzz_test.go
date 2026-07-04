package redact

import (
	"strings"
	"testing"
)

// FuzzRedact asserts the properties the trust core depends on: Redact never
// panics on arbitrary input; Redact is idempotent (re-redacting already-
// redacted output is a no-op); and — the leak-oriented check — a known secret
// is still redacted no matter what fuzz-controlled context surrounds it, so a
// mutation that lets adversarial context SUPPRESS redaction of a real secret
// (a leak the panic/idempotency checks cannot see) is surfaced.
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
		"⟦R:entropy:m:d2e1a4c8⟧",
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

		// RedactPath must be idempotent under BOTH trust levels (the claimed
		// path disables the content-addressed allowlist; the resolved path
		// applies it — both must reach a fixed point).
		for _, trust := range []PathTrust{PathClaimed, PathResolved} {
			pathOnce := p.RedactPath(raw, trust)
			pathTwice := p.RedactPath(string(pathOnce), trust)
			if pathOnce != pathTwice {
				t.Fatalf("RedactPath not idempotent (trust=%d): raw=%q once=%q twice=%q", trust, raw, pathOnce, pathTwice)
			}
		}

		// Leak-oriented property: a canonical, unambiguous secret (the AWS
		// example access key) must be redacted regardless of the fuzz-chosen
		// context preceding it. A mutation that lets context break tokenization
		// or the structural match — and so SUPPRESS redaction of a real secret
		// — is exactly the miss the panic/idempotency checks above cannot find.
		const sentinel = "AKIA" + "IOSFODNN7EXAMPLE" // 20-char AWS example key
		probe := raw + " " + sentinel
		if strings.Contains(string(p.Redact(probe)), sentinel) {
			t.Fatalf("sentinel secret survived redaction when preceded by context %q", raw)
		}
	})
}
