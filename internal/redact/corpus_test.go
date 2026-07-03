package redact

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusXORKey is the fixed cyclic-XOR key used to obfuscate secret-bearing
// corpus fields on disk. It must match the corpus generator exactly. Its only
// job is to keep literal credentials out of git history and past
// secret-scanners; it is not a security boundary.
var corpusXORKey = []byte("rana-corpus-xor-key")

// decodeCorpusField reverses the "xb64" storage transform:
// base64-decode, then cyclic-XOR with corpusXORKey.
func decodeCorpusField(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	out := make([]byte, len(raw))
	for i, b := range raw {
		out[i] = b ^ corpusXORKey[i%len(corpusXORKey)]
	}
	return string(out), nil
}

// corpusSpan mirrors one entry of a corpus row's "spans" array.
type corpusSpan struct {
	Class string `json:"class"`
}

// corpusRow mirrors one line of test/redaction-corpus/corpus.jsonl.
type corpusRow struct {
	Input string       `json:"input"`
	Spans []corpusSpan `json:"spans"`
	// Secrets holds the exact raw secret substring(s) seeded into Input,
	// present only when MustRedact is true. The zero-leak gate scans
	// Pipeline output for these exact strings.
	Secrets    []string `json:"secrets,omitempty"`
	MustRedact bool     `json:"must_redact"`
	// Kind selects which pipeline entry point exercises this entry: "path"
	// routes through Pipeline.RedactPath (per-segment contextual
	// allowlisting applies), anything else (including empty/omitted)
	// routes through Pipeline.Redact.
	Kind string `json:"kind,omitempty"`
	// Enc marks how Input/Secrets are stored on disk. "b64" means both are
	// base64-encoded so no literal credential lands in git history; the
	// loader decodes them. Absent means plaintext (legacy/benign rows).
	Enc string `json:"enc,omitempty"`
}

// redactRow runs the pipeline entry point appropriate to row.Kind, matching
// how production callers would invoke the pipeline for that kind of
// captured string (RedactPath for filesystem paths, Redact for everything
// else — argv elements, KV lines, connection strings, prose).
func redactRow(p *Pipeline, row corpusRow) string {
	if row.Kind == "path" {
		return string(p.RedactPath(row.Input))
	}
	return string(p.Redact(row.Input))
}

// corpusPath resolves the checked-in corpus file relative to this package,
// so `go test ./internal/redact/...` works regardless of the invoking
// working directory.
func corpusPath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "test", "redaction-corpus", "corpus.jsonl")
}

func loadCorpus(t *testing.T) []corpusRow {
	t.Helper()
	path := corpusPath(t)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus %s: %v", path, err)
	}
	defer f.Close()

	var rows []corpusRow
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var row corpusRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("corpus line %d: invalid JSON: %v", lineNo, err)
		}
		// Secret-bearing fields are stored obfuscated so no literal,
		// format-valid credential ever lands in this repo's git history
		// (a secrets-redaction tool leaking real-shaped keys into its own
		// history would be self-defeating, and platform push-protection
		// rightly blocks it — including base64, which scanners decode).
		// "xb64" = base64(cyclic-XOR(plaintext, corpusXORKey)); a scanner
		// that base64-decodes sees only XOR noise. Deterministic, no RNG.
		if row.Enc == "xb64" {
			in, err := decodeCorpusField(row.Input)
			if err != nil {
				t.Fatalf("corpus line %d: bad input encoding: %v", lineNo, err)
			}
			row.Input = in
			for i, s := range row.Secrets {
				d, err := decodeCorpusField(s)
				if err != nil {
					t.Fatalf("corpus line %d: bad secret encoding: %v", lineNo, err)
				}
				row.Secrets[i] = d
			}
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan corpus: %v", err)
	}
	return rows
}

// corpusSalt is a fixed, deterministic salt used for all corpus-gate tests.
// The gate cares about recall/precision/leak-freedom, not about any
// particular CRC value, so a fixed constant salt keeps the run fully
// reproducible.
var corpusSalt = []byte("corpus-gate-fixed-salt-do-not-use-in-prod")

func TestCorpusMinimumSize(t *testing.T) {
	rows := loadCorpus(t)
	if len(rows) < 520 {
		t.Fatalf("corpus has %d entries, want >= 520 per contract", len(rows))
	}
	var mustCount, benignCount int
	for _, r := range rows {
		if r.MustRedact {
			mustCount++
		} else {
			benignCount++
		}
	}
	if benignCount < 120 {
		t.Fatalf("corpus has %d benign (must_redact:false) entries, want >= 120", benignCount)
	}
	t.Logf("corpus: %d total, %d must_redact, %d benign", len(rows), mustCount, benignCount)
}

// TestCorpusRecallGate is CI gate G4: recall >= 99% over must_redact=true
// entries using the built-in pattern/entropy set (no profile extras).
func TestCorpusRecallGate(t *testing.T) {
	rows := loadCorpus(t)
	p, err := NewPipeline(corpusSalt)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}

	var total, redacted int
	var misses []string
	for _, r := range rows {
		if !r.MustRedact {
			continue
		}
		total++
		out := redactRow(p, r)
		if out != r.Input {
			redacted++
		} else {
			misses = append(misses, r.Input)
		}
	}
	if total == 0 {
		t.Fatal("no must_redact=true entries found in corpus")
	}
	recall := float64(redacted) / float64(total)
	if recall < 0.99 {
		limit := misses
		if len(limit) > 20 {
			limit = limit[:20]
		}
		t.Fatalf("recall = %.4f (%d/%d), want >= 0.99; sample misses: %v", recall, redacted, total, limit)
	}
	t.Logf("recall = %.4f (%d/%d redacted)", recall, redacted, total)
}

// TestCorpusPrecisionGate is CI gate G4: at most 5% of benign
// (must_redact:false) entries may be redacted (false positives).
func TestCorpusPrecisionGate(t *testing.T) {
	rows := loadCorpus(t)
	p, err := NewPipeline(corpusSalt)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}

	var total, falsePositives int
	var fps []string
	for _, r := range rows {
		if r.MustRedact {
			continue
		}
		total++
		out := redactRow(p, r)
		if out != r.Input {
			falsePositives++
			fps = append(fps, r.Input)
		}
	}
	if total == 0 {
		t.Fatal("no must_redact=false entries found in corpus")
	}
	rate := float64(falsePositives) / float64(total)
	if rate > 0.05 {
		limit := fps
		if len(limit) > 20 {
			limit = limit[:20]
		}
		t.Fatalf("benign false-positive rate = %.4f (%d/%d), want <= 0.05; sample false positives: %v", rate, falsePositives, total, limit)
	}
	t.Logf("benign false-positive rate = %.4f (%d/%d)", rate, falsePositives, total)
}

// TestCorpusZeroRawSecretLeak is the load-bearing assertion from
// docs/REDACTION.md: any test in which a raw seeded secret reaches a leaf
// hash is an immediate build failure. This asserts, by substring scan
// against the corpus's recorded exact secret payloads (not a heuristic
// over the whole input line, which would false-positive on benign labels
// like "aws_access_key_id"), that no seeded secret survives anywhere in the
// redacted output across the whole corpus.
func TestCorpusZeroRawSecretLeak(t *testing.T) {
	rows := loadCorpus(t)
	p, err := NewPipeline(corpusSalt)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}

	var leaks []string
	for _, r := range rows {
		if !r.MustRedact {
			continue
		}
		if len(r.Secrets) == 0 {
			t.Fatalf("corpus row %q is must_redact but has no recorded secrets to scan for", r.Input)
		}
		out := redactRow(p, r)
		for _, secret := range r.Secrets {
			if strings.Contains(out, secret) {
				leaks = append(leaks, secret)
			}
		}
	}
	if len(leaks) > 0 {
		limit := leaks
		if len(limit) > 20 {
			limit = limit[:20]
		}
		t.Fatalf("%d raw seeded secret(s) leaked into Pipeline output; sample: %v", len(leaks), limit)
	}
}

// TestCorpusRedactIdempotent is the property test required by the
// contract: Redact is idempotent, and output never contains a
// must_redact=true input verbatim.
func TestCorpusRedactIdempotent(t *testing.T) {
	rows := loadCorpus(t)
	p, err := NewPipeline(corpusSalt)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}

	for _, r := range rows {
		once := redactRow(p, r)
		twiceRow := corpusRow{Input: once, Kind: r.Kind}
		twice := redactRow(p, twiceRow)
		if once != twice {
			t.Errorf("Redact not idempotent for %q: once=%q twice=%q", r.Input, once, twice)
		}
		if r.MustRedact && once == r.Input {
			t.Errorf("must_redact input survived verbatim: %q", r.Input)
		}
	}
}

// TestCorpusSpanClassesAreKnown sanity-checks the corpus file itself: every
// declared span class must be one of the frozen §4 classes, catching typos
// in the corpus data before they mask a real detection gap.
func TestCorpusSpanClassesAreKnown(t *testing.T) {
	known := map[string]bool{
		classAWSKey: true, classGCPKey: true, classOpenAIKey: true,
		classAnthropicKey: true, classGHToken: true, classSlackToken: true,
		classStripeKey: true, classJWT: true, classPEM: true,
		classBearer: true, classConnString: true, classEntropy: true,
	}
	rows := loadCorpus(t)
	for i, r := range rows {
		for _, sp := range r.Spans {
			if !known[sp.Class] {
				t.Errorf("corpus row %d (%q): unknown span class %q", i, r.Input, sp.Class)
			}
		}
	}
}
