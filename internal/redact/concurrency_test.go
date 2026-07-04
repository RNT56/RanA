package redact

import (
	"sync"
	"testing"
)

// TestPipelineConcurrentRedactIsRaceFreeAndDeterministic substantiates
// Pipeline's doc comment claim ("safe for concurrent use by multiple
// goroutines after construction") under `go test -race`, and confirms
// determinism holds under concurrent use: every goroutine redacting the
// same input must produce byte-identical output (same spans, same salted
// CRC), since ranad and the session service both hold one shared *Pipeline
// and call Redact/RedactArgv/RedactPath from multiple goroutines
// concurrently in production (docs/REDACTION.md: "the pipeline runs at
// every writer ingress"). A Pipeline with any accidentally-shared mutable
// state (e.g. a reused scratch buffer) could pass every sequential test in
// this package while still corrupting output — or worse, leaking one
// goroutine's raw span into another's result — under real concurrent load.
func TestPipelineConcurrentRedactIsRaceFreeAndDeterministic(t *testing.T) {
	p := testPipeline(t)

	inputs := []string{
		"password=hunter2hunter2hunter2hunter2",
		"AKIA" + "ABCDEFGHIJKLMNOP", // split so no contiguous AWS-key shape in source
		"connect to postgres://alice:s3cr3tpassword@db.internal:5432/app",
		"just an ordinary benign log line with no secrets in it at all",
		"/home/user/.ssh/id_ed25519",
		"sk-ant-" + strings20("A"),
	}

	const goroutines = 16
	const iterations = 50

	// want[i] is the expected (first observed, sequentially-computed)
	// output for inputs[i]; every concurrent call must match it exactly.
	want := make([]Redacted, len(inputs))
	for i, in := range inputs {
		want[i] = p.Redact(in)
	}

	var wg sync.WaitGroup
	errs := make(chan string, goroutines*iterations)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := 0; it < iterations; it++ {
				for i, in := range inputs {
					got := p.Redact(in)
					if got != want[i] {
						errs <- "mismatch: input=" + in + " got=" + string(got) + " want=" + string(want[i])
					}
				}
				// Also exercise RedactArgv and RedactPath concurrently —
				// they share the same Pipeline and its compiled pattern
				// set/salt.
				_ = p.RedactArgv(inputs)
				_ = p.RedactPath("/tmp/upload/"+strings20("Q"), PathResolved)
			}
		}()
	}
	wg.Wait()
	close(errs)

	for e := range errs {
		t.Error(e)
	}
}

// strings20 returns a 20-rune string of r repeated, a convenient
// deterministic high-entropy-length-shaped filler for concurrency-test
// inputs (content doesn't matter here, only that all goroutines redact the
// identical bytes and get identical results).
func strings20(r string) string {
	out := ""
	for i := 0; i < 20; i++ {
		out += r
	}
	return out
}
