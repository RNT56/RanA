package ledger

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// g1FloorEvPS is the sustained-throughput floor gate G1 enforces. The
// laptop-class bar is 10,000 ev/s (CLAUDE.md §4). CI hardware is slower and
// noisier, so CI may relax the floor via RANA_G1_MIN_EVPS (see
// .github/workflows/ci.yml) — but only the throughput floor is relaxable; the
// zero-loss and p99-latency correctness gates below are never relaxed. A
// missing or unparseable env var means the strict 10k floor applies.
func g1FloorEvPS() float64 {
	if v := os.Getenv("RANA_G1_MIN_EVPS"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return f
		}
	}
	return 10_000
}

// BenchmarkWriterSustained is gate G1: it drives >= 1,000,000 synthetic,
// mixed-type events through the REAL encode -> leaf -> seg -> group-commit
// -> sqlite path (schema constructors -> Writer.Append -> the writer
// goroutine's actual commitBatchTx), on a real (production) clock, and
// asserts:
//
//   - >= 10,000 events/sec sustained throughput
//   - zero loss (every appended event is later found durably persisted)
//   - p99 group-commit latency < 15ms
//
// It prints a small metrics table. Runnable on darwin (CONTRACTS
// explicitly requires this — no linux-only dependency anywhere in the
// path under benchmark).
//
// Run: go test -bench BenchmarkWriterSustained -benchtime=1x -run '^$' ./internal/ledger
func BenchmarkWriterSustained(b *testing.B) {
	const totalEvents = 1_000_000

	root := b.TempDir()
	d := Dir(root)
	if err := d.Ensure(); err != nil {
		b.Fatalf("Ensure: %v", err)
	}
	key, err := chain.GenerateKey(root)
	if err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}

	var commitLatencies commitLatencyRecorder

	w, err := NewWriter(d, WriterOptions{
		Key:                  key,
		onCommitDurationHook: commitLatencies.record,
	})
	if err != nil {
		b.Fatalf("NewWriter: %v", err)
	}

	session := schema.NewSessionID(realTimeClockMs{})

	b.ResetTimer()
	start := time.Now()

	for i := 0; i < totalEvents; i++ {
		ev := syntheticEvent(session, uint64(i))
		if err := w.Append(ev); err != nil {
			b.Fatalf("Append %d: %v", i, err)
		}
	}
	if err := w.FlushForTest(); err != nil {
		b.Fatalf("final FlushForTest: %v", err)
	}
	elapsed := time.Since(start)

	if err := w.Close(); err != nil {
		b.Fatalf("Close: %v", err)
	}
	if werr := w.Err(); werr != nil {
		b.Fatalf("writer reported a commit error: %v", werr)
	}

	// Zero-loss check: every appended event must be durably present.
	db, err := openDB(d.DBPath)
	if err != nil {
		b.Fatalf("openDB: %v", err)
	}
	defer db.Close()
	n, err := countEventsForSession(db, session)
	if err != nil {
		b.Fatalf("countEventsForSession: %v", err)
	}
	if n != totalEvents {
		b.Fatalf("zero-loss violated: wrote %d events, found %d persisted", totalEvents, n)
	}

	throughput := float64(totalEvents) / elapsed.Seconds()
	p50, p95, p99, maxLat := commitLatencies.percentiles()

	b.ReportMetric(throughput, "events/sec")
	b.ReportMetric(float64(p99.Microseconds())/1000, "p99_commit_ms")

	fmt.Printf("\nG1 BenchmarkWriterSustained metrics:\n")
	fmt.Printf("  events:            %d\n", totalEvents)
	fmt.Printf("  elapsed:           %s\n", elapsed)
	fmt.Printf("  throughput:        %.0f events/sec\n", throughput)
	fmt.Printf("  commit batches:    %d\n", commitLatencies.count())
	fmt.Printf("  commit p50:        %s\n", p50)
	fmt.Printf("  commit p95:        %s\n", p95)
	fmt.Printf("  commit p99:        %s\n", p99)
	fmt.Printf("  commit max:        %s\n", maxLat)

	floor := g1FloorEvPS()
	if throughput < floor {
		b.Errorf("G1 VIOLATION: throughput %.0f events/sec < %.0f events/sec floor", throughput, floor)
	}
	if p99 >= 15*time.Millisecond {
		b.Errorf("G1 VIOLATION: p99 commit latency %s >= 15ms", p99)
	}
}

// TestWriterBurstNeverSilentlyDrops is G1's companion backpressure proof:
// a burst far larger than the internal queue capacity must EITHER block
// Append (this Writer's actual behavior) OR account for every event via
// the frozen gap-reason vocabulary — it must never silently vanish. Since
// this Writer blocks (never sheds on its own), the proof is: after the
// burst, the durably persisted count exactly equals the appended count,
// with no invented gap reason anywhere (CONTRACTS: "do NOT invent a new
// gap reason (frozen set: ringbuf_full/governor/daemon_restart)").
func TestWriterBurstNeverSilentlyDrops(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping burst test in -short mode")
	}
	root := t.TempDir()
	d := Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	w, err := NewWriter(d, WriterOptions{})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	session := schema.NewSessionID(realTimeClockMs{})

	const burst = 50_000
	const concurrency = 32

	var wg sync.WaitGroup
	var appended int64
	perGoroutine := burst / concurrency
	for g := 0; g < concurrency; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				ev := syntheticEvent(session, uint64(base*perGoroutine+i))
				if err := w.Append(ev); err != nil {
					t.Errorf("Append: %v", err)
					return
				}
				atomic.AddInt64(&appended, 1)
			}
		}(g)
	}
	wg.Wait()

	if err := w.FlushForTest(); err != nil {
		t.Fatalf("FlushForTest: %v", err)
	}

	db, err := openDB(d.DBPath)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()
	n, err := countEventsForSession(db, session)
	if err != nil {
		t.Fatalf("countEventsForSession: %v", err)
	}
	want := int(atomic.LoadInt64(&appended))
	if n != want {
		t.Fatalf("burst caused silent loss: appended %d, persisted %d", want, n)
	}

	// No gap event was fabricated to explain a shortfall that doesn't
	// exist (there is no shortfall — this asserts the writer path never
	// emits a gap of its own accord for ordinary backpressure).
	var gapCount int
	row := db.QueryRow(`SELECT COUNT(*) FROM events WHERE session = ? AND type = ?`, session, string(schema.EventTypeGap))
	if err := row.Scan(&gapCount); err != nil {
		t.Fatalf("counting gap events: %v", err)
	}
	if gapCount != 0 {
		t.Fatalf("writer fabricated %d gap event(s) under ordinary backpressure; it must block, not shed", gapCount)
	}
}

// syntheticEvent returns a small, cheap-to-encode mix of event types
// (weighted toward proc.exec) so the benchmark exercises more than one
// schema constructor without materially affecting throughput.
func syntheticEvent(session string, i uint64) schema.Event {
	ts := i // monotonic-ish; value doesn't matter for the benchmark
	switch i % 5 {
	case 0:
		return schema.NewFsWriteOpen(session, 0, i, ts, ts, 100, redact.Literal("/tmp/x"), schema.PathSourceResolved, 0, 0o644)
	case 1:
		return schema.NewNetConnect(session, 0, i, ts, ts, 100, "tcp", make([]byte, 16), 443, "inet")
	default:
		return schema.NewProcExec(session, 0, i, ts, ts, 100,
			[]redact.Redacted{redact.Literal("/bin/true")},
			redact.Literal("true"), redact.Literal("/root"), redact.Literal("/bin/true"),
			1, 0)
	}
}

// realTimeClockMs adapts the real wall clock to schema.Clock.
type realTimeClockMs struct{}

func (realTimeClockMs) Now() int64 { return time.Now().UnixMilli() }

// commitLatencyRecorder collects per-batch commit durations under a mutex
// for percentile reporting; safe for the writer goroutine to call
// concurrently with nothing else (it's the sole caller in practice, but
// the mutex costs nothing at this scale and keeps the type trivially
// safe).
type commitLatencyRecorder struct {
	mu   sync.Mutex
	durs []time.Duration
}

func (r *commitLatencyRecorder) record(d time.Duration) {
	r.mu.Lock()
	r.durs = append(r.durs, d)
	r.mu.Unlock()
}

func (r *commitLatencyRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.durs)
}

func (r *commitLatencyRecorder) percentiles() (p50, p95, p99, max time.Duration) {
	r.mu.Lock()
	sorted := append([]time.Duration(nil), r.durs...)
	r.mu.Unlock()

	if len(sorted) == 0 {
		return 0, 0, 0, 0
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	pick := func(p float64) time.Duration {
		idx := int(p * float64(len(sorted)-1))
		return sorted[idx]
	}
	return pick(0.50), pick(0.95), pick(0.99), sorted[len(sorted)-1]
}
