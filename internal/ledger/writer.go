package ledger

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/schema"
)

// Group-commit and sealing thresholds (CONTRACTS §internal/ledger,
// docs/TRUST.md §3, §5).
const (
	groupCommitMaxEvents = 512
	groupCommitInterval  = 10 * time.Millisecond

	segSealMaxEvents  = 4096
	segSealMaxAge     = 60 * time.Second
	checkpointMaxSegs = 64
	checkpointMaxWait = 5 * time.Minute

	// appendQueueCapacity sizes the Writer's internal channel. G1 requires
	// >=10k ev/s sustained with group commits every <=10ms / <=512 events;
	// a queue many multiples of one batch deep gives headroom so a
	// momentary scheduling delay does not itself become loss. Append
	// blocks (never drops) when the queue is full — CONTRACTS is explicit
	// that overflow must not invent a new gap reason; the writer must be
	// sized so overflow is a rare, brief backpressure event, not routine
	// behavior.
	appendQueueCapacity = 16384
)

// HeadReportFunc is invoked once per checkpoint with the report to mirror
// (docs/TRUST.md §5). Wired by svc to the ranad socket plus a
// local heads-file fallback; nil is a legal no-op (e.g. in unit tests).
type HeadReportFunc func(chain.HeadReport)

// WriterOptions configures a Writer. All fields have sensible zero-value
// defaults (P6): a zero WriterOptions is a fully valid configuration for a
// single-key, single-writer ledger.
type WriterOptions struct {
	// Key signs checkpoints. If PrivateKey is nil, checkpoints are never
	// signed (segments still seal and chain; useful for tests that only
	// exercise sealing). Production callers MUST supply a real device key
	// (internal/chain.GenerateKey / LoadKey).
	Key chain.KeyInfo

	// OnHeadReport is called synchronously from the writer goroutine after
	// a checkpoint is durably committed. May be nil.
	OnHeadReport HeadReportFunc

	// GroupCommitMaxEvents / GroupCommitInterval override the default
	// group-commit batching thresholds (512 events / 10ms). Zero means
	// "use the default".
	GroupCommitMaxEvents int
	GroupCommitInterval  time.Duration

	// SegSealMaxEvents / SegSealMaxAge override the default segment-seal
	// thresholds (4096 events / 60s-after-first-event). Zero means "use
	// the default".
	SegSealMaxEvents int
	SegSealMaxAge    time.Duration

	// CheckpointMaxSegs / CheckpointMaxWait override the default
	// checkpoint cadence (64 sealed segments / 5 minutes pending). Zero
	// means "use the default".
	CheckpointMaxSegs int
	CheckpointMaxWait time.Duration

	// onCommitDurationHook, when non-nil, is called once per group commit
	// with the wall-clock duration of that commit's SQLite transaction.
	// Unexported: it exists solely to let BenchmarkWriterSustained (gate
	// G1) measure real commit latency without adding public surface area
	// production callers would need to know about.
	onCommitDurationHook func(time.Duration)
}

func (o WriterOptions) groupCommitMaxEvents() int {
	if o.GroupCommitMaxEvents > 0 {
		return o.GroupCommitMaxEvents
	}
	return groupCommitMaxEvents
}

func (o WriterOptions) groupCommitInterval() time.Duration {
	if o.GroupCommitInterval > 0 {
		return o.GroupCommitInterval
	}
	return groupCommitInterval
}

func (o WriterOptions) segSealMaxEvents() int {
	if o.SegSealMaxEvents > 0 {
		return o.SegSealMaxEvents
	}
	return segSealMaxEvents
}

func (o WriterOptions) segSealMaxAge() time.Duration {
	if o.SegSealMaxAge > 0 {
		return o.SegSealMaxAge
	}
	return segSealMaxAge
}

func (o WriterOptions) checkpointMaxSegs() int {
	if o.CheckpointMaxSegs > 0 {
		return o.CheckpointMaxSegs
	}
	return checkpointMaxSegs
}

func (o WriterOptions) checkpointMaxWait() time.Duration {
	if o.CheckpointMaxWait > 0 {
		return o.CheckpointMaxWait
	}
	return checkpointMaxWait
}

// ErrWriterClosed is returned by Append after Close has been called.
var ErrWriterClosed = errors.New("ledger: writer is closed")

// pendingEvent is an event that has passed validation/encoding and is
// queued for the writer goroutine's next group commit.
type pendingEvent struct {
	ev   schema.Event
	enc  []byte   // canonical CBOR (cborcanon.EncodeEvent)
	leaf [32]byte // chain.Leaf(enc)
}

// sessionState is the writer's in-memory chain state for one session,
// rebuilt from durable storage on first touch (openOrInitSession).
type sessionState struct {
	// current, unsealed segment accumulator
	segIndex     uint64
	segFirstRow  int64
	segLastRow   int64
	segLeaves    [][32]byte
	segGapCounts map[string]uint64
	segFirstTs   time.Time // wall-clock time (writer clock) of first event in the open segment
	segOpen      bool

	prevSegHash [32]byte // chain head of the last SEALED segment (genesis: zero)

	// checkpoint bookkeeping
	pendingSegsSinceCheckpoint int
	oldestUnsignedSealedAt     time.Time
	haveOldestUnsigned         bool
}

// Writer is the single-writer ingestion path for one ledger: it accepts
// schema.Event values, validates and canonically encodes them, batches
// them into group commits, seals segments, and produces signed
// ledger-wide checkpoints (CONTRACTS §internal/ledger, docs/TRUST.md).
//
// A Writer owns exactly one goroutine that touches the database for
// writes; Append is safe for concurrent use by multiple goroutines and
// communicates with the writer goroutine over a channel.
type Writer struct {
	db    *sql.DB
	dir   Datadir
	opts  WriterOptions
	clock clock

	queue chan pendingEvent

	closeOnce sync.Once
	closeCh   chan struct{}
	doneCh    chan struct{}

	// flushCh lets test helpers (FlushForTest) force an immediate flush
	// cycle regardless of the count/timer thresholds; the send value is
	// closed by the writer loop once the resulting commit (if any) has
	// completed.
	flushCh chan chan struct{}

	// sealCh lets callers (SealSession) force an immediate segment seal
	// (and checkpoint, if due) for one session outside the normal
	// thresholds.
	sealCh chan sealRequest

	// syncCh receives a signal after every writer-loop iteration that
	// performs a timer-driven flush, so deterministic clock-driven tests
	// (AdvanceAndSync) can observe completion without real sleeps.
	syncCh chan struct{}

	mu       sync.Mutex // guards ledgerPrevCkptHash, sessions map, and commitErr
	sessions map[string]*sessionState

	ledgerPrevCkptHash [32]byte // last checkpoint hash written to this ledger, across ALL sessions (docs/TRUST.md §5)
	commitErr          error    // first fatal commit-time error, if any (see Err)
}

// NewWriter opens (or reuses) the ledger database under dir and starts the
// writer goroutine with production timing (real clock, default batching
// and sealing thresholds unless overridden in opts).
func NewWriter(dir Datadir, opts WriterOptions) (*Writer, error) {
	return newWriterWithClock(dir, opts, realClock{})
}

func newWriterWithClock(dir Datadir, opts WriterOptions, clk clock) (*Writer, error) {
	if err := dir.Ensure(); err != nil {
		return nil, err
	}
	db, err := openDB(dir.DBPath)
	if err != nil {
		return nil, err
	}

	w := &Writer{
		db:       db,
		dir:      dir,
		opts:     opts,
		clock:    clk,
		queue:    make(chan pendingEvent, appendQueueCapacity),
		closeCh:  make(chan struct{}),
		doneCh:   make(chan struct{}),
		flushCh:  make(chan chan struct{}),
		sealCh:   make(chan sealRequest),
		syncCh:   make(chan struct{}, 1),
		sessions: make(map[string]*sessionState),
	}

	prevHash, err := loadLedgerPrevCheckpointHash(db)
	if err != nil {
		db.Close()
		return nil, err
	}
	w.ledgerPrevCkptHash = prevHash

	if err := ensureMeta(db, opts.Key); err != nil {
		db.Close()
		return nil, err
	}

	// Register the group-commit timer's first tick HERE, synchronously,
	// before the writer goroutine starts — see run()'s doc comment for
	// why this ordering matters with a fakeClock.
	initialTimer := clk.After(opts.groupCommitInterval())

	go w.run(initialTimer)
	return w, nil
}

// Append validates ev (schema.Validate), canonically encodes it
// (cborcanon.EncodeEvent — which rejects any raw string per P3), computes
// its leaf hash, and queues it for the next group commit. Append does NOT
// block waiting for that commit to complete (group commit is the whole
// point — waiting per-event would defeat batching and cap throughput far
// below G1's target); it returns as soon as the event is durably enqueued.
// Append blocks only if the internal queue is momentarily full — CONTRACTS
// is explicit that overflow must not invent a new gap reason; the queue is
// sized with headroom (G1) so this is the rare exception, not the norm.
//
// A commit-time failure (e.g. a SQLite I/O error) cannot be returned to
// the Append call that happened to trigger the batch, since many callers'
// events may share one batch; such failures are reported via
// WriterOptions in a future revision and, for v1, are treated as fatal to
// the writer goroutine (CommitErr, checked by Close and exposed via Err).
func (w *Writer) Append(ev schema.Event) error {
	if err := w.Err(); err != nil {
		return fmt.Errorf("ledger: writer has a fatal commit error, refusing further writes: %w", err)
	}
	if err := schema.Validate(ev); err != nil {
		return fmt.Errorf("ledger: invalid event: %w", err)
	}
	enc, err := cborcanon.EncodeEvent(ev)
	if err != nil {
		return fmt.Errorf("ledger: encoding event: %w", err)
	}
	leaf := chain.Leaf(enc)

	pe := pendingEvent{ev: ev, enc: enc, leaf: leaf}

	select {
	case w.queue <- pe:
		return nil
	case <-w.closeCh:
		return ErrWriterClosed
	}
}

// AppendEncoded persists an event whose canonical CBOR bytes were produced
// upstream (by ranad, which ran the redaction pipeline and cborcanon.EncodeEvent
// — including the P3 raw-string guard — before putting the bytes on the wire).
// The svc side must NOT re-encode such an event: CBOR text strings decode back
// to plain Go strings (losing the redact.Redacted type), so a re-encode would
// spuriously trip ErrRawString on already-redacted data. Instead this hashes
// the provided bytes directly, exactly as docs/TRUST.md §7 prescribes ("hash
// the given bytes, do not re-encode").
//
// enc is verified to be well-formed canonical CBOR (so a malformed upstream
// cannot poison the chain with bytes that later fail verification), and ev is
// the already-decoded envelope used only for the ledger's indexing/segment
// bookkeeping — it MUST be the decoding of enc (the caller just produced it
// from enc). Redaction is NOT re-applied here; the bytes are trusted to be
// pre-redacted, which for the kernel-event path is guaranteed by ranad.
func (w *Writer) AppendEncoded(ev schema.Event, enc []byte) error {
	if err := w.Err(); err != nil {
		return fmt.Errorf("ledger: writer has a fatal commit error, refusing further writes: %w", err)
	}
	if err := schema.Validate(ev); err != nil {
		return fmt.Errorf("ledger: invalid event: %w", err)
	}
	ok, err := cborcanon.IsCanonical(enc)
	if err != nil {
		return fmt.Errorf("ledger: checking event bytes: %w", err)
	}
	if !ok {
		return fmt.Errorf("ledger: refusing non-canonical event bytes from the wire")
	}
	leaf := chain.Leaf(enc)
	pe := pendingEvent{ev: ev, enc: enc, leaf: leaf}
	select {
	case w.queue <- pe:
		return nil
	case <-w.closeCh:
		return ErrWriterClosed
	}
}

// Err returns the first commit-time error encountered by the writer
// goroutine, if any (nil while the writer is healthy). Once set, Append
// refuses further writes (returning a wrapped form of this error) rather
// than silently accepting events the writer has already shown it cannot
// durably persist — callers should treat a non-nil Err as fatal and
// restart the process (crash-loud rather than silently drop, per P5's
// spirit applied to the writer's own durability). The underlying SQLite
// handle is left open so any already-queued-but-not-yet-committed batch
// still gets an attempt (and, on repeated failure, updates this same
// error) rather than wedging mid-shutdown; Close() should still be called
// to release the database handle.
func (w *Writer) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.commitErr
}

// Close flushes any pending events, stops the writer goroutine, and closes
// the underlying database handle. Close is idempotent.
func (w *Writer) Close() error {
	var closeErr error
	w.closeOnce.Do(func() {
		close(w.closeCh)
		<-w.doneCh
		closeErr = w.db.Close()
	})
	return closeErr
}

// loadLedgerPrevCheckpointHash reads the most recently written checkpoint's
// CheckpointHash across the whole ledger (docs/TRUST.md §5: "the previous
// checkpoint in the WHOLE LEDGER"), or the zero hash if none exists yet.
func loadLedgerPrevCheckpointHash(db *sql.DB) ([32]byte, error) {
	var body []byte
	row := db.QueryRow(`SELECT body FROM checkpoints ORDER BY cid DESC LIMIT 1`)
	err := row.Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return [32]byte{}, nil
	}
	if err != nil {
		return [32]byte{}, fmt.Errorf("ledger: loading last checkpoint: %w", err)
	}
	return chain.CheckpointHash(body), nil
}
