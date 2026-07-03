package ledger

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/schema"
)

// run is the Writer's single goroutine: it batches queued events into
// group commits (<=512 events or 10ms, whichever first), then — inside the
// same processing step — seals segments and writes checkpoints that
// became due as a result of the commit (CONTRACTS §internal/ledger).
//
// initialTimer is the group-commit timer's FIRST registration, made
// synchronously by newWriterWithClock before this goroutine is even
// started — not registered here. With a fakeClock, a caller that Appends
// an event and then immediately calls AdvanceAndSync has no
// synchronization with when this goroutine actually starts running; if
// the first w.clock.After(interval) call happened here instead, a
// sufficiently unlucky scheduling order could let the test's Advance call
// run (finding zero registered waiters, since this goroutine hasn't
// reached its first After() call yet) BEFORE this goroutine registers its
// timer — silently losing that wakeup forever, since fakeClock.Advance
// only fires waiters that exist at the moment it's called. Registering
// the timer in the constructor's goroutine (which happens-before `go
// w.run()`) closes that window.
func (w *Writer) run(initialTimer <-chan time.Time) {
	defer close(w.doneCh)

	maxEvents := w.opts.groupCommitMaxEvents()
	interval := w.opts.groupCommitInterval()

	var batch []pendingEvent
	timer := initialTimer

	// drainQueue pulls up to n more events CURRENTLY buffered in w.queue
	// into batch without blocking (n < 0 means unbounded — drain
	// everything). A bounded, non-blocking drain right before a
	// timer-triggered flush closes a real race: Append returns as soon as
	// an event is enqueued, but the writer loop's select can still pick
	// the (by-then-also-ready) timer case first, flushing an empty-or-
	// stale batch while the just-enqueued event sits unprocessed one
	// select-iteration longer than a caller synchronizing on "the timer
	// fired" would expect. Bounding it by maxEvents keeps group-commit
	// batches capped (gate G1's p99 gate depends on batches never
	// ballooning past ~512 events even under sustained load) — only
	// flushAll (explicit FlushForTest/SealSession requests, which mean
	// "commit everything appended so far") drains unboundedly.
	drainQueue := func(n int) {
		for n != 0 {
			select {
			case pe := <-w.queue:
				batch = append(batch, pe)
				if n > 0 {
					n--
				}
			default:
				return
			}
		}
	}

	// flushBatch commits the events accumulated in batch — after first
	// topping it up (non-blocking, bounded to maxEvents total) with
	// anything already sitting in the queue, so a timer tick can never
	// race ahead of an Append that already completed before the tick
	// fired (see drainQueue's doc comment).
	flushBatch := func() {
		if room := maxEvents - len(batch); room > 0 {
			drainQueue(room)
		}
		if len(batch) == 0 {
			timer = w.clock.After(interval)
			return
		}
		w.commitBatch(batch)
		batch = batch[:0]
		timer = w.clock.After(interval)
	}

	// flushAll drains every event currently sitting in the queue (as well
	// as whatever is already in batch) and commits them in one group
	// commit, for the "flush everything appended so far" contract
	// FlushForTest/SealSession need.
	flushAll := func() {
		drainQueue(-1)
		flushBatch()
	}

	signalSync := func() {
		select {
		case w.syncCh <- struct{}{}:
		default:
			// Non-blocking: if nobody is waiting on syncCh right now (e.g.
			// production realClock use, which never reads it), never let
			// bookkeeping block the writer loop.
		}
	}

	for {
		select {
		case pe := <-w.queue:
			batch = append(batch, pe)
			if len(batch) >= maxEvents {
				flushBatch()
			}
		case <-timer:
			flushBatch()
			signalSync()
		case done := <-w.flushCh:
			flushAll()
			close(done)
		case req := <-w.sealCh:
			flushAll() // commit anything already queued for this (or any) session first
			err := w.forceSealSession(req.session)
			if err != nil {
				req.errCh <- err
			}
			close(req.done)
		case <-w.closeCh:
			// Drain whatever is already queued (non-blocking) before the
			// final flush, so Append callers racing with Close still get a
			// definitive answer rather than ErrWriterClosed for an event
			// that actually made it in.
		drain:
			for {
				select {
				case pe := <-w.queue:
					batch = append(batch, pe)
				default:
					break drain
				}
			}
			flushBatch()
			return
		}
	}
}

// commitBatch performs one group commit: a single SQLite transaction that
// inserts every event row, then — still logically part of the same
// ingestion step — advances each affected session's in-memory chain state,
// sealing segments and writing checkpoints that become due. A commit-time
// error is fatal to the writer goroutine (see Writer.Err): SQLite write
// failures on a local single-writer append-only ledger are not expected in
// normal operation, and silently continuing past one would risk gaps that
// are not honestly recorded (P5).
func (w *Writer) commitBatch(batch []pendingEvent) {
	if len(batch) == 0 {
		return
	}
	start := time.Now()
	err := w.commitBatchTx(batch)
	if w.opts.onCommitDurationHook != nil {
		w.opts.onCommitDurationHook(time.Since(start))
	}
	if err != nil {
		w.mu.Lock()
		if w.commitErr == nil {
			w.commitErr = err
		}
		w.mu.Unlock()
	}
}

func (w *Writer) commitBatchTx(batch []pendingEvent) error {
	tx, err := w.db.Begin()
	if err != nil {
		return fmt.Errorf("ledger: beginning group-commit transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	stmt, err := tx.Prepare(`INSERT INTO events(session, seg, idx, ts_mono, ts_wall, type, pid, bytes) VALUES (?,?,?,?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("ledger: preparing insert: %w", err)
	}
	defer stmt.Close()

	w.mu.Lock()
	defer w.mu.Unlock()

	touched := make(map[string]bool)

	for _, pe := range batch {
		ev := pe.ev
		st, err := w.openOrInitSessionLocked(tx, ev.Session)
		if err != nil {
			return err
		}
		if !st.segOpen {
			st.segOpen = true
			st.segFirstTs = time.Unix(0, int64(w.clock.Now()))
			st.segLeaves = st.segLeaves[:0]
			st.segGapCounts = map[string]uint64{}
		}

		// The events.seg column records the WRITER's actual segment
		// assignment (st.segIndex) — the segment an event lands in is a
		// sealing-time decision the writer alone makes; a caller-supplied
		// ev.Seg (part of the canonical, already-hashed event bytes) is
		// data, not segment-membership ground truth. Segment membership
		// for verification purposes is authoritatively the sealed
		// segment's [first_rowid,last_rowid] range (see readSegmentEvents
		// in verify.go), which this column mirrors for query convenience.
		// Bind uint64 fields as int64: modernc.org/sqlite rejects uint64
		// query args whose value is >= 1<<63 outright ("high bit set"),
		// and sqlite's own INTEGER storage is signed 64-bit regardless —
		// casting here is a safe, permanent normalization, not a
		// truncation risk for any value this package produces.
		res, err := stmt.Exec(ev.Session, int64(st.segIndex), int64(ev.Idx), int64(ev.TsMono), int64(ev.TsWall), string(ev.Type), ev.Pid, pe.enc)
		if err != nil {
			return fmt.Errorf("ledger: inserting event: %w", err)
		}
		rowID, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("ledger: reading inserted rowid: %w", err)
		}

		if st.segFirstRow == 0 {
			st.segFirstRow = rowID
		}
		st.segLastRow = rowID
		st.segLeaves = append(st.segLeaves, pe.leaf)

		if ev.Type == schema.EventTypeGap {
			if reasonStr := gapReasonString(ev); reasonStr != "" {
				st.segGapCounts[reasonStr]++
			}
		}

		touched[ev.Session] = true

		// Seal immediately once this event has pushed the open segment to
		// (or past) its threshold, rather than only once at the end of
		// the whole batch — a single group commit can easily contain
		// several segments' worth of events (e.g. a 512-event batch
		// against a 4096-event seal threshold does not seal mid-batch,
		// but a small SegSealMaxEvents in tests, or a burst larger than
		// one seal's worth in production, must still seal every threshold
		// crossing, not just the last one).
		if err := w.maybeSealLocked(tx, ev.Session, st, false); err != nil {
			return err
		}
	}

	// Final pass: age-based seals (segments that crossed the age
	// threshold without a further event to trigger the inline check
	// above) for every session touched by this batch.
	for session := range touched {
		st := w.sessions[session]
		if err := w.maybeSealLocked(tx, session, st, false); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ledger: committing group-commit transaction: %w", err)
	}
	committed = true
	return nil
}

// gapReasonString extracts the redact.Redacted "reason" field of a gap
// event as a plain string for internal bookkeeping (gap summaries are
// counts keyed by the frozen reason vocabulary, never free text — safe to
// un-Redact for this internal, non-persisted use).
func gapReasonString(ev schema.Event) string {
	v, ok := ev.Data["reason"]
	if !ok {
		return ""
	}
	// redact.Redacted has underlying kind string; fmt.Sprintf handles any
	// Stringer-less named string type uniformly without importing redact
	// here (avoids a needless import for a one-line conversion).
	return fmt.Sprintf("%v", v)
}

// openOrInitSessionLocked returns the in-memory chain state for session,
// creating the sessions row and loading persisted chain state from the
// database on first touch. Caller must hold w.mu.
func (w *Writer) openOrInitSessionLocked(tx *sql.Tx, session string) (*sessionState, error) {
	if st, ok := w.sessions[session]; ok {
		return st, nil
	}

	var exists bool
	row := tx.QueryRow(`SELECT 1 FROM sessions WHERE id = ?`, session)
	if err := row.Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			if _, err := tx.Exec(`INSERT INTO sessions(id, started_ns) VALUES (?, ?)`, session, int64(w.clock.Now())); err != nil {
				return nil, fmt.Errorf("ledger: inserting session row: %w", err)
			}
		} else {
			return nil, fmt.Errorf("ledger: checking session row: %w", err)
		}
	}

	st := &sessionState{segGapCounts: map[string]uint64{}}

	// Rebuild prevSegHash and segIndex from the last sealed segment, if any.
	var segIdx uint64
	var segHash []byte
	row = tx.QueryRow(`SELECT seg, seg_hash FROM segments WHERE session = ? ORDER BY seg DESC LIMIT 1`, session)
	err := row.Scan(&segIdx, &segHash)
	switch {
	case err == sql.ErrNoRows:
		st.segIndex = 0
	case err != nil:
		return nil, fmt.Errorf("ledger: loading last segment: %w", err)
	default:
		st.segIndex = segIdx + 1
		copy(st.prevSegHash[:], segHash)
	}

	// Count sealed-but-unsigned segments and find the oldest such seal
	// time, to correctly resume checkpoint-cadence bookkeeping across a
	// process restart.
	pending, oldest, err := loadPendingSegStats(tx, session)
	if err != nil {
		return nil, err
	}
	st.pendingSegsSinceCheckpoint = pending
	if pending > 0 {
		st.haveOldestUnsigned = true
		st.oldestUnsignedSealedAt = oldest
	}

	w.sessions[session] = st
	return st, nil
}

// loadPendingSegStats returns the count of sealed segments for session
// that have not yet been covered by a checkpoint, and the sealed_ns of the
// oldest such segment.
func loadPendingSegStats(tx *sql.Tx, session string) (count int, oldest time.Time, err error) {
	var lastCheckpointedSeg sql.NullInt64
	row := tx.QueryRow(`SELECT MAX(seg_last) FROM checkpoints WHERE session = ?`, session)
	if err := row.Scan(&lastCheckpointedSeg); err != nil && err != sql.ErrNoRows {
		return 0, time.Time{}, fmt.Errorf("ledger: loading last checkpointed seg: %w", err)
	}

	var query string
	var args []any
	if lastCheckpointedSeg.Valid {
		query = `SELECT seg, sealed_ns FROM segments WHERE session = ? AND seg > ? ORDER BY seg ASC`
		args = []any{session, lastCheckpointedSeg.Int64}
	} else {
		query = `SELECT seg, sealed_ns FROM segments WHERE session = ? ORDER BY seg ASC`
		args = []any{session}
	}

	rows, err := tx.Query(query, args...)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("ledger: loading pending segments: %w", err)
	}
	defer rows.Close()

	first := true
	for rows.Next() {
		var seg uint64
		var sealedNs int64
		if err := rows.Scan(&seg, &sealedNs); err != nil {
			return 0, time.Time{}, fmt.Errorf("ledger: scanning pending segment: %w", err)
		}
		count++
		if first {
			oldest = time.Unix(0, sealedNs)
			first = false
		}
	}
	return count, oldest, rows.Err()
}

// maybeSealLocked seals session's currently-open segment if it has reached
// the event-count or age threshold, or if force is true (session.end /
// explicit flush). Caller holds w.mu and an open tx.
func (w *Writer) maybeSealLocked(tx *sql.Tx, session string, st *sessionState, force bool) error {
	if !st.segOpen || len(st.segLeaves) == 0 {
		return nil
	}

	age := time.Duration(int64(w.clock.Now()) - st.segFirstTs.UnixNano())
	due := force || len(st.segLeaves) >= w.opts.segSealMaxEvents() || age >= w.opts.segSealMaxAge()
	if !due {
		return nil
	}

	root := chain.MerkleRoot(st.segLeaves)
	header := chain.SegHeader{
		SessionID:    session,
		SegIndex:     st.segIndex,
		FirstRowID:   st.segFirstRow,
		LastRowID:    st.segLastRow,
		EventCount:   uint64(len(st.segLeaves)),
		MerkleRoot:   root,
		PrevSegHash:  st.prevSegHash,
		GapSummary:   copyGapCounts(st.segGapCounts),
		SealedAtWall: w.clock.Now(),
	}
	segHash, headerCBOR, err := chain.SegHash(header)
	if err != nil {
		return fmt.Errorf("ledger: hashing segment header: %w", err)
	}

	gapBlob, err := marshalGapSummary(header.GapSummary)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`INSERT INTO segments(session, seg, first_rowid, last_rowid, event_count, merkle_root, prev_seg_hash, seg_hash, gap, sealed_ns, header, archived_path)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL)`,
		session, int64(header.SegIndex), header.FirstRowID, header.LastRowID, int64(header.EventCount),
		root[:], header.PrevSegHash[:], segHash[:], gapBlob, int64(header.SealedAtWall), headerCBOR)
	if err != nil {
		return fmt.Errorf("ledger: inserting sealed segment: %w", err)
	}

	st.prevSegHash = segHash
	st.segIndex++
	st.segOpen = false
	st.segLeaves = nil
	st.segFirstRow = 0
	st.segLastRow = 0
	st.segGapCounts = map[string]uint64{}

	st.pendingSegsSinceCheckpoint++
	if !st.haveOldestUnsigned {
		st.haveOldestUnsigned = true
		st.oldestUnsignedSealedAt = time.Unix(0, int64(header.SealedAtWall))
	}

	return w.maybeCheckpointLocked(tx, session, st, segHash, header.SegIndex, force)
}

// maybeCheckpointLocked writes a signed checkpoint for session if the
// sealed-but-unsigned segment count or pending age has crossed the
// configured threshold, or if force is true (session.end).
func (w *Writer) maybeCheckpointLocked(tx *sql.Tx, session string, st *sessionState, chainHead [32]byte, lastSeg uint64, force bool) error {
	if st.pendingSegsSinceCheckpoint == 0 {
		return nil
	}

	age := time.Duration(0)
	if st.haveOldestUnsigned {
		age = time.Duration(int64(w.clock.Now()) - st.oldestUnsignedSealedAt.UnixNano())
	}

	due := force || st.pendingSegsSinceCheckpoint >= w.opts.checkpointMaxSegs() || age >= w.opts.checkpointMaxWait()
	if !due {
		return nil
	}

	if len(w.opts.Key.PrivateKey) == 0 {
		// No signing key configured: leave segments sealed-but-unattested
		// rather than fail the batch. Production callers always supply a
		// key; tests that only exercise sealing may not.
		return nil
	}

	firstSeg := lastSeg - uint64(st.pendingSegsSinceCheckpoint) + 1

	ck := chain.Checkpoint{
		SessionID:          session,
		SegFirst:           firstSeg,
		SegLast:            lastSeg,
		ChainHead:          chainHead,
		PrevCheckpointHash: w.ledgerPrevCkptHash,
		SignedAtWall:       w.clock.Now(),
		PubkeyID:           w.opts.Key.PubkeyID,
	}
	body, sig, err := chain.SignCheckpoint(w.opts.Key.PrivateKey, ck)
	if err != nil {
		return fmt.Errorf("ledger: signing checkpoint: %w", err)
	}
	ckptHash := chain.CheckpointHash(body)

	_, err = tx.Exec(`INSERT INTO checkpoints(session, seg_first, seg_last, chain_head, prev_hash, body, sig, pubkey_id, signed_ns)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		session, int64(ck.SegFirst), int64(ck.SegLast), ck.ChainHead[:], ck.PrevCheckpointHash[:], body, sig, ck.PubkeyID, int64(ck.SignedAtWall))
	if err != nil {
		return fmt.Errorf("ledger: inserting checkpoint: %w", err)
	}

	w.ledgerPrevCkptHash = ckptHash
	st.pendingSegsSinceCheckpoint = 0
	st.haveOldestUnsigned = false

	if w.opts.OnHeadReport != nil {
		w.opts.OnHeadReport(chain.HeadReport{
			SessionID: session,
			SegLast:   lastSeg,
			ChainHead: chainHead,
			CkptHash:  ckptHash,
			At:        ck.SignedAtWall,
		})
	}

	return nil
}
