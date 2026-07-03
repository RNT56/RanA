package ledger

import "fmt"

// SealSession forces session's currently-open segment (if any) to seal
// immediately, and writes a checkpoint if any segments are pending,
// regardless of whether the normal count/age/cadence thresholds have been
// reached. Callers (svc) invoke this at session.end (docs/TRUST.md §5:
// checkpoints are written "at session.end"). It is synchronous: by the
// time SealSession returns, the seal (and, if due, a checkpoint) has been
// durably committed.
func (w *Writer) SealSession(session string) error {
	done := make(chan struct{})
	errCh := make(chan error, 1)
	select {
	case w.sealCh <- sealRequest{session: session, done: done, errCh: errCh}:
	case <-w.closeCh:
		return ErrWriterClosed
	}
	<-done
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// sealRequest asks the writer loop to force-seal (and checkpoint if due)
// an open segment for session, outside the normal count/age/cadence
// thresholds.
type sealRequest struct {
	session string
	done    chan struct{}
	errCh   chan error
}

// forceSealSession performs the actual force-seal, called from the writer
// goroutine (which already serializes all database access).
func (w *Writer) forceSealSession(session string) error {
	tx, err := w.db.Begin()
	if err != nil {
		return fmt.Errorf("ledger: beginning seal transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	w.mu.Lock()
	defer w.mu.Unlock()

	st, err := w.openOrInitSessionLocked(tx, session)
	if err != nil {
		return err
	}
	if err := w.maybeSealLocked(tx, session, st, true); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ledger: committing seal transaction: %w", err)
	}
	committed = true
	return nil
}
