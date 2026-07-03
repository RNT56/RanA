package ledger

import (
	"database/sql"
	"fmt"
)

// FlushForTest blocks until the writer loop has performed one flush cycle
// (a group commit of everything queued so far, even if neither the
// event-count nor timer threshold has been reached). It exists purely for
// deterministic tests; production callers rely on the count/timer
// thresholds. Requires the Writer to have been constructed via
// newWriterWithClock (which always installs the internal flush-trigger
// channel used here).
func (w *Writer) FlushForTest() error {
	done := make(chan struct{})
	select {
	case w.flushCh <- done:
	case <-w.closeCh:
		return ErrWriterClosed
	}
	<-done
	return nil
}

// AdvanceAndSync advances fc by dNs nanoseconds and blocks until the
// writer loop has processed (at least) one resulting timer-driven flush
// iteration. It requires the Writer to have been constructed with the
// same fc (via newWriterWithClock).
func (w *Writer) AdvanceAndSync(fc *fakeClock, dNs uint64) {
	fc.Advance(dNs)
	<-w.syncCh
}

// countEventsForSession returns the number of rows in events for session.
func countEventsForSession(db *sql.DB, session string) (int, error) {
	var n int
	row := db.QueryRow(`SELECT COUNT(*) FROM events WHERE session = ?`, session)
	if err := row.Scan(&n); err != nil {
		return 0, fmt.Errorf("ledger: counting events: %w", err)
	}
	return n, nil
}

// readEventRowIDs returns every rowid for session's events, in ascending
// order.
func readEventRowIDs(db *sql.DB, session string) ([]int64, error) {
	rows, err := db.Query(`SELECT rowid FROM events WHERE session = ? ORDER BY rowid ASC`, session)
	if err != nil {
		return nil, fmt.Errorf("ledger: querying event rowids: %w", err)
	}
	defer rows.Close()

	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("ledger: scanning rowid: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
