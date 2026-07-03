package service

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"

	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/schema"
	"github.com/RNT56/RanA/internal/ui"

	_ "modernc.org/sqlite" // driver name "sqlite" — same driver internal/ledger uses
)

// LedgerDataSource implements ui.DataSource by reading directly from a
// ledger.Datadir's SQLite database (read-only queries only — svc's
// ledger.Writer remains the ledger's sole writer, per internal/ledger's
// single-writer discipline). internal/ledger exposes no public read API of
// its own (its exported surface is Writer/Verify/Export/GC), so this type
// reads the documented CONTRACTS §internal/ledger schema directly: events
// rows store full canonical event CBOR in `bytes`, decoded here with
// cborcanon.Decode the same way internal/wire's ranad-socket receive path
// and cmd/rana-verify-standalone do. If internal/ledger's on-disk schema
// ever changes, this reader (and the mirrored decode struct in
// ranad_server.go) must change with it — that coupling is the direct
// consequence of CONTRACTS not defining a read API for internal/ledger; see
// the final report's "conflict" note.
type LedgerDataSource struct {
	db *sql.DB

	mu   sync.Mutex
	subs map[string][]chan schema.Event // session -> live subscriber channels
}

var _ ui.DataSource = (*LedgerDataSource)(nil)

// NewLedgerDataSource opens a read-only connection to dir's ledger
// database. It does not create the database file — a ledger.Writer for the
// same Datadir must already have been constructed at least once (Service
// wires this by always constructing its ledger.Writer before its
// LedgerDataSource, which matches natural startup order: nothing to show
// in the timeline before the writer exists). Querying an empty/fresh
// ledger (a database that exists but has no rows yet) is legal and returns
// empty results.
func NewLedgerDataSource(dir ledger.Datadir) (*LedgerDataSource, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(5000)", dir.DBPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("service: opening ledger db read-only: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("service: connecting to ledger db read-only: %w", err)
	}
	return &LedgerDataSource{db: db, subs: make(map[string][]chan schema.Event)}, nil
}

// Close releases the underlying database connection.
func (ds *LedgerDataSource) Close() error {
	return ds.db.Close()
}

// Sessions implements ui.DataSource.
func (ds *LedgerDataSource) Sessions(ctx context.Context) ([]ui.SessionSummary, error) {
	rows, err := ds.db.QueryContext(ctx, `SELECT id, profile, started_ns, ended_ns FROM sessions ORDER BY started_ns ASC`)
	if err != nil {
		return nil, fmt.Errorf("service: querying sessions: %w", err)
	}
	defer rows.Close()

	var out []ui.SessionSummary
	for rows.Next() {
		var s ui.SessionSummary
		var profile sql.NullString
		var started, ended sql.NullInt64
		if err := rows.Scan(&s.ID, &profile, &started, &ended); err != nil {
			return nil, fmt.Errorf("service: scanning session row: %w", err)
		}
		s.Profile = profile.String
		s.StartedNs = uint64(started.Int64)
		s.EndedNs = uint64(ended.Int64)
		out = append(out, s)
	}
	return out, rows.Err()
}

// Events implements ui.DataSource: events for sessionID with Idx > after,
// oldest first, capped at limit (<=0 means no cap).
func (ds *LedgerDataSource) Events(ctx context.Context, sessionID string, after uint64, limit int) ([]schema.Event, error) {
	query := `SELECT bytes FROM events WHERE session = ? AND idx > ? ORDER BY idx ASC`
	args := []any{sessionID, after}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := ds.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("service: querying events: %w", err)
	}
	defer rows.Close()

	var out []schema.Event
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("service: scanning event row: %w", err)
		}
		if raw == nil {
			continue // GC'd/archived row (bytes nulled out per CONTRACTS GC) — skip rather than error
		}
		var ev schema.Event
		if err := decodeEventFrame(raw, &ev); err != nil {
			return nil, fmt.Errorf("service: decoding event row: %w", err)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// alertTypePrefix is the EventType prefix that identifies an alert event.
// Kept in sync with schema's alert.* EventType constants.
const alertTypePrefix = "alert."

// Alerts implements ui.DataSource: every alert.* event for sessionID.
//
// This deliberately does NOT filter using the events table's `type` mirror
// column (unlike a naive `WHERE type LIKE 'alert.%'`): that column is
// written but never hashed or cross-checked by chain verification (see
// internal/ledger/export.go's decodeEventEnvelopeFields and
// export_test.go), so an attacker with raw sqlite write access to
// ledger.db could UPDATE it to hide a real alert row or fabricate a fake
// one in the live UI without `rana verify` ever noticing — the persisted,
// hashed `bytes` column would be untouched. Filtering on the decoded
// ev.Type instead (the same authoritative field export and verify trust)
// closes that gap for the live alert feed too. Alerts are a low-volume
// event class, so the extra per-row decode cost of scanning every event
// in the session is acceptable.
func (ds *LedgerDataSource) Alerts(ctx context.Context, sessionID string) ([]schema.Event, error) {
	rows, err := ds.db.QueryContext(ctx, `SELECT bytes FROM events WHERE session = ? ORDER BY idx ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("service: querying alerts: %w", err)
	}
	defer rows.Close()

	var out []schema.Event
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("service: scanning alert row: %w", err)
		}
		if raw == nil {
			continue
		}
		var ev schema.Event
		if err := decodeEventFrame(raw, &ev); err != nil {
			return nil, fmt.Errorf("service: decoding alert row: %w", err)
		}
		if !strings.HasPrefix(string(ev.Type), alertTypePrefix) {
			continue
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// streamBufferSize bounds each Stream subscriber's channel. Per ui.
// DataSource's contract, Stream "MUST NOT block a producer elsewhere in
// the system" (P2 extended to the UI tail): PublishLive drops rather than
// blocks when a subscriber's buffer is full, so a slow browser tab can
// never back-pressure the append path.
const streamBufferSize = 256

// Stream implements ui.DataSource: a channel of events for sessionID,
// fed by PublishLive (svc calls PublishLive from its own post-Append
// hook — this DataSource does not poll the database for new rows). The
// channel is closed when ctx is done.
func (ds *LedgerDataSource) Stream(ctx context.Context, sessionID string) (<-chan schema.Event, error) {
	ch := make(chan schema.Event, streamBufferSize)

	ds.mu.Lock()
	ds.subs[sessionID] = append(ds.subs[sessionID], ch)
	ds.mu.Unlock()

	go func() {
		<-ctx.Done()
		ds.mu.Lock()
		list := ds.subs[sessionID]
		for i, c := range list {
			if c == ch {
				ds.subs[sessionID] = append(list[:i], list[i+1:]...)
				break
			}
		}
		ds.mu.Unlock()
		close(ch)
	}()

	return ch, nil
}

// PublishLive fans ev out to every active Stream subscriber for ev.Session.
// It never blocks: a subscriber whose buffer is full has the event dropped
// for it (P2 spirit — the UI tail must never be able to slow down
// capture), which is safe because Stream/PublishLive is a live-tail
// convenience only, never the record of truth (that's the ledger itself,
// queried via Events).
func (ds *LedgerDataSource) PublishLive(ev schema.Event) {
	ds.mu.Lock()
	subs := ds.subs[ev.Session]
	ds.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
			// full: drop for this slow subscriber rather than block the publisher
		}
	}
}
