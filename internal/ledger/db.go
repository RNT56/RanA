package ledger

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // driver name "sqlite"
)

// schemaDDL creates every ledger table if it does not already exist
// (CONTRACTS §internal/ledger). bytes columns hold full canonical event /
// header / checkpoint-body CBOR; paths/event_paths are a search index only,
// never load-bearing for chain verification.
const schemaDDL = `
CREATE TABLE IF NOT EXISTS sessions (
	id         TEXT PRIMARY KEY,
	profile    TEXT,
	started_ns INTEGER,
	ended_ns   INTEGER,
	host       BLOB,
	caveats    TEXT
);

CREATE TABLE IF NOT EXISTS events (
	rowid    INTEGER PRIMARY KEY,
	session  TEXT,
	seg      INTEGER,
	idx      INTEGER,
	ts_mono  INTEGER,
	ts_wall  INTEGER,
	type     TEXT,
	pid      INTEGER,
	bytes    BLOB
);
CREATE INDEX IF NOT EXISTS idx_events_session_seg ON events(session, seg);

CREATE TABLE IF NOT EXISTS segments (
	session       TEXT,
	seg           INTEGER,
	first_rowid   INTEGER,
	last_rowid    INTEGER,
	event_count   INTEGER,
	merkle_root   BLOB,
	prev_seg_hash BLOB,
	seg_hash      BLOB,
	gap           BLOB,
	sealed_ns     INTEGER,
	header        BLOB,
	archived_path TEXT,
	PRIMARY KEY(session, seg)
);

CREATE TABLE IF NOT EXISTS checkpoints (
	cid        INTEGER PRIMARY KEY,
	session    TEXT,
	seg_first  INTEGER,
	seg_last   INTEGER,
	chain_head BLOB,
	prev_hash  BLOB,
	body       BLOB,
	sig        BLOB,
	pubkey_id  TEXT,
	signed_ns  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_checkpoints_session ON checkpoints(session);

CREATE TABLE IF NOT EXISTS digests (
	session TEXT,
	path    TEXT,
	prev    BLOB,
	new     BLOB,
	size_delta INTEGER,
	at_ns   INTEGER
);

CREATE TABLE IF NOT EXISTS paths (
	id        INTEGER PRIMARY KEY,
	canonical TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS event_paths (
	rowid   INTEGER,
	path_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_event_paths_path ON event_paths(path_id);

CREATE TABLE IF NOT EXISTS meta (
	k TEXT PRIMARY KEY,
	v BLOB
);
`

// openDB opens (creating if necessary) the SQLite database at path with
// RanA's canonical pragmas: WAL journal mode, synchronous=NORMAL, and a
// busy_timeout so concurrent readers (e.g. the timeline UI, `rana verify`)
// never spuriously fail against the single writer goroutine (CONTRACTS
// §internal/ledger). It then ensures the schema (CREATE IF NOT EXISTS).
func openDB(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("ledger: opening sqlite db %s: %w", path, err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ledger: connecting to sqlite db %s: %w", path, err)
	}

	// Single-writer discipline (CONTRACTS: "single writer goroutine"): cap
	// the pool so SQLite-level lock contention cannot silently serialize
	// writers we didn't intend to allow.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("ledger: setting journal_mode: %w", err)
	}
	if _, err := db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("ledger: setting synchronous: %w", err)
	}
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		db.Close()
		return nil, fmt.Errorf("ledger: setting busy_timeout: %w", err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		db.Close()
		return nil, fmt.Errorf("ledger: setting foreign_keys: %w", err)
	}

	if _, err := db.Exec(schemaDDL); err != nil {
		db.Close()
		return nil, fmt.Errorf("ledger: creating schema: %w", err)
	}

	return db, nil
}
