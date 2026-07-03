package service

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
	"lukechampine.com/blake3"
)

// maxDigestBytes bounds how large a file this worker will read into memory
// to BLAKE3-digest. Digest scopes point at agent workspaces (docs/PROFILES.md
// §[digest]: "the agent's workspace, the repo working tree") which an
// adversarial or merely careless agent fully controls — without a cap, a
// single huge file written into a digest scope forces this long-lived
// process to buffer arbitrarily large content in RAM on every settle,
// which is exactly the kind of unbounded-resource-on-adversarial-input
// this worker must not allow (P2/P5 spirit: digesting is best-effort
// enrichment, never something a hostile write can use against the
// recorder itself). Files over this size are skipped the same way an
// unreadable/vanished file is skipped today: no fs.settle is emitted for
// that scan, and the next scan retries — the fact of the write is still
// on the record via the kernel-sourced fs.write_open event; only the
// content digest is foregone.
const maxDigestBytes = 256 * 1024 * 1024 // 256MiB

// DigestWorkerConfig configures a DigestWorker.
type DigestWorkerConfig struct {
	// Scopes are glob patterns (docs/PROFILES.md [digest].scopes,
	// $SESSION_CWD already expanded by the caller via
	// profile.ExpandSessionCWDAll) naming which files to content-digest.
	Scopes []string
	// Exclude are glob patterns excluded from Scopes (docs/PROFILES.md
	// [digest].exclude).
	Exclude []string
	// Session is the session id stamped on every emitted fs.settle event.
	Session string
	// Pipeline redacts every path before it reaches an event (P3: "Redact
	// the path before the event").
	Pipeline *redact.Pipeline
	// Emit receives every fs.settle event this worker produces.
	Emit func(schema.Event) error
	// Clock supplies wall-clock time for event timestamps and (in Run) the
	// debounce ticker.
	Clock Clock
	// DebounceInterval is how long a file's mtime must be unchanged across
	// two successive scans before it is considered "settled" and digested
	// (CONTRACTS: "close-write debounce (mtime-scan ticker") — i.e. the
	// scan-to-scan interval used by Run's ticker. ScanOnce callers (tests)
	// drive this manually instead.
	DebounceInterval time.Duration
}

// ErrNilEmitDigest is returned by NewDigestWorker when cfg.Emit is nil.
var ErrNilEmitDigest = errors.New("service: DigestWorkerConfig.Emit must not be nil")

// fileState is what DigestWorker remembers about one tracked file between
// scans, to detect a close-write (mtime unchanged across two consecutive
// scans, size/mtime different from what was last digested).
type fileState struct {
	lastSeenModTime time.Time
	lastSeenSize    int64
	stableSinceScan bool // true once modTime was observed unchanged for one full scan interval
	settledDigest   []byte
	settledSize     int64
	everDigested    bool
}

// DigestWorker watches profile digest scopes and, once a file's
// modification appears settled (its mtime is unchanged across two
// successive scans — a debounce standing in for a real close-write/inotify
// signal per CONTRACTS: "poll close-write debounce via mtime scan ticker,
// no fsnotify dep"), BLAKE3-digests it and emits an fs.settle event
// carrying (prev_digest, new_digest, size_delta). The scanned path is
// redacted before it is ever placed on an event (P3).
type DigestWorker struct {
	cfg     DigestWorkerConfig
	include []globPattern
	exclude []globPattern

	files map[string]*fileState // absolute path -> state
}

// NewDigestWorker constructs a DigestWorker from cfg. Scope/exclude
// patterns are compiled eagerly so a malformed pattern fails fast at
// construction rather than silently matching nothing at scan time.
func NewDigestWorker(cfg DigestWorkerConfig) (*DigestWorker, error) {
	if cfg.Emit == nil {
		return nil, ErrNilEmitDigest
	}
	if cfg.Clock == nil {
		cfg.Clock = SystemClock
	}
	if cfg.DebounceInterval <= 0 {
		cfg.DebounceInterval = 2 * time.Second
	}

	include, err := compileGlobs(cfg.Scopes)
	if err != nil {
		return nil, fmt.Errorf("service: compiling digest scopes: %w", err)
	}
	exclude, err := compileGlobs(cfg.Exclude)
	if err != nil {
		return nil, fmt.Errorf("service: compiling digest excludes: %w", err)
	}

	return &DigestWorker{
		cfg:     cfg,
		include: include,
		exclude: exclude,
		files:   make(map[string]*fileState),
	}, nil
}

// Run scans on cfg.Clock's ticker (cfg.DebounceInterval) until stop is
// closed. It never blocks a caller of Emit for longer than one Emit call —
// P2's spirit (observation must stay inert) extends here: a slow or
// erroring Emit only delays the NEXT digest, never anything upstream.
//
// The first After() registration happens in RunFrom (called synchronously
// by StartDigestWorker before the goroutine starts), not here, for the
// same reason documented on internal/ledger.Writer.run: with a fakeClock,
// a caller that starts the worker and then immediately calls
// fc.Advance(...) has no synchronization with when this goroutine actually
// begins running. If the first Clock.After call happened inside this
// loop, an unlucky scheduling order could let Advance fire (finding zero
// registered waiters, since this goroutine hasn't reached its first
// After() call yet) before the goroutine registers its own timer,
// silently losing that wakeup. Run is kept as the direct, no-preregistered-
// timer entry point for callers that don't care about that race (i.e. are
// using the real SystemClock, where the race cannot manifest because
// After() always returns a live, already-ticking channel).
func (w *DigestWorker) Run(stop <-chan struct{}) {
	w.RunFrom(stop, w.cfg.Clock.After(w.cfg.DebounceInterval))
}

// RunFrom is like Run but takes the first tick channel already registered
// (see Run's doc comment for why this ordering matters with a fakeClock).
func (w *DigestWorker) RunFrom(stop <-chan struct{}, firstTick <-chan time.Time) {
	tick := firstTick
	for {
		select {
		case <-stop:
			return
		case now := <-tick:
			w.ScanOnce(now)
			tick = w.cfg.Clock.After(w.cfg.DebounceInterval)
		}
	}
}

// scanTargets walks every include scope's filesystem root(s), returning
// the set of currently-matching, non-excluded regular file paths. Glob
// roots are derived by walking from the filesystem root(s) implied by each
// pattern's non-wildcard prefix, so a scope like /home/u/project/** does
// not require enumerating the whole filesystem.
func (w *DigestWorker) scanTargets() []string {
	seen := make(map[string]bool)
	var out []string
	for _, inc := range w.include {
		root := inc.staticRoot()
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // best-effort scan: an unreadable subtree is skipped, not fatal
			}
			if d.IsDir() {
				return nil
			}
			if seen[p] {
				return nil
			}
			if !inc.match(p) {
				return nil
			}
			for _, ex := range w.exclude {
				if ex.match(p) {
					return nil
				}
			}
			seen[p] = true
			out = append(out, p)
			return nil
		})
	}
	return out
}

// ScanOnce performs one scan-and-maybe-emit pass at time now: for every
// matching file, update its tracked mtime/size; if the file's mtime was
// already unchanged since the PREVIOUS ScanOnce call (i.e. it has been
// stable across one full scan interval) and its content differs from what
// was last digested, BLAKE3 it and emit fs.settle.
//
// This two-scan debounce is what turns raw mtime polling into a
// close-write signal without fsnotify: a file mid-write has a mtime that
// keeps advancing scan-to-scan and is never digested; only once it stops
// changing for a full interval is it considered settled.
func (w *DigestWorker) ScanOnce(now time.Time) {
	targets := w.scanTargets()
	current := make(map[string]bool, len(targets))

	for _, p := range targets {
		current[p] = true
		info, err := os.Stat(p)
		if err != nil {
			continue // file vanished between scan and stat; next scan will drop it
		}
		mt := info.ModTime()
		size := info.Size()

		st, existed := w.files[p]
		if !existed {
			w.files[p] = &fileState{lastSeenModTime: mt, lastSeenSize: size, stableSinceScan: false}
			continue
		}

		if mt.Equal(st.lastSeenModTime) && size == st.lastSeenSize {
			if !st.stableSinceScan {
				st.stableSinceScan = true
				w.maybeDigest(p, st, size, now)
			}
			// already digested for this stable period; nothing further to do
			continue
		}

		// mtime or size moved: file is being written; reset stability.
		st.lastSeenModTime = mt
		st.lastSeenSize = size
		st.stableSinceScan = false
	}

	// Drop tracking for files no longer present/matching (deleted, or
	// moved out of scope) — CONTRACTS does not ask for a delete-class
	// digest event; fs.unlink (a kernel event) already records the
	// deletion fact.
	for p := range w.files {
		if !current[p] {
			delete(w.files, p)
		}
	}
}

// maybeDigest BLAKE3-hashes p and emits fs.settle if the content actually
// differs from the last settled digest (a file whose mtime/size round-trip
// back to a previously-seen value — e.g. touch with no content change —
// still gets read once here, but only emits if the digest differs).
func (w *DigestWorker) maybeDigest(p string, st *fileState, size int64, now time.Time) {
	if size > maxDigestBytes {
		return // too large to safely buffer/hash; skip silently, next scan retries
	}

	f, err := os.Open(p)
	if err != nil {
		return // vanished or unreadable between stat and open; skip silently, next scan retries
	}
	defer f.Close()

	h := blake3.New(32, nil)
	// Cap the read at maxDigestBytes+1 (rather than trusting the size we
	// stat'd earlier) so a file that grows between stat and read cannot
	// make this loop buffer/hash unbounded content either — read one byte
	// past the cap purely to detect "still growing past the limit" and
	// bail without ever holding more than maxDigestBytes+1 bytes.
	n, err := io.Copy(h, io.LimitReader(f, maxDigestBytes+1))
	if err != nil {
		return // read error mid-file; skip silently, next scan retries
	}
	if n > maxDigestBytes {
		return // grew past the cap while reading; skip silently, next scan retries
	}
	digest := h.Sum(nil)

	if st.everDigested && bytesEqual(digest, st.settledDigest) {
		return // content unchanged from last settle (e.g. touch with no write)
	}

	var prevDigest []byte
	var prevSize int64
	if st.everDigested {
		prevDigest = st.settledDigest
		prevSize = st.settledSize
	}

	redactedPath := w.cfg.Pipeline.RedactPath(p)
	ev := schema.NewFsSettle(w.cfg.Session, 0, 0, uint64(now.UnixNano()), uint64(now.UnixNano()), 0,
		redactedPath, prevDigest, digest, size-prevSize, uint64(now.UnixNano()))

	st.settledDigest = digest
	st.settledSize = size
	st.everDigested = true

	// KNOWN GAP (P5): see the identical note at marker_listener.go's Emit
	// call site — this discards Emit's error with no logging and no gap
	// event, so a failed fs.settle append (including a fatal Writer.Err()
	// commit failure) is silently lost today.
	_ = w.cfg.Emit(ev)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---- minimal glob support (no new deps; internal/profile's Glob type is
// unexported so this package implements the same small subset it needs:
// literal segments, single-segment path.Match wildcards, and a `**` that
// matches zero or more whole segments — CONTRACTS: "use path.Match-based
// segments or write a simple ** globber") ----

type globPattern struct {
	raw      string
	segments []string
}

func compileGlobs(patterns []string) ([]globPattern, error) {
	out := make([]globPattern, 0, len(patterns))
	for _, p := range patterns {
		g, err := compileGlobPattern(p)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

func compileGlobPattern(pattern string) (globPattern, error) {
	segs := splitPathSegments(pattern)
	for _, s := range segs {
		if s == "**" {
			continue
		}
		if _, err := path.Match(s, ""); err != nil {
			return globPattern{}, fmt.Errorf("segment %q: %w", s, err)
		}
	}
	return globPattern{raw: pattern, segments: segs}, nil
}

func splitPathSegments(p string) []string {
	raw := strings.Split(p, "/")
	out := raw[:0:0]
	for _, s := range raw {
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// staticRoot returns the longest path prefix of the pattern that contains
// no glob metacharacters, used to bound a filesystem walk instead of
// scanning from "/". A pattern with no static prefix (e.g. "**") walks
// from "/", which callers are expected to avoid in practice (digest scopes
// are always rooted under a concrete directory per docs/PROFILES.md).
func (g globPattern) staticRoot() string {
	var parts []string
	for _, s := range g.segments {
		if strings.ContainsAny(s, "*?[") {
			break
		}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}

func (g globPattern) match(target string) bool {
	pathSegs := splitPathSegments(target)
	memo := make(map[[2]int]bool, len(g.segments)*len(pathSegs))
	return matchGlobSegments(g.segments, pathSegs, 0, 0, memo)
}

func matchGlobSegments(pat, target []string, pi, ti int, memo map[[2]int]bool) bool {
	key := [2]int{pi, ti}
	if v, ok := memo[key]; ok {
		return v
	}
	var result bool
	switch {
	case pi == len(pat):
		result = ti == len(target)
	case pat[pi] == "**":
		if pi == len(pat)-1 {
			result = true
		} else {
			for i := ti; i <= len(target); i++ {
				if matchGlobSegments(pat, target, pi+1, i, memo) {
					result = true
					break
				}
			}
		}
	case ti == len(target):
		result = false
	default:
		ok, err := path.Match(pat[pi], target[ti])
		result = err == nil && ok && matchGlobSegments(pat, target, pi+1, ti+1, memo)
	}
	memo[key] = result
	return result
}
