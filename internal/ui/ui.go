// Package ui serves RanA's embedded, localhost-only timeline: a canvas
// "event river" (process/filesystem/network lanes), a session picker, a
// run-cluster causality view, and a live SSE tail —
// docs/ARCHITECTURE.md §4, CONTRACTS §internal/ui.
//
// The UI is a single static bundle (dist/app.js, built by esbuild from
// src/*.ts and checked in so go:embed works without a Node toolchain at
// build time — see the package README note in CONTRACTS) plus index.html.
// The HTTP handler here is deliberately data-source-agnostic: it takes a
// small DataSource interface rather than importing internal/ledger
// directly, so it is fully unit-testable against a fake.
//
// Security posture (docs/THREAT-MODEL.md): binding to
// 127.0.0.1 is the caller's job (this package never calls net.Listen).
// What this package enforces on every route: a per-launch bearer token
// (header or, for the SSE route which cannot set custom headers, a query
// parameter), a strict Content-Security-Policy (default-src 'self'), no
// cookies, and no CORS headers of any kind.
package ui

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/RNT56/RanA/internal/schema"
)

//go:embed dist
var distFS embed.FS

//go:embed index.html
var indexHTML []byte

// SessionSummary is the compact per-session listing shape served by
// /api/sessions. Field names/json tags are the wire contract with
// src/types.ts — keep them in sync.
type SessionSummary struct {
	ID        string `json:"id"`
	Profile   string `json:"profile"`
	StartedNs uint64 `json:"started_ns"`
	EndedNs   uint64 `json:"ended_ns"`
}

// wireEvent is the JSON shape sent to the browser for every event
// (/api/events, /api/alerts, /api/stream). schema.Event carries no json
// tags (it is a frozen, CBOR-first envelope owned by internal/schema, not
// ours to modify), so this package defines its own wire adapter with field
// names matching the CBOR key convention documented on schema.Event (v,
// type, session, seg, idx, ts_mono, ts_wall, pid, origin, state, data) —
// keep in sync with src/types.ts's RanaEvent.
type wireEvent struct {
	V       uint8          `json:"v"`
	Type    string         `json:"type"`
	Session string         `json:"session"`
	Seg     uint64         `json:"seg"`
	Idx     uint64         `json:"idx"`
	TsMono  uint64         `json:"ts_mono"`
	TsWall  uint64         `json:"ts_wall"`
	Pid     uint32         `json:"pid"`
	Origin  string         `json:"origin"`
	State   string         `json:"state"`
	Data    map[string]any `json:"data"`
}

func toWireEvent(ev schema.Event) wireEvent {
	data := ev.Data
	if data == nil {
		data = map[string]any{}
	}
	return wireEvent{
		V:       ev.V,
		Type:    string(ev.Type),
		Session: ev.Session,
		Seg:     ev.Seg,
		Idx:     ev.Idx,
		TsMono:  ev.TsMono,
		TsWall:  ev.TsWall,
		Pid:     ev.Pid,
		Origin:  string(ev.Origin),
		State:   string(ev.State),
		Data:    data,
	}
}

func toWireEvents(evs []schema.Event) []wireEvent {
	out := make([]wireEvent, len(evs))
	for i, ev := range evs {
		out[i] = toWireEvent(ev)
	}
	return out
}

// DataSource is the small, storage-agnostic interface the handler reads
// from. The real implementation is wired by internal/service against
// internal/ledger; tests use a fake (CONTRACTS §internal/ui: "a fake feeds
// tests so it's testable without the real ledger").
type DataSource interface {
	// Sessions returns all known sessions, most useful order left to the
	// implementation (the handler does not re-sort).
	Sessions(ctx context.Context) ([]SessionSummary, error)

	// Events returns events for sessionID with Idx > after, oldest first,
	// capped at limit (0 or negative means "no cap" — the DataSource
	// implementation decides its own sane default/ceiling).
	Events(ctx context.Context, sessionID string, after uint64, limit int) ([]schema.Event, error)

	// Alerts returns alert.* events for sessionID.
	Alerts(ctx context.Context, sessionID string) ([]schema.Event, error)

	// Stream returns a channel of live events for sessionID. The
	// implementation MUST close the channel when ctx is done and MUST NOT
	// block a producer elsewhere in the system (P2: observation is inert;
	// a slow UI reader must never back-pressure capture).
	Stream(ctx context.Context, sessionID string) (<-chan schema.Event, error)
}

// ErrEmptyToken is returned by Handler when token is empty — an empty
// token would make every route effectively unauthenticated.
var ErrEmptyToken = errors.New("ui: token must not be empty")

// ErrNilDataSource is returned by Handler when ds is nil.
var ErrNilDataSource = errors.New("ui: DataSource must not be nil")

// contentSecurityPolicy is applied to every response, API and asset alike.
// default-src 'self' with no further relaxation: the UI is a single
// same-origin bundle, it never needs inline scripts, remote fonts, or
// third-party connections.
const contentSecurityPolicy = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'"

// Handler builds the localhost timeline HTTP handler. token is the
// per-launch bearer token the caller (internal/service) generates and
// prints/opens for the user; every route requires it. Binding to
// 127.0.0.1 is the caller's responsibility (docs/ARCHITECTURE.md §4).
func Handler(token string, ds DataSource) (http.Handler, error) {
	if token == "" {
		return nil, ErrEmptyToken
	}
	if ds == nil {
		return nil, ErrNilDataSource
	}

	assets, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil, fmt.Errorf("ui: sub dist fs: %w", err)
	}

	h := &handler{token: token, ds: ds, assets: assets}

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.serveIndexOrAsset)
	mux.HandleFunc("/api/sessions", h.serveSessions)
	mux.HandleFunc("/api/events", h.serveEvents)
	mux.HandleFunc("/api/alerts", h.serveAlerts)
	mux.HandleFunc("/api/stream", h.serveStream)

	return withSecurityHeaders(withAuth(token, mux)), nil
}

type handler struct {
	token  string
	ds     DataSource
	assets fs.FS
}

// ---- middleware ----

// withSecurityHeaders sets the headers required on every response
// regardless of auth outcome: CSP, no-sniff, and explicit non-CORS. It
// never sets a cookie.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("Content-Security-Policy", contentSecurityPolicy)
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Referrer-Policy", "no-referrer")
		// Deliberately no Access-Control-Allow-Origin (or any other CORS
		// header): the UI is same-origin only.
		next.ServeHTTP(w, r)
	})
}

// withAuth requires the bearer token on every request: as an
// "Authorization: Bearer <token>" header, or (for the SSE route, which
// EventSource cannot attach custom headers to) a "token" query parameter.
func withAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tokenOK(token, r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func tokenOK(token string, r *http.Request) bool {
	if auth := r.Header.Get("Authorization"); auth != "" {
		const prefix = "Bearer "
		if strings.HasPrefix(auth, prefix) && constantTimeEq(strings.TrimPrefix(auth, prefix), token) {
			return true
		}
		return false
	}
	if q := r.URL.Query().Get("token"); q != "" {
		return constantTimeEq(q, token)
	}
	return false
}

// constantTimeEq compares two strings without early-exit timing leakage.
// The token is short-lived and per-launch, but there is no reason to take
// the cheap-and-wrong path here.
func constantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		// Still touch every byte of the shorter/either string so timing
		// does not trivially leak length either; in practice token length
		// is fixed and public, so this is defense in depth, not the load-
		// bearing property.
		var diff byte = 1
		for i := 0; i < len(a); i++ {
			diff |= a[i]
		}
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ---- routes ----

func (h *handler) serveIndexOrAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" || path == "index.html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		// Inject the per-launch token so the browser can load the (also
		// token-gated) assets and call the API: a static index served from a
		// page opened at /?token=… cannot otherwise propagate the token to its
		// sub-resource requests, which would 401. The token is same-origin and
		// short-lived; embedding it in the user's own page is the correct
		// mechanism (no cookies, CSP default-src 'self').
		_, _ = w.Write(bytes.ReplaceAll(indexHTML, []byte("__RANA_TOKEN__"), []byte(h.token)))
		return
	}

	f, err := h.assets.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	if ct := contentTypeFor(path); ct != "" {
		w.Header().Set("Content-Type", ct)
	}

	// embed.FS's file implementation is documented to support io.Seeker in
	// practice, but fs.File does not guarantee it structurally — fall back
	// to a buffered read rather than risk a type-assertion panic on a
	// filesystem implementation that doesn't.
	if rs, ok := f.(io.ReadSeeker); ok {
		http.ServeContent(w, r, path, time.Time{}, rs)
		return
	}
	data, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.ServeContent(w, r, path, time.Time{}, bytesReadSeeker(data))
}

// bytesReadSeeker adapts a byte slice to io.ReadSeeker for the fallback
// path in serveIndexOrAsset.
func bytesReadSeeker(b []byte) io.ReadSeeker {
	return bytes.NewReader(b)
}

func contentTypeFor(name string) string {
	switch {
	case strings.HasSuffix(name, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".map"):
		return "application/json; charset=utf-8"
	default:
		return ""
	}
}

func (h *handler) serveSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sessions, err := h.ds.Sessions(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if sessions == nil {
		sessions = []SessionSummary{}
	}
	writeJSON(w, sessions)
}

func (h *handler) serveEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session := r.URL.Query().Get("session")
	if session == "" {
		http.Error(w, "missing session parameter", http.StatusBadRequest)
		return
	}
	after := parseUintParam(r, "after", 0)
	limit := int(parseUintParam(r, "limit", 0))

	events, err := h.ds.Events(r.Context(), session, after, limit)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, toWireEvents(events))
}

func (h *handler) serveAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session := r.URL.Query().Get("session")
	if session == "" {
		http.Error(w, "missing session parameter", http.StatusBadRequest)
		return
	}
	alerts, err := h.ds.Alerts(r.Context(), session)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, toWireEvents(alerts))
}

func (h *handler) serveStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session := r.URL.Query().Get("session")
	if session == "" {
		http.Error(w, "missing session parameter", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()
	ch, err := h.ds.Stream(ctx, session)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	bw := bufio.NewWriter(w)
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			body, err := json.Marshal(toWireEvent(ev))
			if err != nil {
				continue // never let one bad event kill the tail
			}
			_, _ = bw.WriteString("data: ")
			_, _ = bw.Write(body)
			_, _ = bw.WriteString("\n\n")
			if err := bw.Flush(); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

func parseUintParam(r *http.Request, name string, def uint64) uint64 {
	s := r.URL.Query().Get(name)
	if s == "" {
		return def
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return def
	}
	return v
}
