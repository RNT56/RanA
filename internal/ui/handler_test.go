package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RNT56/RanA/internal/schema"
)

// fakeSource is a minimal in-memory DataSource for testing the handler
// without any real ledger (CONTRACTS §internal/ui: "the handler takes a
// small data-source interface ... so it's testable without the real
// ledger").
type fakeSource struct {
	mu       sync.Mutex
	sessions []SessionSummary
	events   map[string][]schema.Event // by session id
	alerts   map[string][]schema.Event // by session id

	// streamEvents, if set, is sent (in order) to every Stream subscriber
	// as soon as it is invoked, then the channel is left open until the
	// context is canceled.
	streamEvents []schema.Event
	streamErr    error

	sessionsErr error
	eventsErr   error
	alertsErr   error
}

func (f *fakeSource) Sessions(ctx context.Context) ([]SessionSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sessionsErr != nil {
		return nil, f.sessionsErr
	}
	out := make([]SessionSummary, len(f.sessions))
	copy(out, f.sessions)
	return out, nil
}

func (f *fakeSource) Events(ctx context.Context, sessionID string, after uint64, limit int) ([]schema.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.eventsErr != nil {
		return nil, f.eventsErr
	}
	all := f.events[sessionID]
	var out []schema.Event
	for _, ev := range all {
		if ev.Idx > after {
			out = append(out, ev)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeSource) Alerts(ctx context.Context, sessionID string) ([]schema.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.alertsErr != nil {
		return nil, f.alertsErr
	}
	out := make([]schema.Event, len(f.alerts[sessionID]))
	copy(out, f.alerts[sessionID])
	return out, nil
}

func (f *fakeSource) Stream(ctx context.Context, sessionID string) (<-chan schema.Event, error) {
	if f.streamErr != nil {
		return nil, f.streamErr
	}
	ch := make(chan schema.Event, len(f.streamEvents)+1)
	for _, ev := range f.streamEvents {
		ch <- ev
	}
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch, nil
}

const testToken = "test-bearer-token-0123456789"

func newTestHandler(t *testing.T, ds DataSource) http.Handler {
	t.Helper()
	h, err := Handler(testToken, ds)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	return h
}

func doReq(t *testing.T, h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandler_RejectsEmptyToken(t *testing.T) {
	if _, err := Handler("", &fakeSource{}); err == nil {
		t.Fatal("Handler with empty token: want error, got nil")
	}
}

func TestHandler_RejectsNilDataSource(t *testing.T) {
	if _, err := Handler(testToken, nil); err == nil {
		t.Fatal("Handler with nil DataSource: want error, got nil")
	}
}

func TestHandler_RequiresToken_AllRoutes(t *testing.T) {
	ds := &fakeSource{}
	h := newTestHandler(t, ds)

	routes := []string{"/", "/index.html", "/app.js", "/api/sessions", "/api/events?session=s1", "/api/alerts?session=s1"}
	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			rec := doReq(t, h, http.MethodGet, route, "")
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("route %s without token: got status %d, want 401; body=%s", route, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestHandler_RejectsWrongToken(t *testing.T) {
	ds := &fakeSource{}
	h := newTestHandler(t, ds)
	rec := doReq(t, h, http.MethodGet, "/api/sessions", "not-the-right-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: got status %d, want 401", rec.Code)
	}
}

func TestHandler_AcceptsTokenViaQueryParam(t *testing.T) {
	// SSE / EventSource cannot set a custom Authorization header from
	// browser JS, so the stream route must also accept ?token=.
	ds := &fakeSource{}
	h := newTestHandler(t, ds)
	req := httptest.NewRequest(http.MethodGet, "/api/sessions?token="+testToken, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token via query param: got status %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandler_ServesIndexWithCSP(t *testing.T) {
	ds := &fakeSource{}
	h := newTestHandler(t, ds)
	rec := doReq(t, h, http.MethodGet, "/", testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /: got status %d, want 200", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") {
		t.Fatalf("CSP header = %q, want it to contain default-src 'self'", csp)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html prefix", ct)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("GET / returned empty body")
	}
}

func TestHandler_AllResponsesCarryCSPAndSecurityHeaders(t *testing.T) {
	ds := &fakeSource{}
	h := newTestHandler(t, ds)
	rec := doReq(t, h, http.MethodGet, "/api/sessions", testToken)
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") {
		t.Fatalf("api route CSP = %q, want default-src 'self'", csp)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want unset (no CORS)", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestHandler_NoCookiesEverSet(t *testing.T) {
	ds := &fakeSource{}
	h := newTestHandler(t, ds)
	for _, route := range []string{"/", "/api/sessions"} {
		rec := doReq(t, h, http.MethodGet, route, testToken)
		if sc := rec.Header().Values("Set-Cookie"); len(sc) != 0 {
			t.Fatalf("route %s set cookies: %v", route, sc)
		}
	}
}

func TestHandler_ServesBundledAsset(t *testing.T) {
	ds := &fakeSource{}
	h := newTestHandler(t, ds)
	rec := doReq(t, h, http.MethodGet, "/app.js", testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /app.js: got status %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "javascript") {
		t.Fatalf("Content-Type = %q, want javascript", ct)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("GET /app.js returned empty body")
	}
}

// TestHandler_IndexHasNoInlineStyle guards against a CSP self-defeat: the
// handler's CSP is "default-src 'self'" with no style-src directive and no
// 'unsafe-inline', which means style-src inherits default-src and a
// browser will silently DROP any inline <style> block or style="" attribute
// in index.html (CSP fetch directives fall back to default-src when
// unset). If styling needs to be reintroduced, it must ship as a
// same-origin stylesheet (<link rel="stylesheet" href="/...">), never
// inline, or the CSP itself must gain an explicit, justified relaxation.
func TestHandler_IndexHasNoInlineStyle(t *testing.T) {
	ds := &fakeSource{}
	h := newTestHandler(t, ds)
	rec := doReq(t, h, http.MethodGet, "/", testToken)
	body := rec.Body.String()
	if strings.Contains(body, "<style") {
		t.Fatalf("index.html contains an inline <style> block, which the handler's CSP (%s) silently blocks in-browser; move CSS to a same-origin stylesheet", contentSecurityPolicy)
	}
	if strings.Contains(body, "style=\"") {
		t.Fatalf("index.html contains an inline style=\"\" attribute, which the handler's CSP (%s) silently blocks in-browser", contentSecurityPolicy)
	}
}

// TestHandler_ServesStylesheetSameOrigin proves that if index.html links a
// stylesheet, it resolves as a same-origin asset servable under this
// handler's strict CSP without any relaxation.
func TestHandler_ServesStylesheetSameOrigin(t *testing.T) {
	ds := &fakeSource{}
	h := newTestHandler(t, ds)
	indexRec := doReq(t, h, http.MethodGet, "/", testToken)
	body := indexRec.Body.String()
	if !strings.Contains(body, `href="/style.css`) {
		t.Skip("index.html does not link a stylesheet; nothing to verify")
	}
	rec := doReq(t, h, http.MethodGet, "/style.css", testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /style.css: got status %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "css") {
		t.Fatalf("Content-Type = %q, want css", ct)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("GET /style.css returned empty body")
	}
}

// TestHandler_InjectsToken proves the handler substitutes the per-launch token
// into the served index so the browser can load the (also token-gated) assets
// and call the API — a static index cannot know the token, and without this
// the sub-resource requests would 401 in a real browser.
func TestHandler_InjectsToken(t *testing.T) {
	ds := &fakeSource{}
	h := newTestHandler(t, ds)
	body := doReq(t, h, http.MethodGet, "/", testToken).Body.String()
	if strings.Contains(body, "__RANA_TOKEN__") {
		t.Fatalf("index still contains the __RANA_TOKEN__ placeholder — token not injected")
	}
	if !strings.Contains(body, testToken) {
		t.Fatalf("index does not contain the injected token; body=%s", body)
	}
}

func TestHandler_UnknownRoute404(t *testing.T) {
	ds := &fakeSource{}
	h := newTestHandler(t, ds)
	rec := doReq(t, h, http.MethodGet, "/does/not/exist", testToken)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown route: got status %d, want 404", rec.Code)
	}
}

func TestHandler_APISessions(t *testing.T) {
	ds := &fakeSource{
		sessions: []SessionSummary{
			{ID: "sess-1", Profile: "default", StartedNs: 1000, EndedNs: 2000},
			{ID: "sess-2", Profile: "claude-code", StartedNs: 1500, EndedNs: 0},
		},
	}
	h := newTestHandler(t, ds)
	rec := doReq(t, h, http.MethodGet, "/api/sessions", testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/sessions: got status %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got []SessionSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v; body=%s", err, rec.Body.String())
	}
	if len(got) != 2 {
		t.Fatalf("got %d sessions, want 2", len(got))
	}
	if got[0].ID != "sess-1" || got[1].ID != "sess-2" {
		t.Fatalf("unexpected sessions: %+v", got)
	}
}

func TestHandler_APISessions_SourceError(t *testing.T) {
	ds := &fakeSource{sessionsErr: errors.New("boom")}
	h := newTestHandler(t, ds)
	rec := doReq(t, h, http.MethodGet, "/api/sessions", testToken)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got status %d, want 500", rec.Code)
	}
}

func mustEvent(t *testing.T, session string, idx uint64, typ schema.EventType) schema.Event {
	t.Helper()
	ev := schema.Event{
		V: 1, Type: typ, Session: session, Seg: 0, Idx: idx,
		TsMono: idx * 1000, TsWall: idx * 1000,
		Pid: 42, Origin: schema.OriginKernel, State: schema.StateObserved,
		Data: map[string]any{},
	}
	return ev
}

func TestHandler_APIEvents_FiltersBySessionAndAfter(t *testing.T) {
	evs := []schema.Event{
		mustEvent(t, "sess-1", 1, schema.EventTypeProcExec),
		mustEvent(t, "sess-1", 2, schema.EventTypeProcExit),
		mustEvent(t, "sess-1", 3, schema.EventTypeNetConnect),
	}
	ds := &fakeSource{events: map[string][]schema.Event{"sess-1": evs}}
	h := newTestHandler(t, ds)

	rec := doReq(t, h, http.MethodGet, "/api/events?session=sess-1&after=1", testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/events: got status %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got []schema.Event
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2 (idx 2,3)", len(got))
	}
}

func TestHandler_APIEvents_MissingSessionParam(t *testing.T) {
	ds := &fakeSource{}
	h := newTestHandler(t, ds)
	rec := doReq(t, h, http.MethodGet, "/api/events", testToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", rec.Code)
	}
}

func TestHandler_APIEvents_RespectsLimit(t *testing.T) {
	evs := []schema.Event{
		mustEvent(t, "sess-1", 1, schema.EventTypeProcExec),
		mustEvent(t, "sess-1", 2, schema.EventTypeProcExit),
		mustEvent(t, "sess-1", 3, schema.EventTypeNetConnect),
	}
	ds := &fakeSource{events: map[string][]schema.Event{"sess-1": evs}}
	h := newTestHandler(t, ds)
	rec := doReq(t, h, http.MethodGet, "/api/events?session=sess-1&limit=1", testToken)
	var got []schema.Event
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
}

func TestHandler_APIAlerts(t *testing.T) {
	alerts := []schema.Event{mustEvent(t, "sess-1", 1, schema.EventTypeAlertNewDomain)}
	ds := &fakeSource{alerts: map[string][]schema.Event{"sess-1": alerts}}
	h := newTestHandler(t, ds)
	rec := doReq(t, h, http.MethodGet, "/api/alerts?session=sess-1", testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/alerts: got status %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got []schema.Event
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d alerts, want 1", len(got))
	}
}

func TestHandler_APIAlerts_MissingSessionParam(t *testing.T) {
	ds := &fakeSource{}
	h := newTestHandler(t, ds)
	rec := doReq(t, h, http.MethodGet, "/api/alerts", testToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", rec.Code)
	}
}

func TestHandler_StreamSSE_EmitsEvents(t *testing.T) {
	streamed := []schema.Event{
		mustEvent(t, "sess-1", 1, schema.EventTypeProcExec),
		mustEvent(t, "sess-1", 2, schema.EventTypeNetConnect),
	}
	ds := &fakeSource{streamEvents: streamed}
	h := newTestHandler(t, ds)

	srv := httptest.NewServer(h)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/stream?session=sess-1&token="+testToken, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/stream: got status %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	buf := make([]byte, 4096)
	deadline := time.Now().Add(4 * time.Second)
	var collected string
	for time.Now().Before(deadline) {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			collected += string(buf[:n])
		}
		if strings.Count(collected, "\"idx\":2") > 0 {
			break
		}
		if err != nil {
			break
		}
	}
	if !strings.Contains(collected, "data:") {
		t.Fatalf("SSE stream did not contain any data: frame, got: %q", collected)
	}
	if !strings.Contains(collected, "\"idx\":1") || !strings.Contains(collected, "\"idx\":2") {
		t.Fatalf("SSE stream missing expected events, got: %q", collected)
	}
}

func TestHandler_StreamSSE_MissingSessionParam(t *testing.T) {
	ds := &fakeSource{}
	h := newTestHandler(t, ds)
	rec := doReq(t, h, http.MethodGet, "/api/stream", testToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", rec.Code)
	}
}

func TestHandler_OnlyGETAllowed(t *testing.T) {
	ds := &fakeSource{}
	h := newTestHandler(t, ds)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/sessions: got status %d, want 405", rec.Code)
	}
}
