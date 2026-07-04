package report

import (
	"context"
	"strings"
	"testing"

	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// fakeDataSource is a minimal in-memory report.DataSource for unit-testing
// IncidentReport without a real ledger.
type fakeDataSource struct {
	sessions []SessionSummary
	events   map[string][]schema.Event // session -> events, oldest first
	alerts   map[string][]schema.Event
}

func (f *fakeDataSource) Sessions(ctx context.Context) ([]SessionSummary, error) {
	return f.sessions, nil
}

func (f *fakeDataSource) Events(ctx context.Context, sessionID string, after uint64, limit int) ([]schema.Event, error) {
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

func (f *fakeDataSource) Alerts(ctx context.Context, sessionID string) ([]schema.Event, error) {
	return f.alerts[sessionID], nil
}

func buildFakeDS() *fakeDataSource {
	const sess = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	events := []schema.Event{
		schema.NewSessionStart(sess, 0, 1, 1000, 1000, 100,
			redact.Literal("claude-code"), []redact.Redacted{redact.Literal("claude-code"), redact.Literal("run")},
			map[string]any{
				"os": redact.Literal("linux"), "kernel": redact.Literal("6.6.0"),
				"rana_version": redact.Literal("0.1.0"), "boot_id": redact.Literal("abc123"),
			}, nil),
		schema.NewMarker(sess, 0, 2, 1500, 1500, 100, "openclaw.run", map[string]any{
			"runId":   redact.Literal("run-42"),
			"agentId": redact.Literal("default"),
			"channel": redact.Literal("telegram"),
			"status":  redact.Literal("accepted"),
		}),
		schema.NewProcExec(sess, 0, 3, 2000, 2000, 101,
			[]redact.Redacted{redact.Literal("curl"), redact.Literal("https://example.com")},
			redact.Literal("curl"), redact.Literal("/home/u/proj"), redact.Literal("/usr/bin/curl"), 100, 1000),
		schema.NewFsSensitiveRead(sess, 0, 4, 2500, 2500, 101, redact.Literal("/home/u/.ssh/id_ed25519"), redact.Literal("ssh_key")),
		schema.NewNetDNS(sess, 0, 5, 2600, 2600, 101, redact.Literal("evil.example.com"), []redact.Redacted{redact.Literal("1.2.3.4")}, 300),
		schema.NewNetConnect(sess, 0, 6, 2700, 2700, 101, "tcp", make([]byte, 16), 443, "inet"),
		schema.NewAlertSensitiveRead(sess, 0, 7, 2800, 2800, 101, redact.Literal("/home/u/.ssh/id_ed25519"), redact.Literal("ssh_key")),
		schema.NewFsSettle(sess, 0, 8, 2900, 2900, 101, redact.Literal("/home/u/proj/out.txt"), nil, make([]byte, 32), 12, 2900),
		schema.NewGap(sess, 0, 9, 3000, 3000, 0, "ringbuf_full", map[string]uint64{"proc.exec": 3}, 2000, 3000),
		schema.NewMarker(sess, 0, 10, 3100, 3100, 100, "openclaw.run", map[string]any{
			"runId":  redact.Literal("run-42"),
			"status": redact.Literal("ok"),
		}),
		schema.NewSessionEnd(sess, 0, 11, 3200, 3200, 100),
	}

	return &fakeDataSource{
		sessions: []SessionSummary{{ID: sess, Profile: "openclaw", StartedNs: 1000, EndedNs: 3200}},
		events:   map[string][]schema.Event{sess: events},
		alerts: map[string][]schema.Event{sess: {
			schema.NewAlertSensitiveRead(sess, 0, 7, 2800, 2800, 101, redact.Literal("/home/u/.ssh/id_ed25519"), redact.Literal("ssh_key")),
		}},
	}
}

func TestIncidentReport_HeaderAndTimeline(t *testing.T) {
	ds := buildFakeDS()
	const sess = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

	out, err := IncidentReport(context.Background(), ds, sess)
	if err != nil {
		t.Fatalf("IncidentReport: %v", err)
	}

	for _, want := range []string{
		sess,
		"openclaw",  // profile
		"linux",     // host fingerprint field
		"6.6.0",     // kernel
		"0.1.0",     // rana version
		"proc.exec", // load-bearing event type
		"/usr/bin/curl",
		"fs.sensitive_read",
		"/home/u/.ssh/id_ed25519",
		"net.connect",
		"net.dns",
		"evil.example.com",
		"fs.settle",
		"alert.sensitive_read",
		"gap",
		"ringbuf_full",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing expected substring %q\n---\n%s", want, out)
		}
	}
}

func TestIncidentReport_CausalityClustersByRunID(t *testing.T) {
	ds := buildFakeDS()
	const sess = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

	out, err := IncidentReport(context.Background(), ds, sess)
	if err != nil {
		t.Fatalf("IncidentReport: %v", err)
	}
	if !strings.Contains(out, "run-42") {
		t.Errorf("report should mention the marker runId run-42:\n%s", out)
	}
	// The causality section should exist as its own heading.
	if !strings.Contains(strings.ToLower(out), "causality") {
		t.Errorf("report should contain a causality clusters section:\n%s", out)
	}
}

func TestIncidentReport_FooterEmbedsLimitsPointer(t *testing.T) {
	ds := buildFakeDS()
	const sess = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

	out, err := IncidentReport(context.Background(), ds, sess)
	if err != nil {
		t.Fatalf("IncidentReport: %v", err)
	}
	if !strings.Contains(out, "LIMITS.md") {
		t.Errorf("report footer must point to LIMITS.md honesty doc:\n%s", out)
	}
}

func TestIncidentReport_NeverRendersMarkerContentFields(t *testing.T) {
	// Guard against P7: even if some hypothetical marker carried a
	// forbidden content-shaped field, IncidentReport must never render
	// anything beyond the known lifecycle/identifier fields it explicitly
	// selects (runId, agentId, channel, status) — it must not do a
	// generic "dump all Data fields" walk over marker events.
	const sess = "s2"
	ds := &fakeDataSource{
		sessions: []SessionSummary{{ID: sess, Profile: "generic"}},
		events: map[string][]schema.Event{sess: {
			schema.NewSessionStart(sess, 0, 1, 0, 0, 1, redact.Literal("generic"), nil, map[string]any{}, nil),
			schema.NewMarker(sess, 0, 2, 100, 100, 1, "run.start", map[string]any{
				"runId": redact.Literal("r1"),
				// A hypothetical hostile/misconfigured carried field that
				// should never appear verbatim in a "content" sense; the
				// report must only ever surface known identifier fields.
				"text": redact.Literal("this looks like message content but is opaque redact.Redacted"),
			}),
		}},
		alerts: map[string][]schema.Event{},
	}

	out, err := IncidentReport(context.Background(), ds, sess)
	if err != nil {
		t.Fatalf("IncidentReport: %v", err)
	}
	if strings.Contains(out, "this looks like message content") {
		t.Errorf("report must never render raw marker Data field values outside the fixed identifier set:\n%s", out)
	}
}

func TestIncidentReport_UnknownSession(t *testing.T) {
	ds := buildFakeDS()
	if _, err := IncidentReport(context.Background(), ds, "does-not-exist"); err == nil {
		t.Fatal("expected error for unknown session")
	}
}

func TestIncidentReport_EmptySessionStillProducesHeaderAndFooter(t *testing.T) {
	const sess = "empty-session"
	ds := &fakeDataSource{
		sessions: []SessionSummary{{ID: sess, Profile: "generic"}},
		events:   map[string][]schema.Event{},
		alerts:   map[string][]schema.Event{},
	}
	out, err := IncidentReport(context.Background(), ds, sess)
	if err != nil {
		t.Fatalf("IncidentReport: %v", err)
	}
	if !strings.Contains(out, sess) {
		t.Errorf("report should still mention the session id: %s", out)
	}
	if !strings.Contains(out, "LIMITS.md") {
		t.Errorf("report footer must point to LIMITS.md even for an empty session: %s", out)
	}
}
