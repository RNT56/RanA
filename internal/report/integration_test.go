package report_test

import (
	"context"
	"strings"
	"testing"

	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/report"
	"github.com/RNT56/RanA/internal/schema"
	"github.com/RNT56/RanA/internal/service"
	"github.com/RNT56/RanA/internal/ui"
)

// dsAdapter narrows an *service.LedgerDataSource (which satisfies the
// broader internal/ui.DataSource interface) down to the small
// internal/report.DataSource shape, converting ui.SessionSummary values to
// report.SessionSummary values. This mirrors cmd/rana/report_adapter.go's
// reportDataSource — the real CLI wiring's copy of the same adapter, which
// this package cannot import (it lives in package main) — so it is
// duplicated here to prove internal/report's DataSource interface is
// genuinely satisfiable by the real ledger-backed implementation, not just
// by the in-package fake.
type dsAdapter struct {
	inner *service.LedgerDataSource
}

func (a dsAdapter) Sessions(ctx context.Context) ([]report.SessionSummary, error) {
	ss, err := a.inner.Sessions(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]report.SessionSummary, len(ss))
	for i, s := range ss {
		out[i] = report.SessionSummary{ID: s.ID, Profile: s.Profile, StartedNs: s.StartedNs, EndedNs: s.EndedNs}
	}
	return out, nil
}

func (a dsAdapter) Events(ctx context.Context, sessionID string, after uint64, limit int) ([]schema.Event, error) {
	return a.inner.Events(ctx, sessionID, after, limit)
}

func (a dsAdapter) Alerts(ctx context.Context, sessionID string) ([]schema.Event, error) {
	return a.inner.Alerts(ctx, sessionID)
}

var _ report.DataSource = dsAdapter{}
var _ ui.DataSource = (*service.LedgerDataSource)(nil)

// TestIncidentReport_AgainstRealLedger builds a real on-disk ledger via
// internal/ledger.Writer (the same durable, chain-hashed path production
// uses), reads it back through internal/service.LedgerDataSource, and
// confirms IncidentReport produces a sane narrative end to end — proving
// the report package's DataSource contract matches the real
// implementation's shape, not just the in-package fake's.
func TestIncidentReport_AgainstRealLedger(t *testing.T) {
	dir := ledger.Dir(t.TempDir())
	if err := dir.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	w, err := ledger.NewWriter(dir, ledger.WriterOptions{})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	const session = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	events := []schema.Event{
		schema.NewSessionStart(session, 0, 1, 0, 1000, 100,
			redact.Literal("claude-code"), []redact.Redacted{redact.Literal("claude-code")},
			map[string]any{
				"os": redact.Literal("linux"), "kernel": redact.Literal("6.6.0"),
				"rana_version": redact.Literal("0.1.0"), "boot_id": redact.Literal("boot-1"),
			}, nil),
		schema.NewProcExec(session, 0, 2, 0, 2000, 101,
			[]redact.Redacted{redact.Literal("git"), redact.Literal("status")},
			redact.Literal("git"), redact.Literal("/home/u/proj"), redact.Literal("/usr/bin/git"), 100, 1000),
		schema.NewFsSensitiveRead(session, 0, 3, 0, 3000, 101, redact.Literal("/home/u/.ssh/id_ed25519"), redact.Literal("ssh_key")),
		schema.NewAlertSensitiveRead(session, 0, 4, 0, 3100, 101, redact.Literal("/home/u/.ssh/id_ed25519"), redact.Literal("ssh_key")),
		schema.NewNetDNS(session, 0, 5, 0, 3150, 101, redact.Literal("evil.example.com"), []redact.Redacted{redact.Literal("1.2.3.4")}, 300),
		schema.NewNetConnect(session, 0, 6, 0, 3160, 101, "tcp", make([]byte, 16), 443, "inet"),
		schema.NewMarker(session, 0, 7, 0, 3170, 100, "openclaw.run", map[string]any{
			"runId":   redact.Literal("run-abc"),
			"agentId": redact.Literal("default"),
			"channel": redact.Literal("telegram"),
			"status":  redact.Literal("accepted"),
		}),
		schema.NewGap(session, 0, 8, 0, 3200, 0, "governor", map[string]uint64{"net.connect": 2}, 3000, 3200),
		schema.NewSessionEnd(session, 0, 9, 0, 3300, 100),
	}
	for _, ev := range events {
		if err := w.Append(ev); err != nil {
			t.Fatalf("Append %s: %v", ev.Type, err)
		}
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("FlushForTest: %v", err)
	}
	if err := w.SealSession(session); err != nil {
		t.Fatalf("SealSession: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close writer: %v", err)
	}

	ds, err := service.NewLedgerDataSource(dir)
	if err != nil {
		t.Fatalf("NewLedgerDataSource: %v", err)
	}
	defer ds.Close()

	out, err := report.IncidentReport(context.Background(), dsAdapter{inner: ds}, session)
	if err != nil {
		t.Fatalf("IncidentReport: %v", err)
	}

	for _, want := range []string{
		session,
		"claude-code",
		"linux",
		"6.6.0",
		"proc.exec",
		"/usr/bin/git",
		"status", // argv element, proves array-of-string decode is handled, not just scalar fields
		"fs.sensitive_read",
		"/home/u/.ssh/id_ed25519",
		"alert.sensitive_read",
		"net.dns",
		"evil.example.com",
		"net.connect",
		"run-abc",
		"gap",
		"governor",
		"LIMITS.md",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("real-ledger report missing expected substring %q\n---\n%s", want, out)
		}
	}
}
