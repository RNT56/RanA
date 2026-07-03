package service

import (
	"context"
	"testing"
	"time"

	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/schema"
)

func newTestLedgerDir(t *testing.T) ledger.Datadir {
	t.Helper()
	dir := ledger.Dir(t.TempDir())
	if err := dir.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	return dir
}

func writeTestEvents(t *testing.T, dir ledger.Datadir, session string, n int) {
	t.Helper()
	w, err := ledger.NewWriter(dir, ledger.WriterOptions{})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	for i := 0; i < n; i++ {
		ev := schema.NewSessionEnd(session, 0, uint64(i+1), uint64(i*1000), uint64(i*2000), 42)
		if i == 0 {
			ev = schema.NewSessionStart(session, 0, 1, 0, 0, 42, "generic", nil, map[string]any{}, nil)
		}
		if err := w.Append(ev); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("FlushForTest: %v", err)
	}
	if err := w.SealSession(session); err != nil {
		t.Fatalf("SealSession: %v", err)
	}
}

func TestLedgerDataSource_SessionsListsWrittenSessions(t *testing.T) {
	dir := newTestLedgerDir(t)
	writeTestEvents(t, dir, "01ARZ3NDEKTSV4RRFFQ69G5FAV", 3)

	ds, err := NewLedgerDataSource(dir)
	if err != nil {
		t.Fatalf("NewLedgerDataSource: %v", err)
	}
	defer ds.Close()

	sessions, err := ds.Sessions(context.Background())
	if err != nil {
		t.Fatalf("Sessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("got %d sessions, want 1: %+v", len(sessions), sessions)
	}
	if sessions[0].ID != "01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Fatalf("session id = %q", sessions[0].ID)
	}
}

func TestLedgerDataSource_EventsReturnsInOrderAfterIdx(t *testing.T) {
	dir := newTestLedgerDir(t)
	writeTestEvents(t, dir, "01ARZ3NDEKTSV4RRFFQ69G5FAV", 5)

	ds, err := NewLedgerDataSource(dir)
	if err != nil {
		t.Fatalf("NewLedgerDataSource: %v", err)
	}
	defer ds.Close()

	all, err := ds.Events(context.Background(), "01ARZ3NDEKTSV4RRFFQ69G5FAV", 0, 0)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("got %d events, want 5", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].Idx <= all[i-1].Idx {
			t.Fatalf("events not in ascending idx order at %d: %d <= %d", i, all[i].Idx, all[i-1].Idx)
		}
	}

	after, err := ds.Events(context.Background(), "01ARZ3NDEKTSV4RRFFQ69G5FAV", 2, 0)
	if err != nil {
		t.Fatalf("Events after=2: %v", err)
	}
	for _, ev := range after {
		if ev.Idx <= 2 {
			t.Fatalf("event idx %d not > after=2", ev.Idx)
		}
	}

	limited, err := ds.Events(context.Background(), "01ARZ3NDEKTSV4RRFFQ69G5FAV", 0, 2)
	if err != nil {
		t.Fatalf("Events limit=2: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("got %d events, want 2 (limit)", len(limited))
	}
}

func TestLedgerDataSource_EventsUnknownSessionEmpty(t *testing.T) {
	dir := newTestLedgerDir(t)
	writeTestEvents(t, dir, "01ARZ3NDEKTSV4RRFFQ69G5FAV", 2)

	ds, err := NewLedgerDataSource(dir)
	if err != nil {
		t.Fatalf("NewLedgerDataSource: %v", err)
	}
	defer ds.Close()

	events, err := ds.Events(context.Background(), "nonexistent-session", 0, 0)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("got %d events for unknown session, want 0", len(events))
	}
}

func TestLedgerDataSource_AlertsFiltersToAlertTypes(t *testing.T) {
	dir := newTestLedgerDir(t)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FAV"

	w, err := ledger.NewWriter(dir, ledger.WriterOptions{})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	if err := w.Append(schema.NewSessionStart(session, 0, 1, 0, 0, 42, "generic", nil, map[string]any{}, nil)); err != nil {
		t.Fatalf("Append session.start: %v", err)
	}
	if err := w.Append(schema.NewAlertNewDomain(session, 0, 2, 1000, 2000, 42, "example.com")); err != nil {
		t.Fatalf("Append alert.new_domain: %v", err)
	}
	if err := w.FlushForTest(); err != nil {
		t.Fatalf("FlushForTest: %v", err)
	}
	if err := w.SealSession(session); err != nil {
		t.Fatalf("SealSession: %v", err)
	}

	ds, err := NewLedgerDataSource(dir)
	if err != nil {
		t.Fatalf("NewLedgerDataSource: %v", err)
	}
	defer ds.Close()

	alerts, err := ds.Alerts(context.Background(), session)
	if err != nil {
		t.Fatalf("Alerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1: %+v", len(alerts), alerts)
	}
	if alerts[0].Type != schema.EventTypeAlertNewDomain {
		t.Fatalf("alert type = %q", alerts[0].Type)
	}
}

func TestLedgerDataSource_StreamDeliversNewlyAppendedEvents(t *testing.T) {
	dir := newTestLedgerDir(t)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FAV"

	w, err := ledger.NewWriter(dir, ledger.WriterOptions{})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	ds, err := NewLedgerDataSource(dir)
	if err != nil {
		t.Fatalf("NewLedgerDataSource: %v", err)
	}
	defer ds.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := ds.Stream(ctx, session)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	// Feed the DataSource's live-tail path directly (svc wires this from
	// its own post-Append hook, not by polling the DB — see PublishLive).
	ev := schema.NewSessionStart(session, 0, 1, 0, 0, 42, "generic", nil, map[string]any{}, nil)
	if err := w.Append(ev); err != nil {
		t.Fatalf("Append: %v", err)
	}
	ds.PublishLive(ev)

	select {
	case got := <-ch:
		if got.Session != session {
			t.Fatalf("streamed event session = %q, want %q", got.Session, session)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for streamed event")
	}

	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("channel should be closing/closed after context cancellation, got a value")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stream channel to close after cancel")
	}
}

func TestLedgerDataSource_StreamIgnoresOtherSessions(t *testing.T) {
	dir := newTestLedgerDir(t)
	w, err := ledger.NewWriter(dir, ledger.WriterOptions{})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	ds, err := NewLedgerDataSource(dir)
	if err != nil {
		t.Fatalf("NewLedgerDataSource: %v", err)
	}
	defer ds.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := ds.Stream(ctx, "session-a")
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	other := schema.NewSessionStart("session-b", 0, 1, 0, 0, 42, "generic", nil, map[string]any{}, nil)
	ds.PublishLive(other)

	select {
	case ev := <-ch:
		t.Fatalf("received event for unsubscribed session: %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}
}
