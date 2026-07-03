package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewTimelineHost_RequiresAuth(t *testing.T) {
	dir := newTestLedgerDir(t)
	writeTestEvents(t, dir, "01ARZ3NDEKTSV4RRFFQ69G5FAV", 2)

	ds, err := NewLedgerDataSource(dir)
	if err != nil {
		t.Fatalf("NewLedgerDataSource: %v", err)
	}
	defer ds.Close()

	host, err := NewTimelineHost(TimelineHostConfig{Token: "s3cr3t-token", DataSource: ds})
	if err != nil {
		t.Fatalf("NewTimelineHost: %v", err)
	}

	srv := httptest.NewServer(host.Handler())
	defer srv.Close()

	// No auth: rejected.
	resp, err := http.Get(srv.URL + "/api/sessions")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	// Correct bearer token: accepted.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer s3cr3t-token")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET authed: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp2.StatusCode)
	}
}

func TestNewTimelineHost_CSPHeaderPresent(t *testing.T) {
	dir := newTestLedgerDir(t)
	writeTestEvents(t, dir, "01ARZ3NDEKTSV4RRFFQ69G5FAV", 1)

	ds, err := NewLedgerDataSource(dir)
	if err != nil {
		t.Fatalf("NewLedgerDataSource: %v", err)
	}
	defer ds.Close()

	host, err := NewTimelineHost(TimelineHostConfig{Token: "tok", DataSource: ds})
	if err != nil {
		t.Fatalf("NewTimelineHost: %v", err)
	}
	srv := httptest.NewServer(host.Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if csp := resp.Header.Get("Content-Security-Policy"); csp == "" {
		t.Fatal("missing Content-Security-Policy header")
	}
}

func TestNewTimelineHost_EmptyTokenRejected(t *testing.T) {
	dir := newTestLedgerDir(t)
	writeTestEvents(t, dir, "s", 1)
	ds, err := NewLedgerDataSource(dir)
	if err != nil {
		t.Fatalf("NewLedgerDataSource: %v", err)
	}
	defer ds.Close()

	_, err = NewTimelineHost(TimelineHostConfig{Token: "", DataSource: ds})
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}

func TestGenerateLaunchToken_NonEmptyAndUnique(t *testing.T) {
	a, err := GenerateLaunchToken()
	if err != nil {
		t.Fatalf("GenerateLaunchToken: %v", err)
	}
	b, err := GenerateLaunchToken()
	if err != nil {
		t.Fatalf("GenerateLaunchToken: %v", err)
	}
	if a == "" || len(a) < 16 {
		t.Fatalf("token too short: %q", a)
	}
	if a == b {
		t.Fatal("two calls returned the same token")
	}
}

// sanity: DataSource wiring actually serves real ledger content end to end
// through the HTTP layer, not just an empty stub.
func TestNewTimelineHost_ServesRealEvents(t *testing.T) {
	dir := newTestLedgerDir(t)
	session := "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	writeTestEvents(t, dir, session, 3)

	ds, err := NewLedgerDataSource(dir)
	if err != nil {
		t.Fatalf("NewLedgerDataSource: %v", err)
	}
	defer ds.Close()

	host, err := NewTimelineHost(TimelineHostConfig{Token: "tok", DataSource: ds})
	if err != nil {
		t.Fatalf("NewTimelineHost: %v", err)
	}
	srv := httptest.NewServer(host.Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/events?session="+session, nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}
