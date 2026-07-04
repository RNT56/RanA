package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/report"
	"github.com/RNT56/RanA/internal/schema"
	"github.com/RNT56/RanA/internal/service"
)

// version is stamped at build time; "dev" otherwise.
var version = "dev"

func versionString() string { return version }

func defaultDataDir() string {
	if d := os.Getenv("RANA_DATA_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "rana")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "share", "rana")
	}
	return "rana-data"
}

func main() {
	dataDir := flag.String("data", defaultDataDir(), "RanA data directory (the ledger to expose, read-only)")
	flag.Parse()

	be := newLedgerBackend(*dataDir)
	srv := newServer(be)
	if err := run(srv, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "rana-mcp: %v\n", err)
		os.Exit(1)
	}
}

// run is the MCP stdio transport: newline-delimited JSON-RPC 2.0. Each line is
// one request; each non-notification gets one response line.
func run(s *server, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // tolerate large tool results
	enc := json.NewEncoder(out)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_ = enc.Encode(rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"),
				Error: &rpcError{Code: codeParse, Message: "parse error"}})
			continue
		}
		if resp := s.handle(context.Background(), req); resp != nil {
			if err := enc.Encode(resp); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

// --- ledgerBackend: the real read-only ledger implementation of Backend. ---

type ledgerBackend struct {
	dir ledger.Datadir
	ds  *service.LedgerDataSource
	err error
}

func newLedgerBackend(dataDir string) *ledgerBackend {
	dir := ledger.Dir(dataDir)
	ds, err := service.NewLedgerDataSource(dir)
	return &ledgerBackend{dir: dir, ds: ds, err: err}
}

func (b *ledgerBackend) Sessions(ctx context.Context) ([]SessionInfo, error) {
	if b.err != nil {
		return nil, b.err
	}
	ss, err := b.ds.Sessions(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SessionInfo, len(ss))
	for i, s := range ss {
		out[i] = SessionInfo{ID: s.ID, Profile: s.Profile, StartedNs: s.StartedNs, EndedNs: s.EndedNs}
	}
	return out, nil
}

func (b *ledgerBackend) Events(ctx context.Context, session string, after uint64, limit int) ([]map[string]any, error) {
	if b.err != nil {
		return nil, b.err
	}
	evs, err := b.ds.Events(ctx, session, after, limit)
	if err != nil {
		return nil, err
	}
	return eventsToMaps(evs)
}

func (b *ledgerBackend) Alerts(ctx context.Context, session string) ([]map[string]any, error) {
	if b.err != nil {
		return nil, b.err
	}
	evs, err := b.ds.Alerts(ctx, session)
	if err != nil {
		return nil, err
	}
	return eventsToMaps(evs)
}

func (b *ledgerBackend) Verify(session string) (VerifyResult, error) {
	if b.err != nil {
		return VerifyResult{}, b.err
	}
	res, err := ledger.Verify(b.dir, ledger.VerifyOptions{Session: session})
	if err != nil {
		return VerifyResult{}, err
	}
	verdict := map[int]string{
		ledger.CodeOK:         "intact",
		ledger.CodeBroken:     "broken — tampering detected",
		ledger.CodeIncomplete: "incomplete — unverifiable (not proof of tampering)",
	}[res.Code]
	findings := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		findings = append(findings, fmt.Sprintf("%v", f))
	}
	return VerifyResult{Code: res.Code, Verdict: verdict, Findings: findings}, nil
}

func (b *ledgerBackend) IncidentReport(ctx context.Context, session string) (string, error) {
	if b.err != nil {
		return "", b.err
	}
	return report.IncidentReport(ctx, reportDataSource{inner: b.ds}, session)
}

// eventsToMaps renders redacted schema events as JSON-shaped maps. The events
// are already redacted (P3) — any string that was a secret is a typed marker,
// so the resulting maps are safe to hand to a model.
func eventsToMaps(evs []schema.Event) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(evs))
	for _, ev := range evs {
		b, err := json.Marshal(ev)
		if err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// reportDataSource adapts *service.LedgerDataSource to internal/report's
// DataSource (converting ui.SessionSummary -> report.SessionSummary), mirroring
// cmd/rana's adapter so `rana-mcp` and the CLI render the same incident report.
type reportDataSource struct{ inner *service.LedgerDataSource }

func (a reportDataSource) Sessions(ctx context.Context) ([]report.SessionSummary, error) {
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
func (a reportDataSource) Events(ctx context.Context, s string, after uint64, limit int) ([]schema.Event, error) {
	return a.inner.Events(ctx, s, after, limit)
}
func (a reportDataSource) Alerts(ctx context.Context, s string) ([]schema.Event, error) {
	return a.inner.Alerts(ctx, s)
}
