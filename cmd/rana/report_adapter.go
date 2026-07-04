package main

import (
	"context"

	"github.com/RNT56/RanA/internal/report"
	"github.com/RNT56/RanA/internal/schema"
	"github.com/RNT56/RanA/internal/service"
)

// reportDataSource narrows a *service.LedgerDataSource down to
// internal/report.DataSource's shape, converting ui.SessionSummary values
// (LedgerDataSource's native return type) to report.SessionSummary values.
// This is exactly the adapter internal/report/integration_test.go's
// dsAdapter anticipates a real CLI wiring writing (see that file's doc
// comment) — it exists here, in production code, so `rana export --format
// incident` and `rana show --diff` share one implementation rather than
// each hand-rolling their own.
type reportDataSource struct {
	inner *service.LedgerDataSource
}

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

func (a reportDataSource) Events(ctx context.Context, sessionID string, after uint64, limit int) ([]schema.Event, error) {
	return a.inner.Events(ctx, sessionID, after, limit)
}

func (a reportDataSource) Alerts(ctx context.Context, sessionID string) ([]schema.Event, error) {
	return a.inner.Alerts(ctx, sessionID)
}

var _ report.DataSource = reportDataSource{}

// identityPathTranslator implements report.PathTranslator as the identity
// function: on a plain Linux/macOS host (the only place cmd/rana's `show
// --diff` runs — never inside RanA's macOS guest, which has no CLI of its
// own), the path recorded on an fs.settle event is already a local
// filesystem path, so no guest->host translation (internal/vm.PathXlate)
// applies.
type identityPathTranslator struct{}

func (identityPathTranslator) Translate(path string) (string, error) { return path, nil }

var _ report.PathTranslator = identityPathTranslator{}
