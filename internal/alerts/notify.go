// Package alerts implements RanA's rules engine (plan §4.3 alert.*, plan
// Phase 5, docs/ARCHITECTURE.md §4, CONTRACTS §internal/alerts): a set of
// deterministic rules that consume schema.Event values post-persist (i.e.
// after the ledger has already committed them — alerts are enrichment on
// top of an already-durable, already-chained record, never a gate on it)
// and, for the rules that detect something new, synthesize an alert.*
// schema event of their own plus a best-effort desktop notification.
//
// Alerts are themselves ordinary svc-origin schema events: they get
// persisted, chained, and verified exactly like everything else. Nothing
// in this package is load-bearing truth (P1) — it is entirely derived from
// facts the kernel or svc already recorded.
package alerts

// Notifier delivers a best-effort desktop notification. Implementations
// MUST NOT block meaningfully or ever cause the alerts pipeline to fail:
// Engine always treats a Notifier error as non-fatal (logged/ignored by the
// caller, never propagated as an Observe error) — see engine.go.
//
// title and body MUST already be redact-safe: callers only ever pass
// values sourced from event Data fields that have already passed the
// redaction pipeline (they are redact.Redacted at the point they were
// captured), so notification text can never surface a raw secret.
type Notifier interface {
	Notify(title, body string) error
}

// NopNotifier is a Notifier that does nothing and never errors. It is a
// safe, portable default for platforms/builds that have no desktop
// notification mechanism wired up (see notify_other.go).
type NopNotifier struct{}

// Notify implements Notifier by doing nothing.
func (NopNotifier) Notify(string, string) error { return nil }

// NotifyCall records a single Notify invocation, used by FakeNotifier.
type NotifyCall struct {
	Title string
	Body  string
}

// FakeNotifier is a test double that records every Notify call it
// receives, in order, and optionally returns a canned error — used to
// verify the Engine's best-effort failure isolation (a Notifier error must
// never block or fail the alerts pipeline).
type FakeNotifier struct {
	Calls []NotifyCall
	Err   error
}

// Notify records the call and returns Err (nil unless configured).
func (f *FakeNotifier) Notify(title, body string) error {
	f.Calls = append(f.Calls, NotifyCall{Title: title, Body: body})
	return f.Err
}
