package report

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// SessionSummary is the compact per-session shape IncidentReport reads from
// a DataSource. It mirrors internal/ui.SessionSummary's fields exactly, but
// is defined independently here so internal/report has no dependency on
// internal/ui (report is a library consumed by future CLI wiring, not a
// UI-server concern).
type SessionSummary struct {
	ID        string
	Profile   string
	StartedNs uint64
	EndedNs   uint64
}

// DataSource is the read-only subset of internal/service.LedgerDataSource
// (and internal/ui.DataSource) that report needs: session listing plus a
// session's recorded events and alerts. Report functions depend on this
// narrow interface rather than a concrete ledger type so they can be unit
// tested against a synthetic in-memory fake, per CLAUDE.md §3.2 (pure-Go
// layers testable against synthetic event streams, decoupled from
// internal/bpf/internal/ledger internals).
type DataSource interface {
	Sessions(ctx context.Context) ([]SessionSummary, error)
	Events(ctx context.Context, sessionID string, after uint64, limit int) ([]schema.Event, error)
	Alerts(ctx context.Context, sessionID string) ([]schema.Event, error)
}

// limitsPointer is the fixed footer text pointing at RanA's honesty
// document (CLAUDE.md P10, P4: "claim exactly what the chain delivers").
// IncidentReport never restates or summarizes LIMITS.md's content — it
// only points at it, so the two documents cannot drift into contradicting
// each other.
const limitsPointer = "This report is built only from events RanA actually recorded. " +
	"For what RanA does and does not guarantee — including known attribution escapes " +
	"and residual redaction risk — see LIMITS.md."

// loadBearingTypes is the set of event types IncidentReport's timeline
// includes: the kernel- and svc-sourced facts that reconstruct what an
// agent session actually did (P1). marker.* events are handled separately
// (causality clustering), never treated as load-bearing timeline entries
// in their own right, and alert.* is included as it is itself a recorded,
// load-bearing consequence (a rule fired).
var loadBearingTypes = map[schema.EventType]bool{
	schema.EventTypeProcExec:        true,
	schema.EventTypeFsSensitiveRead: true,
	schema.EventTypeNetConnect:      true,
	schema.EventTypeNetDNS:          true,
	schema.EventTypeFsSettle:        true,
	schema.EventTypeGap:             true,
}

// ErrSessionNotFound is returned by IncidentReport when session is not
// among ds.Sessions().
var ErrSessionNotFound = fmt.Errorf("report: session not found")

// IncidentReport builds a Markdown narrative for session, built entirely
// from already-recorded, already-redacted events read from ds. It never
// renders anything resembling model I/O (P7): the only marker fields it
// ever surfaces are the fixed lifecycle/identifier set (runId, agentId,
// channel, status) — it does not walk a marker event's full Data map.
//
// The report has four parts:
//  1. a header (session id, profile, host fingerprint from session.start);
//  2. a timeline of load-bearing events (proc.exec, fs.sensitive_read,
//     net.connect/net.dns, fs.settle, alert.*, gap);
//  3. causality clusters grouped by marker runId, where present;
//  4. a footer pointing at LIMITS.md (never restating its content).
func IncidentReport(ctx context.Context, ds DataSource, session string) (string, error) {
	sessions, err := ds.Sessions(ctx)
	if err != nil {
		return "", fmt.Errorf("report: listing sessions: %w", err)
	}
	summary, ok := findSession(sessions, session)
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrSessionNotFound, session)
	}

	events, err := ds.Events(ctx, session, 0, 0)
	if err != nil {
		return "", fmt.Errorf("report: reading events for %q: %w", session, err)
	}
	alertEvents, err := ds.Alerts(ctx, session)
	if err != nil {
		return "", fmt.Errorf("report: reading alerts for %q: %w", session, err)
	}

	var b strings.Builder
	writeHeader(&b, summary, events)
	writeTimeline(&b, events, alertEvents)
	writeCausalityClusters(&b, events)
	writeFooter(&b)

	return b.String(), nil
}

func findSession(sessions []SessionSummary, id string) (SessionSummary, bool) {
	for _, s := range sessions {
		if s.ID == id {
			return s, true
		}
	}
	return SessionSummary{}, false
}

// writeHeader emits the session id, profile, and host fingerprint (pulled
// from the session's session.start event, if present — a session with no
// session.start yet, e.g. mid-crash-recovery, still gets a header from
// SessionSummary alone).
func writeHeader(b *strings.Builder, s SessionSummary, events []schema.Event) {
	fmt.Fprintf(b, "# Incident Report: session %s\n\n", s.ID)
	fmt.Fprintf(b, "- **Profile:** %s\n", nonEmpty(s.Profile))

	if start := findFirst(events, schema.EventTypeSessionStart); start != nil {
		if profileName, ok := redactedField(start.Data, "profile"); ok && profileName != "" {
			// session.start's own profile field is authoritative over the
			// SessionSummary's (both svc-sourced; prefer the one carried on
			// the actual recorded event).
			b.WriteString("- **Profile (session.start):** " + profileName + "\n")
		}
		if host, ok := asStringAnyMap(start.Data["host"]); ok {
			b.WriteString("- **Host fingerprint:**\n")
			for _, k := range sortedKeys(host) {
				fmt.Fprintf(b, "  - %s: %s\n", k, formatValue(host[k]))
			}
		}
	}
	fmt.Fprintf(b, "- **Started (ns):** %d\n", s.StartedNs)
	fmt.Fprintf(b, "- **Ended (ns):** %d\n", s.EndedNs)
	b.WriteString("\n")
}

// writeTimeline emits one line per load-bearing event, oldest first, plus
// every alert.* event (fetched separately in case an implementation's
// Events() call is capped/paginated in a way Alerts() is not).
func writeTimeline(b *strings.Builder, events, alertEvents []schema.Event) {
	b.WriteString("## Timeline\n\n")

	var rows []schema.Event
	for _, ev := range events {
		if loadBearingTypes[ev.Type] || strings.HasPrefix(string(ev.Type), "alert.") {
			rows = append(rows, ev)
		}
	}
	// Merge in any alert events not already present in events (by Idx),
	// preserving chronological (Idx) order.
	seen := make(map[uint64]bool, len(rows))
	for _, ev := range rows {
		seen[ev.Idx] = true
	}
	for _, ev := range alertEvents {
		if !seen[ev.Idx] {
			rows = append(rows, ev)
			seen[ev.Idx] = true
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Idx < rows[j].Idx })

	if len(rows) == 0 {
		b.WriteString("_No load-bearing events recorded for this session._\n\n")
		return
	}

	for _, ev := range rows {
		fmt.Fprintf(b, "- `[idx %d, ts_wall %d]` **%s** (pid %d): %s\n",
			ev.Idx, ev.TsWall, ev.Type, ev.Pid, describeEvent(ev))
	}
	b.WriteString("\n")
}

// describeEvent renders a one-line, type-specific summary of ev's
// already-redacted Data fields. It only ever reads frozen, documented
// fields for each type (plan §4.3) — never a generic field dump.
func describeEvent(ev schema.Event) string {
	switch ev.Type {
	case schema.EventTypeProcExec:
		exe, _ := redactedField(ev.Data, "exe_path")
		argv := redactedSliceField(ev.Data, "argv")
		return fmt.Sprintf("exec %s %s", exe, strings.Join(argv, " "))
	case schema.EventTypeFsSensitiveRead:
		path, _ := redactedField(ev.Data, "path")
		rule, _ := redactedField(ev.Data, "rule")
		return fmt.Sprintf("sensitive read %s (rule: %s)", path, rule)
	case schema.EventTypeNetConnect:
		proto, _ := redactedField(ev.Data, "proto")
		dport, _ := ev.Data["dport"].(uint64)
		return fmt.Sprintf("connect %s :%d", proto, dport)
	case schema.EventTypeNetDNS:
		qname, _ := redactedField(ev.Data, "qname")
		return fmt.Sprintf("dns query %s", qname)
	case schema.EventTypeFsSettle:
		path, _ := redactedField(ev.Data, "path")
		return fmt.Sprintf("file settled %s", path)
	case schema.EventTypeGap:
		reason, _ := redactedField(ev.Data, "reason")
		return fmt.Sprintf("GAP reason=%s (losses are recorded, never silent)", reason)
	default:
		if strings.HasPrefix(string(ev.Type), "alert.") {
			return describeAlert(ev)
		}
		return ""
	}
}

func describeAlert(ev schema.Event) string {
	switch ev.Type {
	case schema.EventTypeAlertSensitiveRead:
		path, _ := redactedField(ev.Data, "path")
		rule, _ := redactedField(ev.Data, "rule")
		return fmt.Sprintf("ALERT sensitive read %s (rule: %s)", path, rule)
	case schema.EventTypeAlertNewDomain:
		qname, _ := redactedField(ev.Data, "qname")
		return fmt.Sprintf("ALERT new domain %s", qname)
	case schema.EventTypeAlertCgroupEscape:
		from, _ := redactedField(ev.Data, "from")
		to, _ := redactedField(ev.Data, "to")
		return fmt.Sprintf("ALERT cgroup escape %s -> %s", from, to)
	case schema.EventTypeAlertEscapePrecursor:
		precursor, _ := redactedField(ev.Data, "precursor")
		return fmt.Sprintf("ALERT escape precursor: %s", precursor)
	case schema.EventTypeAlertBurst:
		class, _ := redactedField(ev.Data, "class")
		return fmt.Sprintf("ALERT burst: %s", class)
	default:
		return "ALERT"
	}
}

// writeCausalityClusters groups marker.* events by their runId field (when
// present) and lists, per cluster, only the fixed identifier/lifecycle
// fields (runId, agentId, channel, status) plus the marker's event type —
// never the marker's full Data map, which could in principle carry other
// profile-declared carried fields. This is a structural guard against P7:
// even a misconfigured profile that carries an extra field cannot make it
// into the rendered report through this path.
func writeCausalityClusters(b *strings.Builder, events []schema.Event) {
	b.WriteString("## Causality Clusters (by marker runId)\n\n")

	type clusterEntry struct {
		idx     uint64
		tsWall  uint64
		evType  schema.EventType
		agentID string
		channel string
		status  string
	}
	clusters := make(map[string][]clusterEntry)
	var order []string
	var unclustered []schema.Event

	for _, ev := range events {
		if !schema.IsMarkerType(ev.Type) {
			continue
		}
		runID, ok := redactedField(ev.Data, "runId")
		if !ok || runID == "" {
			unclustered = append(unclustered, ev)
			continue
		}
		if _, seen := clusters[runID]; !seen {
			order = append(order, runID)
		}
		agentID, _ := redactedField(ev.Data, "agentId")
		channel, _ := redactedField(ev.Data, "channel")
		status, _ := redactedField(ev.Data, "status")
		clusters[runID] = append(clusters[runID], clusterEntry{
			idx: ev.Idx, tsWall: ev.TsWall, evType: ev.Type,
			agentID: agentID, channel: channel, status: status,
		})
	}

	if len(order) == 0 {
		b.WriteString("_No marker-correlated causality clusters for this session._\n\n")
		return
	}

	sort.Strings(order)
	for _, runID := range order {
		fmt.Fprintf(b, "### runId `%s`\n\n", runID)
		for _, e := range clusters[runID] {
			fmt.Fprintf(b, "- `[idx %d, ts_wall %d]` %s", e.idx, e.tsWall, e.evType)
			var extras []string
			if e.agentID != "" {
				extras = append(extras, "agent="+e.agentID)
			}
			if e.channel != "" {
				extras = append(extras, "channel="+e.channel)
			}
			if e.status != "" {
				extras = append(extras, "status="+e.status)
			}
			if len(extras) > 0 {
				b.WriteString(" (" + strings.Join(extras, ", ") + ")")
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
}

func writeFooter(b *strings.Builder) {
	b.WriteString("---\n\n")
	b.WriteString(limitsPointer + "\n")
}

// ---- small helpers over schema.Event.Data (redact.Redacted-typed fields
// only — never a generic dump) ----

func findFirst(events []schema.Event, t schema.EventType) *schema.Event {
	for i := range events {
		if events[i].Type == t {
			return &events[i]
		}
	}
	return nil
}

// redactedField reads data[key] as a redact.Redacted or plain string,
// returning ("", false) if the key is absent or not string-shaped. Shared by
// this file's per-type describeEvent/describeAlert cases and by
// digest_diff.go's DigestDiff (fs.settle's "path" field is always a
// redact.Redacted via schema.NewFsSettle, but this also accepts a plain
// string defensively for synthetic test events built without going through
// the redaction pipeline).
func redactedField(data map[string]any, key string) (string, bool) {
	v, ok := data[key]
	if !ok {
		return "", false
	}
	switch s := v.(type) {
	case redact.Redacted:
		return string(s), true
	case string:
		return s, true
	default:
		return "", false
	}
}

// redactedSliceField reads data[key] as a list of already-redacted
// strings, accepting either the in-process shape ([]redact.Redacted, as
// schema constructors build it before any encode round-trip) or the
// generic shape a CBOR decode produces for an array of text values
// ([]any of plain strings — cborcanon.Decode's Data field only pins the
// map itself to map[string]any; array *elements* decode generically).
// Either way the values passing through here already went through the
// redaction pipeline before ever being encoded (P3) — this function only
// normalizes their Go representation for display, it does not redact.
func redactedSliceField(data map[string]any, key string) []string {
	v, ok := data[key]
	if !ok {
		return nil
	}
	switch slice := v.(type) {
	case []redact.Redacted:
		out := make([]string, len(slice))
		for i, r := range slice {
			out[i] = string(r)
		}
		return out
	case []any:
		out := make([]string, 0, len(slice))
		for _, elem := range slice {
			switch e := elem.(type) {
			case redact.Redacted:
				out = append(out, string(e))
			case string:
				out = append(out, e)
			}
		}
		return out
	default:
		return nil
	}
}

// asStringAnyMap accepts either a map[string]any (the shape produced by
// schema.NewSessionStart's own callers before any encode round-trip, and
// by synthetic test fixtures) or a map[any]any (the shape fxamacker/cbor
// produces for a nested map value decoded generically off the wire/ledger,
// since cborcanon.Decode's top-level Data field is the only one told to
// decode into map[string]any — nested map values fall back to CBOR's
// generic map[any]any), normalizing either into map[string]any for
// display. Non-string keys are skipped rather than causing a panic or a
// silently wrong report.
func asStringAnyMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			if ks, ok := k.(string); ok {
				out[ks] = val
			}
		}
		return out, true
	default:
		return nil, false
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func formatValue(v any) string {
	switch t := v.(type) {
	case redact.Redacted:
		return string(t)
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}

func nonEmpty(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}
