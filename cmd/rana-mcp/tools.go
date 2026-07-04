package main

import (
	"context"
	"fmt"
)

// builtinTools is the read-only tool set exposed to the model. Every one is a
// query over the already-redacted, effects-only ledger — none can write, and
// none can surface a secret or model I/O (there are none to surface).
func builtinTools() []toolDef {
	strProp := func(desc string) map[string]any {
		return map[string]any{"type": "string", "description": desc}
	}
	sessionArg := map[string]any{
		"type":       "object",
		"properties": map[string]any{"session": strProp("The session id (from rana_list_sessions).")},
		"required":   []string{"session"},
	}

	return []toolDef{
		{
			Name: "rana_list_sessions",
			Description: "List every recorded agent session (id, profile, start/end time). " +
				"The entry point — most other tools take a session id from here.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
			handler: func(ctx context.Context, be Backend, _ map[string]any) (string, error) {
				sessions, err := be.Sessions(ctx)
				if err != nil {
					return "", err
				}
				return jsonText(map[string]any{"sessions": sessions, "count": len(sessions)})
			},
		},
		{
			Name: "rana_get_alerts",
			Description: "The signal: the alert.* events for a session (first-contact domain, " +
				"sensitive-read, burst, and the exfil-precursor 'trifecta'). Start here to see " +
				"what needs attention before reading the full event stream.",
			InputSchema: sessionArg,
			handler: func(ctx context.Context, be Backend, args map[string]any) (string, error) {
				session, err := argString(args, "session")
				if err != nil {
					return "", err
				}
				alerts, err := be.Alerts(ctx, session)
				if err != nil {
					return "", err
				}
				return jsonText(map[string]any{"session": session, "alerts": alerts, "count": len(alerts)})
			},
		},
		{
			Name: "rana_get_events",
			Description: "The effects timeline for a session: proc.exec / fs.* / net.* / marker.* " +
				"events, oldest first, already redacted (secrets appear only as typed markers). " +
				"Paginate with 'after' (return events with idx > after) and 'limit'.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"session": strProp("The session id."),
					"after":   map[string]any{"type": "integer", "description": "Return events whose idx is greater than this (0 for the start)."},
					"limit":   map[string]any{"type": "integer", "description": "Max events to return (default 200)."},
				},
				"required": []string{"session"},
			},
			handler: func(ctx context.Context, be Backend, args map[string]any) (string, error) {
				session, err := argString(args, "session")
				if err != nil {
					return "", err
				}
				after := uint64(argIntOr(args, "after", 0))
				limit := argIntOr(args, "limit", 200)
				if limit <= 0 || limit > 2000 {
					limit = 200
				}
				events, err := be.Events(ctx, session, after, limit)
				if err != nil {
					return "", err
				}
				var nextAfter uint64
				if n := len(events); n > 0 {
					if idx, ok := events[n-1]["idx"].(uint64); ok {
						nextAfter = idx
					} else if f, ok := events[n-1]["idx"].(float64); ok {
						nextAfter = uint64(f)
					}
				}
				return jsonText(map[string]any{
					"session": session, "events": events, "count": len(events),
					"next_after": nextAfter,
					"note":       "String values that were secrets appear as typed redaction markers, never cleartext (P3).",
				})
			},
		},
		{
			Name: "rana_verify",
			Description: "Verify a session's cryptographic chain. Returns intact (0), broken/tampered " +
				"(2), or incomplete (3) with the findings. Use this to confirm the record you are " +
				"reasoning over has not been altered since it was written.",
			InputSchema: sessionArg,
			handler: func(_ context.Context, be Backend, args map[string]any) (string, error) {
				session, err := argString(args, "session")
				if err != nil {
					return "", err
				}
				res, err := be.Verify(session)
				if err != nil {
					return "", err
				}
				return jsonText(res)
			},
		},
		{
			Name: "rana_incident_report",
			Description: "A human-readable Markdown incident report for a session: header (profile, " +
				"host), the load-bearing timeline, run-cluster causality, and the alerts — a " +
				"narrative synthesis of what the agent did, suitable to summarize or quote.",
			InputSchema: sessionArg,
			handler: func(ctx context.Context, be Backend, args map[string]any) (string, error) {
				session, err := argString(args, "session")
				if err != nil {
					return "", err
				}
				md, err := be.IncidentReport(ctx, session)
				if err != nil {
					return "", err
				}
				if md == "" {
					return "", fmt.Errorf("no report for session %q (unknown session?)", session)
				}
				return md, nil
			},
		},
	}
}
