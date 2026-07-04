package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// fakeBackend is an in-memory Backend for driving the protocol without a ledger.
type fakeBackend struct{}

func (fakeBackend) Sessions(context.Context) ([]SessionInfo, error) {
	return []SessionInfo{{ID: "01ARZ3", Profile: "openclaw", StartedNs: 100, EndedNs: 900}}, nil
}
func (fakeBackend) Events(_ context.Context, _ string, after uint64, limit int) ([]map[string]any, error) {
	return []map[string]any{
		{"type": "proc.exec", "idx": float64(1), "origin": "kernel"},
		{"type": "fs.sensitive_read", "idx": float64(2), "origin": "kernel"},
	}, nil
}
func (fakeBackend) Alerts(context.Context, string) ([]map[string]any, error) {
	return []map[string]any{{"type": "alert.sensitive_read", "idx": float64(3)}}, nil
}
func (fakeBackend) Verify(string) (VerifyResult, error) {
	return VerifyResult{Code: 0, Verdict: "intact"}, nil
}
func (fakeBackend) IncidentReport(context.Context, string) (string, error) {
	return "# Incident report\n\nopenclaw session.", nil
}

// drive runs a batch of JSON-RPC request lines through the server and returns
// the decoded responses (nil entries for notifications that got no reply).
func drive(t *testing.T, reqs ...string) []rpcResponse {
	t.Helper()
	in := strings.NewReader(strings.Join(reqs, "\n") + "\n")
	var out bytes.Buffer
	if err := run(newServer(fakeBackend{}), in, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	var resps []rpcResponse
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var r rpcResponse
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("bad response line %q: %v", line, err)
		}
		resps = append(resps, r)
	}
	return resps
}

func TestMCP_InitializeAdvertisesTools(t *testing.T) {
	r := drive(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if len(r) != 1 || r[0].Error != nil {
		t.Fatalf("initialize failed: %+v", r)
	}
	res, _ := r[0].Result.(map[string]any)
	if res["protocolVersion"] != protocolVersion {
		t.Errorf("protocolVersion = %v, want %q", res["protocolVersion"], protocolVersion)
	}
	caps, _ := res["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Errorf("initialize did not advertise tools capability: %v", caps)
	}
}

func TestMCP_NotificationGetsNoReply(t *testing.T) {
	// A notification (no id) must produce NO response line.
	r := drive(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if len(r) != 0 {
		t.Fatalf("notification produced a reply: %+v", r)
	}
}

func TestMCP_ToolsListHasAllReadTools(t *testing.T) {
	r := drive(t, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	res, _ := r[0].Result.(map[string]any)
	tools, _ := res["tools"].([]any)
	got := map[string]bool{}
	for _, tv := range tools {
		tm, _ := tv.(map[string]any)
		got[tm["name"].(string)] = true
	}
	for _, want := range []string{"rana_list_sessions", "rana_get_events", "rana_get_alerts", "rana_verify", "rana_incident_report"} {
		if !got[want] {
			t.Errorf("tools/list missing %q (got %v)", want, got)
		}
	}
}

func TestMCP_CallSessionsAndEvents(t *testing.T) {
	r := drive(t,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rana_list_sessions","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"rana_get_events","arguments":{"session":"01ARZ3","limit":10}}}`,
	)
	if len(r) != 2 {
		t.Fatalf("want 2 responses, got %d", len(r))
	}
	// Sessions result text should mention the session id.
	text := toolText(t, r[0])
	if !strings.Contains(text, "01ARZ3") || !strings.Contains(text, "openclaw") {
		t.Errorf("sessions text missing content: %s", text)
	}
	// Events result should carry a next_after cursor and the redaction note.
	etext := toolText(t, r[1])
	if !strings.Contains(etext, "sensitive_read") || !strings.Contains(etext, "next_after") {
		t.Errorf("events text missing content: %s", etext)
	}
	if !strings.Contains(etext, "redaction markers") {
		t.Errorf("events result should carry the P3 redaction note: %s", etext)
	}
}

func TestMCP_CallMissingArgIsToolError(t *testing.T) {
	// A tool call missing its required arg returns isError=true (not an RPC error).
	r := drive(t, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"rana_get_events","arguments":{}}}`)
	res, _ := r[0].Result.(map[string]any)
	if res == nil || res["isError"] != true {
		t.Fatalf("missing-arg call should be a tool error, got %+v", r[0])
	}
}

func TestMCP_UnknownMethodAndTool(t *testing.T) {
	r := drive(t,
		`{"jsonrpc":"2.0","id":6,"method":"no/such/method"}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"rana_delete_everything","arguments":{}}}`,
	)
	if r[0].Error == nil || r[0].Error.Code != codeMethodNotFd {
		t.Errorf("unknown method should be a method-not-found error: %+v", r[0])
	}
	if r[1].Error == nil {
		t.Errorf("unknown tool should error (no write tools exist): %+v", r[1])
	}
}

func toolText(t *testing.T, r rpcResponse) string {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("tool call errored: %+v", r.Error)
	}
	res, _ := r.Result.(map[string]any)
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content in %+v", res)
	}
	c0, _ := content[0].(map[string]any)
	return c0["text"].(string)
}
