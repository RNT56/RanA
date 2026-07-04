// Command rana-mcp is a read-only Model Context Protocol server over a RanA
// ledger. It lets an agent/LLM query what ANOTHER agent did — the
// tamper-evident, kernel-truth, already-redacted effects timeline — over
// stdio, without ever touching secrets or model I/O (there are none in the
// ledger by construction: P3 redaction + P7 effects-only). Every tool is a
// READ; the server never writes to the ledger and exposes no capture surface.
package main

import (
	"context"
	"encoding/json"
	"fmt"
)

// protocolVersion is the MCP protocol revision this server implements against.
const protocolVersion = "2024-11-05"

const serverName = "rana-mcp"

// --- JSON-RPC 2.0 envelopes (MCP stdio transport: newline-delimited JSON). ---

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent => notification
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

const (
	codeParse       = -32700
	codeInvalidReq  = -32600
	codeMethodNotFd = -32601
	codeInvalid     = -32602
	codeInternal    = -32603
)

// --- Backend: the read-only ledger surface the tools call. Injected so the
// server is testable without a real ledger. ---

// SessionInfo is one recorded session, as an MCP tool reports it.
type SessionInfo struct {
	ID        string `json:"id"`
	Profile   string `json:"profile"`
	StartedNs uint64 `json:"started_ns"`
	EndedNs   uint64 `json:"ended_ns"`
}

// VerifyResult is the verdict of a chain verification.
type VerifyResult struct {
	Code     int      `json:"code"` // 0 intact, 2 broken (tamper), 3 incomplete
	Verdict  string   `json:"verdict"`
	Findings []string `json:"findings,omitempty"`
}

// Backend is the read-only data access the tools need. schema events are
// returned as already-JSON-shaped maps (already redacted — no raw secrets).
type Backend interface {
	Sessions(ctx context.Context) ([]SessionInfo, error)
	Events(ctx context.Context, session string, after uint64, limit int) ([]map[string]any, error)
	Alerts(ctx context.Context, session string) ([]map[string]any, error)
	Verify(session string) (VerifyResult, error)
	IncidentReport(ctx context.Context, session string) (string, error)
}

// --- Server ---

type server struct {
	be    Backend
	tools []toolDef
}

type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	handler     func(ctx context.Context, be Backend, args map[string]any) (string, error)
}

func newServer(be Backend) *server {
	s := &server{be: be}
	s.tools = builtinTools()
	return s
}

// handle dispatches one JSON-RPC request and returns a response, or nil for a
// notification (no id) which MCP requires we not reply to.
func (s *server) handle(ctx context.Context, req rpcRequest) *rpcResponse {
	if len(req.ID) == 0 {
		// Notification (e.g. notifications/initialized): do the side effect if
		// any, never reply.
		return nil
	}
	reply := func(result any) *rpcResponse { return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result} }
	fail := func(code int, msg string) *rpcResponse {
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: code, Message: msg}}
	}

	switch req.Method {
	case "initialize":
		return reply(map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "version": versionString()},
			"instructions": "Read-only access to a RanA ledger: the tamper-evident, kernel-truth, " +
				"already-redacted record of what an AI agent executed, touched, and contacted. " +
				"It contains effects only — never prompts, completions, or secrets. Start with " +
				"rana_list_sessions, then rana_get_alerts for what needs attention, rana_get_events " +
				"for detail, rana_verify to confirm the chain is intact, and rana_incident_report " +
				"for a narrative summary.",
		})
	case "tools/list":
		return reply(map[string]any{"tools": s.tools})
	case "tools/call":
		return s.callTool(ctx, req, reply, fail)
	case "ping":
		return reply(map[string]any{})
	default:
		return fail(codeMethodNotFd, "method not found: "+req.Method)
	}
}

func (s *server) callTool(ctx context.Context, req rpcRequest,
	reply func(any) *rpcResponse, fail func(int, string) *rpcResponse) *rpcResponse {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return fail(codeInvalid, "invalid tools/call params: "+err.Error())
	}
	var tool *toolDef
	for i := range s.tools {
		if s.tools[i].Name == p.Name {
			tool = &s.tools[i]
			break
		}
	}
	if tool == nil {
		return fail(codeInvalid, "unknown tool: "+p.Name)
	}
	text, err := tool.handler(ctx, s.be, p.Arguments)
	if err != nil {
		// MCP convention: a tool error is a normal result with isError=true, so
		// the model sees the failure rather than the whole call erroring out.
		return reply(map[string]any{
			"content": []map[string]any{{"type": "text", "text": "error: " + err.Error()}},
			"isError": true,
		})
	}
	return reply(map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
	})
}

// --- argument helpers ---

func argString(args map[string]any, key string) (string, error) {
	v, ok := args[key]
	if !ok {
		return "", fmt.Errorf("missing required argument %q", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("argument %q must be a string", key)
	}
	return s, nil
}

func argIntOr(args map[string]any, key string, def int) int {
	v, ok := args[key]
	if !ok {
		return def
	}
	// JSON numbers decode to float64.
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return def
}

func jsonText(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
