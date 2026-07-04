# rana-mcp — query the ledger from an agent

`rana-mcp` is a **read-only** [Model Context Protocol](https://modelcontextprotocol.io)
server over a RanA ledger. It lets an agent or LLM reason about **what another
agent did** — the tamper-evident, kernel-truth, already-redacted timeline of
effects — over stdio.

Why this is safe to hand a model: the ledger contains **effects only, never
prompts, completions, keystrokes, or secrets** (P7 + P3). Every string a secret
could hide in was redacted to a typed marker *before it was hashed*, so there is
nothing sensitive for a tool to leak. And every tool is a **read**: `rana-mcp`
never writes to the ledger and exposes no capture surface.

## Tools

| Tool | What it returns |
|---|---|
| `rana_list_sessions` | Every recorded session (id, profile, start/end). The entry point. |
| `rana_get_alerts` | The **signal** — the `alert.*` events (first-contact domain, sensitive-read, burst, the exfil-precursor trifecta). Start here. |
| `rana_get_events` | The effects timeline (`proc.exec` / `fs.*` / `net.*` / `marker.*`), oldest first, paginated by `after`/`limit`. |
| `rana_verify` | Verify a session's cryptographic chain: intact (0), broken/tampered (2), or incomplete (3). |
| `rana_incident_report` | A Markdown narrative: header, load-bearing timeline, run-cluster causality, alerts. |

## Run it

```sh
rana-mcp --data ~/.local/share/rana      # or set RANA_DATA_DIR
```

It speaks JSON-RPC 2.0 over stdio (newline-delimited), so any MCP client
launches it as a subprocess. Example client config (Claude Desktop / Claude
Code / any MCP host):

```json
{
  "mcpServers": {
    "rana": {
      "command": "rana-mcp",
      "args": ["--data", "/home/you/.local/share/rana"]
    }
  }
}
```

Then ask your agent things like *"which of my recorded sessions has a critical
alert, and verify its chain is intact"* or *"summarize what the openclaw session
touched on disk."* The agent answers from the signed effects record — without
ever seeing a prompt or a secret, because there are none in the ledger to see.

## The correlation, done right

`rana-mcp` surfaces the `marker.*` events, which carry the run identifiers
(`runId`, `agentId`, `channel`, `status`) — **identifiers only, no content**. To
tie an effect back to the intent behind it, join those `runId`s against your
agent framework's *own* prompt logs, on your side of the wall. RanA holds the
effects and the id; your framework holds the thoughts; you join them when you
need to — the honeypot never gets built.
