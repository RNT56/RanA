# RanA marker bridge for Claude Code

`rana-marker.js` is a tiny, optional [Claude Code hook](https://code.claude.com/docs/en/hooks)
that emits **run-lifecycle markers** to RanA's local marker socket. Markers let
the RanA timeline cluster a session's kernel events into
"session started → these execs → these egress connects → this file changed"
(the *causality* lens) instead of showing a flat, undifferentiated event river.

It is **enrichment only** and completely optional. RanA already records the real
(kernel-truth, eBPF-sourced) events with or without this hook; the marker just
adds run boundaries so the timeline reads better.

## What it sends — and what it never sends

Each marker is one line of newline-delimited JSON over a Unix domain socket:

```json
{"v":1,"token":"<token>","event":"run.start","origin":"enrichment","runId":"<session_id>","agentId":"<agent_id>","channel":"startup","status":"accepted","phase":"start","ts":1712345678901}
```

**Identifiers and lifecycle ONLY.** The allowlisted keys are exactly:
`runId`, `agentId`, `channel`, `status`, `phase`, `ts`.

It **never** sends prompts, completions, message text, summaries, transcript
paths, session titles, or any model/user content. This is RanA principle **P7**
("effects, not thoughts") and is enforced two ways in the script: it only ever
*reads* identifier fields from the hook payload, and a final `sanitize()` pass
drops anything outside the allowlist before a byte leaves the process. Markers
are `origin: "enrichment"` — never authoritative (**P1**); RanA's listener will
never let a marker fabricate a kernel event.

## Lifecycle mapping

| Claude Code hook event | RanA marker | status |
|---|---|---|
| `SessionStart` | `run.start` | `accepted` |
| `SessionEnd` | `run.end` | `completed` (or `error`) |
| `Stop` *(optional)* | `run.end` | `completed` |

The script selects the marker from the hook payload's `hook_event_name`, so a
single command wired to both `SessionStart` and `SessionEnd` is all you need.
`runId` is the Claude Code `session_id`; `agentId` is the `agent_id` (present
only for subagents; omitted otherwise); `channel` on `run.start` is the
`SessionStart` `source` label (`startup`/`resume`/…). All are fixed
identifiers/enums, never free text.

> **Note on `Stop`:** `Stop` fires at the end of *every* response turn, so
> wiring it will emit a `run.end` after each turn (treating each turn as a run).
> If you want one run per whole session, wire `SessionEnd` only. `SessionEnd`
> does not fire on every termination path, so `Stop` is offered as a coarser but
> more reliable "run closed" signal. Pick one; the default snippet below uses
> `SessionEnd`.

## Inert when RanA isn't present

The hook reads its socket path and per-session token from the environment:

- `RANA_MARKER_SOCKET` — path to the RanA marker Unix socket
- `RANA_MARKER_TOKEN` — per-session shared token

RanA sets these when it adopts/records a Claude Code session. **If
`RANA_MARKER_SOCKET` is absent or empty, the hook is completely inert** — it
does not open a socket, does not error, does not read stdin content, and exits
cleanly. It is also best-effort throughout: a connection error, RanA being down,
a malformed payload, or a wedged socket (250 ms timeout) all end in a clean
exit so Claude Code is never blocked or disrupted (**P2**).

## Install

Requires `node` on `PATH` (Claude Code already runs on Node). Register the hook
in a `settings.json` (`~/.claude/settings.json` for all projects, or
`.claude/settings.json` in a repo). Point the command at this file:

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "node /path/to/rana/plugins/claude-code/rana-marker.js",
            "timeout": 5
          }
        ]
      }
    ],
    "SessionEnd": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "node /path/to/rana/plugins/claude-code/rana-marker.js",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

Replace `/path/to/rana` with the absolute path to your RanA checkout (or copy
`rana-marker.js` somewhere stable and point at that). To also close a run at the
end of each turn, add an identical `"Stop"` block.

That's it. When RanA records the session (with `RANA_MARKER_SOCKET` /
`RANA_MARKER_TOKEN` in the environment), the timeline gains run boundaries;
when RanA isn't present, the hook does nothing.

## License

Apache-2.0 (same as RanA).
