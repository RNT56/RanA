# RanA marker bridge for OpenAI Codex CLI

`rana-marker.js` emits **content-free run-lifecycle markers** to RanA so the
timeline can cluster a Codex session's kernel events into causal groups
("session started → these execs → these egress connects → this file changed")
instead of showing a raw, undifferentiated event river.

Markers are **enrichment, never authoritative** (RanA principle P1,
`origin=enrichment`). They carry **identifiers and lifecycle only** (P7):

```json
{ "v": 1, "token": "…", "event": "run.start", "origin": "enrichment",
  "runId": "<codex session_id>", "agentId": "codex", "channel": "cli",
  "status": "accepted", "phase": "start", "ts": 1720100000000 }
```

It **never** sends prompts, completions, `last_assistant_message`, the transcript
path, the model name, or any other message/model content. Codex's hook payload
*does* include those on stdin; the script reads them into a variable it never
forwards and ships only `session_id` (an identifier) plus a fixed status label.

## What it maps

Codex's lifecycle-hook facility runs a `type = "command"` hook for each event and
passes the event as a single JSON object on **stdin**
(fields: `session_id`, `hook_event_name`, `cwd`, `source`, …).
See the Codex hooks docs: <https://developers.openai.com/codex/hooks>

| Codex hook event | RanA marker | status        |
|------------------|-------------|---------------|
| `SessionStart`   | `run.start` | `accepted`    |
| `Stop`           | `run.end`   | `completed`   |

`runId` is Codex's `session_id`; `agentId` is `codex`; `channel` is `cli`.
`Stop` is reported as `completed` because a Codex crash never reaches a Stop
hook and the payload carries no error signal.

## Inert when RanA is absent

If `RANA_MARKER_SOCKET` is unset or empty, the script does nothing at all — no
socket, no error, exit 0. Codex runs completely untouched. RanA sets
`RANA_MARKER_SOCKET` / `RANA_MARKER_TOKEN` in the session environment when it
adopts the Codex process; without RanA present those vars simply aren't there.

## Best-effort and crash-proof (P2)

Every failure path — RanA down, malformed stdin, serialize error, wedged socket
— is swallowed silently, and the process always exits `0` so Codex never sees a
hook failure. A 250 ms socket timeout guarantees a stuck socket never lingers.
One short-lived connection per marker keeps it stateless.

## Install / register

Requires `node` on `PATH` (Codex users typically already have it). Copy the
script somewhere stable, e.g.:

```sh
mkdir -p ~/.codex/hooks
cp plugins/codex/rana-marker.js ~/.codex/hooks/rana-marker.js
```

Then add these two hook groups to `~/.codex/config.toml`. The event name is
passed both on stdin (`hook_event_name`) and as an explicit argument, so the
mapping is robust across Codex builds:

```toml
# --- RanA marker bridge (content-free lifecycle markers) ---
[[hooks.SessionStart]]
matcher = "startup|resume"

[[hooks.SessionStart.hooks]]
type    = "command"
command = 'node "~/.codex/hooks/rana-marker.js" SessionStart'
timeout = 5

[[hooks.Stop]]

[[hooks.Stop.hooks]]
type    = "command"
command = 'node "~/.codex/hooks/rana-marker.js" Stop'
timeout = 5
```

That's it. When RanA is recording the Codex session, the timeline gains
run-boundary markers; when it isn't, the hook is a no-op.

## License

Apache-2.0 (same as RanA).
