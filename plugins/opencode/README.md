# RanA marker bridge for OpenCode

`rana-plugin.ts` is an optional ~150-LOC [OpenCode](https://opencode.ai) plugin
that emits **run-lifecycle markers** to RanA's local marker socket. It upgrades
RanA's raw kernel-event river into causal clusters — "this request → these
execs → these egress connects → this file changed" — by tagging events with the
OpenCode session (run) they belong to.

It is **enrichment only** (RanA principle P1): a marker can mislabel a cluster,
never fabricate a kernel event. If the plugin is absent or RanA is not present,
RanA falls back to inferred (time + process-tree) causality and loses nothing
load-bearing.

## What it sends (and does not)

Markers carry **identifiers and lifecycle ONLY** (P7 — "effects, not thoughts"):

| Sent | Never sent |
|------|------------|
| `runId`, `agentId`, `channel`, `status`, `phase`, `ts` | prompts, completions, message text, tool args/output, summaries, any model I/O |

The plugin enforces this with a hard allowlist (`ALLOWED_FIELDS`) — any field
not on the list is stripped before a byte leaves the process, so even a future
OpenCode event shape that leaked content into a forwarded field could not carry
it out. There is no flag to disable this.

Wire format: newline-delimited JSON over a Unix domain socket, one object per
line:

```json
{"v":1,"token":"<RANA_MARKER_TOKEN>","event":"run.start","origin":"enrichment","runId":"ses_...","status":"accepted","phase":"start","ts":1720099200000}
```

## Lifecycle mapping

The plugin subscribes to OpenCode's generic `event` hook and maps three session
events (see <https://opencode.ai/docs/plugins/>):

| OpenCode event | RanA marker | status |
|----------------|-------------|--------|
| `session.created` | `run.start` | `accepted` |
| `session.idle` (agent finished responding) | `run.end` | `completed` |
| `session.error` | `run.end` | `error` |

`runId` is taken from `event.properties.sessionID`. All content-bearing events
(`message.updated`, `message.part.updated`, `tool.execute.before/after`,
`permission.*`) are deliberately **not** hooked.

## Inert when RanA is absent

The socket path and a shared token come from the environment:

- `RANA_MARKER_SOCKET` — the marker Unix socket path (RanA sets this at
  adopt/run time)
- `RANA_MARKER_TOKEN` — the per-session shared token the listener checks

If `RANA_MARKER_SOCKET` is unset or empty, the plugin does **nothing** — no
socket, no error, no inspection of events. Sends are best-effort and
crash-proof: a connection error, RanA being down, or a serialize failure is
swallowed silently, and a 250 ms socket timeout ensures a wedged socket never
lingers. One short-lived connection per marker keeps the plugin stateless and
never blocks the agent loop (P2 — observation is inert).

## Install

OpenCode auto-loads plugin files from either directory:

- Project-level: `.opencode/plugin/`
- Global: `~/.config/opencode/plugin/`

Copy the plugin into one of them:

```sh
# global (all projects)
mkdir -p ~/.config/opencode/plugin
cp rana-plugin.ts ~/.config/opencode/plugin/rana-plugin.ts

# — or — project-level
mkdir -p .opencode/plugin
cp rana-plugin.ts .opencode/plugin/rana-plugin.ts
```

That is all that is required — OpenCode loads any `.ts`/`.js` file in the plugin
directory at startup. (If you prefer explicit registration or distribute this as
an npm package, add it to the `plugin` array in `opencode.json`:)

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["./.opencode/plugin/rana-plugin.ts"]
}
```

RanA populates `RANA_MARKER_SOCKET` / `RANA_MARKER_TOKEN` for the recorded
session; you do not set them by hand.

## License

Apache-2.0 (same as RanA).
