# RanA marker bridge for goose

`rana-marker.sh` is a tiny, optional [goose hook](https://goose-docs.ai/blog/2026/05/14/goose-hooks/)
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
{"v":1,"token":"<token>","event":"run.start","origin":"enrichment","runId":"<session_id>","agentId":"goose","status":"accepted","phase":"start","ts":1712345678901}
```

**Identifiers and lifecycle ONLY.** The allowlisted keys are exactly:
`runId`, `agentId`, `channel`, `status`, `phase`, `ts`.

It **never** sends prompts, messages, tool inputs/outputs, file contents, or
working paths' contents. This is RanA principle **P7** ("effects, not thoughts").
Enforcement is by construction: the script reads **only** the `session_id` field
from goose's hook payload — it never touches `prompt`, `message`, or `tool_input`
— and it assembles the outgoing JSON by hand from shell-escaped scalar values, so
no content field can be smuggled through. Markers are `origin: "enrichment"` —
never authoritative (**P1**); RanA's listener will never let a marker fabricate a
kernel event, and it rejects any line carrying a forbidden field.

## Lifecycle mapping

goose delivers [command hooks](https://goose-docs.ai/blog/2026/05/14/goose-hooks/)
by running a command as a short-lived subprocess and passing the event JSON on
**stdin** (fields include `event`, `session_id`, `working_dir`). This script reads
one object, emits at most one marker, and exits.

| goose hook event | RanA marker | status |
|---|---|---|
| `SessionStart` | `run.start` | `accepted` |
| `SessionEnd` *(or `Stop`)* | `run.end` | `completed` |

Every other goose hook event (`UserPromptSubmit`, `PreToolUse`, `PostToolUse`,
`BeforeShellExecution`, …) is ignored — those carry model/tool content we must
not read.

## Install

goose auto-discovers plugins that contain a `hooks/hooks.json`. Under user scope
that is `~/.agents/plugins/<name>/`.

1. Copy the script somewhere stable and make it executable:

   ```sh
   mkdir -p ~/.agents/plugins/rana/hooks
   cp rana-marker.sh ~/.agents/plugins/rana/hooks/rana-marker.sh
   chmod +x ~/.agents/plugins/rana/hooks/rana-marker.sh
   ```

2. Create `~/.agents/plugins/rana/hooks/hooks.json` wiring both lifecycle
   events to the one command:

   ```json
   {
     "hooks": {
       "SessionStart": [
         { "hooks": [ { "type": "command", "command": "~/.agents/plugins/rana/hooks/rana-marker.sh" } ] }
       ],
       "SessionEnd": [
         { "hooks": [ { "type": "command", "command": "~/.agents/plugins/rana/hooks/rana-marker.sh" } ] }
       ]
     }
   }
   ```

That's it. `rana adopt goose` sets `RANA_MARKER_SOCKET` (and a per-session
`RANA_MARKER_TOKEN`) in the goose process environment; the hook picks them up
automatically.

## Safety properties (why this can't hurt goose)

- **Inert without RanA.** If `RANA_MARKER_SOCKET` is unset or empty, the script
  exits `0` immediately without reading stdin or opening any socket (**P2**,
  observation is inert).
- **Best-effort, crash-proof.** RanA down, no listener, a wedged socket, or a
  missing sender tool all end in a clean `exit 0`. The send runs in the
  background under a hard ~2s guard, so it can never hold up a hook slot.
- **No extra runtime dependency.** Pure POSIX `sh`; for the socket write it uses
  whichever of `socat` / `nc` / `python3` / `node` is already present, and for
  parsing it uses `jq` if available or a conservative `sed` fallback. If none are
  present it degrades to a silent no-op.
- **Content-free by construction.** Only `session_id` is read from the payload;
  the marker JSON is built from a fixed allowlist of scalar fields.

## Verify the wire format locally

Start a listener on a socket, point the env at it, and pipe a fake payload:

```sh
# terminal 1: a throwaway listener
socat -u UNIX-LISTEN:/tmp/rana.sock,fork -

# terminal 2:
echo '{"event":"SessionStart","session_id":"sess-123","working_dir":"/x"}' \
  | RANA_MARKER_SOCKET=/tmp/rana.sock RANA_MARKER_TOKEN=demo ./rana-marker.sh
```

You should see exactly one `run.start` line with `runId:"sess-123"`, `agentId:"goose"`,
`origin:"enrichment"`, and no `working_dir` or any content field.

## License

Apache-2.0 (same as RanA).
