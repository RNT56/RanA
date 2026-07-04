# RanA marker emitter for Gemini CLI

`rana-marker.sh` emits **run-lifecycle markers** (`run.start` / `run.end`) from
[Gemini CLI](https://github.com/google-gemini/gemini-cli) to RanA's local marker
socket, so RanA can cluster a session's kernel effects by `runId` — turning the
raw event river into *"session start → these execs → these egress connects →
this file changed."*

It sends **identifiers and lifecycle only** — `runId` (Gemini's `session_id`),
`agentId`, `channel`, `status`, `phase`, `ts`. It **never** sends prompts,
completions, transcript, `GEMINI.md` context, or any model I/O (P7). The script
parses only the session id, the event name, and the short `source`/`reason`
lifecycle label from the hook payload; a defense-in-depth character filter strips
anything unexpected before a line leaves the process, and RanA's listener rejects
any forbidden field — so it fails safe.

## How it wires in

Gemini CLI has a first-class [hooks system](https://geminicli.com/docs/hooks/):
`settings.json` can register **command hooks** that fire on lifecycle events.
Gemini passes each hook a JSON payload on **stdin**. This emitter uses two:

| Gemini event  | stdin fields it reads         | RanA marker |
|---------------|-------------------------------|-------------|
| `SessionStart`| `session_id`, `source`        | `run.start` |
| `SessionEnd`  | `session_id`, `reason`        | `run.end`   |

Content-bearing events (`BeforeModel`/`AfterModel`, `PreToolUse`/`PostToolUse`,
`Notification`) are deliberately **not** hooked — they carry model I/O and tool
arguments RanA must never touch (P7).

## Install

1. Drop the script somewhere on disk (e.g. next to your Gemini config):

   ```sh
   mkdir -p ~/.gemini
   cp rana-marker.sh ~/.gemini/rana-marker.sh
   chmod +x ~/.gemini/rana-marker.sh
   ```

2. Register it as a `SessionStart` and `SessionEnd` command hook in
   `~/.gemini/settings.json` (merge into any existing `hooks` object):

   ```json
   {
     "hooks": {
       "SessionStart": [
         {
           "hooks": [
             { "type": "command", "command": "~/.gemini/rana-marker.sh", "timeout": 2000 }
           ]
         }
       ],
       "SessionEnd": [
         {
           "hooks": [
             { "type": "command", "command": "~/.gemini/rana-marker.sh", "timeout": 2000 }
           ]
         }
       ]
     }
   }
   ```

   The same script handles both events — it branches on `hook_event_name` from
   the stdin payload.

RanA provides `RANA_MARKER_SOCKET` and `RANA_MARKER_TOKEN` in the environment of
the recorded session (via `rana run gemini …` or `rana adopt gemini-cli`). When
they are absent, the hook is completely **inert** (it exits 0 immediately) — safe
to leave wired even when RanA isn't running.

## Verify the wire format

Without a running RanA, point the hook at a loopback socket and feed it a mock
payload:

```sh
# terminal 1: throwaway listener at the socket path
python3 -c 'import socket,os; p="/tmp/m.sock"; os.path.exists(p) and os.unlink(p); s=socket.socket(socket.AF_UNIX); s.bind(p); s.listen(1); c,_=s.accept(); print(c.recv(4096).decode())'

# terminal 2:
echo '{"session_id":"demo-1","hook_event_name":"SessionStart","source":"startup"}' \
  | RANA_MARKER_SOCKET=/tmp/m.sock RANA_MARKER_TOKEN=t ./rana-marker.sh
```

You should see a single `{"event":"run.start",…}` line containing only
identifier/lifecycle fields.

## Dependencies

POSIX shell only. The Unix-socket write prefers `python3`; if that's missing it
falls back to `nc -U`. If neither exists the script silently no-ops (still exits
0) — a marker must never block or fail the agent loop (P2).

## Note on Gemini CLI's sandbox

Gemini CLI can execute shell/tool code inside a **Docker / Podman** sandbox or a
**macOS Seatbelt** profile (`sandbox` in settings / `--sandbox` / `GEMINI_SANDBOX`).
Container-sandboxed execs run in a different cgroup owned by the container
runtime, so RanA records the `docker`/`podman` precursor but not the in-container
work — a documented blind spot (`profiles/gemini-cli.toml`, `LIMITS.md`). The
seatbelt path stays in the local session cgroup and is fully captured. The marker
still ties the local timeline to the run either way.
