# RanA marker emitter for Hermes Agent

`rana_plugin.py` emits **run-lifecycle markers** (`run.start` / `run.end`) from
[Hermes Agent](https://github.com/NousResearch/hermes-agent) to RanA's local
marker socket, so RanA can cluster a run's kernel effects by `runId` — turning
the raw event river into *"inbound message → these execs → these egress
connects → this file changed."*

It sends **identifiers and lifecycle only** — `runId`, `agentId`, `channel`,
`status`, `phase`, `ts`. It **never** sends prompts, completions, message text,
or any model I/O (P7). The allowlist strips everything else before it leaves the
process, and RanA's listener rejects any forbidden field, so it fails safe.

## Install

Drop the plugin where Hermes discovers plugins:

```sh
mkdir -p ~/.hermes/plugins
cp rana_plugin.py ~/.hermes/plugins/
```

Hermes auto-loads plugins from `~/.hermes/plugins/` (user-level),
`.hermes/plugins/` (project-level), or a `plugin` entry in `config.yaml`, and
calls `register(context)`. This plugin registers hooks on the run/session start
and end lifecycle events via the context's hook API.

## Wiring the hooks

Hermes's hook names live in `gateway/hooks.py` and can vary across versions, so
`register()` tries the common lifecycle names (`run_start`/`session_start`/… →
`run.start`, `run_end`/`session_end`/… → `run.end`) and no-ops on whatever isn't
present — a plugin must never break the agent. If your Hermes build uses
different hook names, point them at `on_run_start` / `on_run_end` (both take the
run context and read `run_id`/`session_id` + `channel` from it).

RanA provides `RANA_MARKER_SOCKET` and `RANA_MARKER_TOKEN` in the environment of
the recorded session (via `rana run hermes …` or `rana adopt hermes`). When they
are absent, the plugin is completely inert — safe to leave installed even when
RanA isn't running.

## Verify the wire format

Without a running RanA, point it at a loopback socket and run the smoke test:

```sh
# terminal 1: a throwaway listener at the socket path
python3 -c 'import socket,os; p="/tmp/m.sock"; os.path.exists(p) and os.unlink(p); s=socket.socket(socket.AF_UNIX); s.bind(p); s.listen(1); c,_=s.accept(); print(c.recv(4096).decode())'
# terminal 2:
RANA_MARKER_SOCKET=/tmp/m.sock RANA_MARKER_TOKEN=t python3 rana_plugin.py
```

You should see a `{"event":"run.start",…}` line with only identifier fields.

## Note on Hermes's execution environments

Hermes can run tool code in **Docker / Modal / Daytona / SSH** environments. RanA
records the *local* Hermes process tree; code Hermes offloads to a container or a
remote host runs outside the session's cgroup and is a documented blind spot
(`profiles/hermes.toml`, `LIMITS.md`). The marker still ties the local timeline
to the run — but the remote effects themselves are not RanA's to see.
