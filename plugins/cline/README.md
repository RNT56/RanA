# RanA marker bridge for Cline

An optional, tiny set of [Cline hooks](https://docs.cline.bot/features/hooks)
that emit **run-lifecycle markers** to RanA's local marker socket. Markers let
the RanA timeline cluster a task's kernel events into
"task started → these execs → these egress connects → this file changed"
(the *causality* lens) instead of a flat, undifferentiated event river.

It is **enrichment only** and completely optional. RanA already records the real
(kernel-truth, eBPF-sourced) events with or without these hooks; the markers just
add run boundaries — keyed on Cline's `taskId` — so the timeline reads better.

## Files

| File | Role |
|---|---|
| `rana-marker.js` | The shared implementation (Node). Reads one `HookInput` JSON on stdin, emits at most one marker, exits. |
| `TaskStart`, `TaskComplete`, `TaskCancel` | Thin executable wrappers named exactly after Cline's hook events; each `exec`s `rana-marker.js` with the event name. |

Cline discovers hooks as **executable files named exactly after the lifecycle
event** (no extension) in a hooks directory, and runs the matching file with the
event JSON on stdin. Keeping the logic in one file (`rana-marker.js`) means the
P7 allowlist is reviewed in one place; the wrappers are three lines each.

## What it sends — and what it never sends

Each marker is one line of newline-delimited JSON over a Unix domain socket:

```json
{"v":1,"token":"<token>","event":"run.start","origin":"enrichment","runId":"<taskId>","agentId":"cline","channel":"cli","status":"accepted","phase":"start","ts":1712345678901}
```

**Identifiers and lifecycle ONLY.** The allowlisted keys are exactly:
`runId`, `agentId`, `channel`, `status`, `phase`, `ts`.

It **never** sends prompts, completions, message text, task descriptions,
tool params/results, workspace paths, or any model/user content. This is RanA
principle **P7** ("effects, not thoughts") and is enforced two ways: the script
only ever *reads* `taskId` and `hookName` from the payload, and a final
`sanitize()` pass drops anything outside the allowlist before a byte leaves the
process. Markers are `origin: "enrichment"` — never authoritative (**P1**);
RanA's listener will never let a marker fabricate a kernel event. A smoke test
confirms that a `HookInput` stuffed with `task`, `prompt`, `content`,
`workspaceRoots`, and `userId` produces markers containing none of them.

## Lifecycle mapping

| Cline hook event | RanA marker | status |
|---|---|---|
| `TaskStart` (and `TaskResume`) | `run.start` | `accepted` |
| `TaskComplete` (after `attempt_completion`) | `run.end` | `completed` |
| `TaskCancel` | `run.end` | `cancelled` |

`runId` is Cline's `taskId`. Content-bearing hooks — `UserPromptSubmit`,
`PreToolUse`, `PostToolUse`, `PreCompact` — are deliberately **not** installed;
they carry prompt/tool text RanA must never touch (P7).

## Inert when RanA isn't present

The hook reads its socket path and per-session token from the environment:

- `RANA_MARKER_SOCKET` — path to the RanA marker Unix socket
- `RANA_MARKER_TOKEN` — per-session shared token

RanA sets these when it adopts/records a Cline session. **If
`RANA_MARKER_SOCKET` is absent or empty, the hook is completely inert** — it
does not open a socket, does not error, does not read stdin content, prints
nothing, and exits cleanly. It is best-effort throughout: a connection error,
RanA being down, a malformed payload, or a wedged socket (250 ms timeout) all
end in a clean `exit(0)` with no stdout, so Cline treats the hook as a no-op
"allow" and is never blocked or disrupted (**P2**).

## Install

Requires `node` on `PATH` (Cline is a Node application). Copy the four files
into a Cline hooks directory, preserving the executable bit:

```sh
# Global — the CLI / hub default hooks dir:
mkdir -p ~/.cline/hooks
cp rana-marker.js TaskStart TaskComplete TaskCancel ~/.cline/hooks/
chmod +x ~/.cline/hooks/TaskStart ~/.cline/hooks/TaskComplete ~/.cline/hooks/TaskCancel ~/.cline/hooks/rana-marker.js

# — or the VS Code extension's documented global hooks dir:
#   ~/Documents/Cline/Rules/Hooks/
#
# — or project-scoped:
#   <repo>/.clinerules/hooks/
```

The CLI can also point at an arbitrary directory with `cline --hooks-dir <path>`
(default `~/.cline/hooks`). RanA populates `RANA_MARKER_SOCKET` /
`RANA_MARKER_TOKEN` for the recorded session; you do not set them by hand.

## Note on the VS Code extension vs the CLI

The markers work the same however Cline is launched, but **kernel-event
attribution differs** and this is documented in the `cline` profile and
`LIMITS.md`:

- **CLI / hub** (`cline`, `cline --zen`): Cline runs as its own process tree, so
  its execs, file writes, and egress attribute directly to `cline`. Clean path.
- **VS Code extension** (`saoudrizwan.claude-dev`): the agent runs inside the VS
  Code *extension-host* process. RanA still captures the kernel effects (they are
  execs under the Code subtree in the session cgroup), but they attribute to
  `code`/the extension host rather than to a `cline` binary. The marker `runId`
  (Cline's `taskId`) is what re-associates those effects with the Cline task in
  that case — which is exactly what these hooks provide.

## License

Apache-2.0 (same as RanA).
