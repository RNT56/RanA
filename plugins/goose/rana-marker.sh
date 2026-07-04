#!/bin/sh
# rana-marker.sh — RanA marker bridge for goose (Block / AAIF)
# ---------------------------------------------------------------------------
# Emits run-lifecycle MARKERS to the local RanA marker socket so the RanA
# timeline can cluster "session started -> these execs -> these egress connects
# -> this file changed" (the causality lens) instead of a flat, raw event river.
#
# HOW GOOSE DRIVES IT:
#   This is a goose *command hook*. goose runs it as a short-lived subprocess on
#   each lifecycle event and passes the event JSON on stdin. We do NOT stay
#   resident: read one JSON object, emit at most one marker, exit 0. Wired via a
#   plugin's hooks/hooks.json for SessionStart + SessionEnd (see README.md).
#   Hook mechanism: https://goose-docs.ai/blog/2026/05/14/goose-hooks/
#
#   Lifecycle mapping (session granularity — one "run" == one goose session):
#     SessionStart  -> run.start { status:"accepted" }
#     SessionEnd    -> run.end   { status:"completed" }
#   The marker is chosen from stdin's "event" field, so ONE hook command wired
#   to both events is all that is needed.
#
# WHAT THIS SENDS (and the hard rule it enforces):
#   Identifiers + lifecycle ONLY: { runId, agentId, channel, status, phase, ts }.
#   NEVER prompts, messages, tool_input, tool output, file contents, or working
#   paths' contents. This mirrors RanA principle P7 ("effects, not thoughts") and
#   P1 (markers are ENRICHMENT — origin=enrichment; a marker can mislabel, never
#   fabricate a kernel event). We deliberately read ONLY the session id from the
#   payload; we never touch goose's "tool_input", "prompt", or "message" fields.
#
# TRANSPORT: one line of newline-delimited JSON over a Unix domain socket whose
# path + per-session token come from RanA via RANA_MARKER_SOCKET /
# RANA_MARKER_TOKEN. If RANA_MARKER_SOCKET is unset/empty this script is
# completely inert (no socket, no error, clean exit) — RanA simply isn't present
# and goose is unaffected (P2, observation is inert).
#
# DEPENDENCIES: POSIX sh + one of {socat|nc|python3|node} for the datagram, and
# {jq or a tiny sed fallback} for the session id. All are best-effort: if none
# are available, the script exits 0 silently and goose is undisturbed. No
# RanA-attributable failure can ever reach the agent.
#
# LICENSE: Apache-2.0 (same as RanA).

set -u

SOCK="${RANA_MARKER_SOCKET:-}"
TOKEN="${RANA_MARKER_TOKEN:-}"

# Fast path: RanA not present -> do nothing at all (don't even read stdin).
[ -n "$SOCK" ] || exit 0

# --- Read the goose hook payload from stdin (bounded). ----------------------
# head -c caps how much we ever read so a huge payload can't wedge the hook.
INPUT="$(head -c 65536 2>/dev/null)"

# --- Extract ONLY identifier fields. Never read content fields. -------------
# Prefer jq (exact). Fall back to a conservative sed that pulls the first
# "session_id":"..." string. Anything we can't parse becomes empty.
json_str() {
  # $1 = key name. Reads $INPUT from the environment.
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$INPUT" | jq -r --arg k "$1" '.[$k] // empty' 2>/dev/null
  else
    printf '%s' "$INPUT" \
      | sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -n 1
  fi
}

EVENT_NAME="$(json_str event)"
RUN_ID="$(json_str session_id)"

# Map goose lifecycle event -> RanA marker event + status. Only SessionStart /
# SessionEnd are translated; every other goose hook event exits silently.
case "$EVENT_NAME" in
  SessionStart)
    MARKER_EVENT="run.start"; STATUS="accepted"; PHASE="start" ;;
  SessionEnd|Stop)
    MARKER_EVENT="run.end";   STATUS="completed"; PHASE="end" ;;
  *)
    exit 0 ;;
esac

TS="$(date +%s000 2>/dev/null || echo 0)"

# --- Build the marker line. Allowlist ONLY. ---------------------------------
# We assemble JSON by hand from scalar, shell-escaped values so no content field
# can ever be smuggled in. RUN_ID is emitted only if it is a plausible id
# (letters/digits/-/_); anything else is dropped rather than passed through.
esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

RUN_FIELD=""
case "$RUN_ID" in
  ""|*[!A-Za-z0-9._-]*) RUN_FIELD="" ;;              # missing or unexpected shape -> omit
  *) RUN_FIELD="\"runId\":\"$(esc "$RUN_ID")\"," ;;
esac

LINE="{\"v\":1,\"token\":\"$(esc "$TOKEN")\",\"event\":\"$MARKER_EVENT\",\"origin\":\"enrichment\",${RUN_FIELD}\"agentId\":\"goose\",\"status\":\"$STATUS\",\"phase\":\"$PHASE\",\"ts\":$TS}"

# --- Send it, best-effort, with a hard timeout. -----------------------------
# One short-lived connection, <=1s, then we exit whether or not it succeeded.
send() {
  if command -v socat >/dev/null 2>&1; then
    printf '%s\n' "$LINE" | socat -t1 - "UNIX-CONNECT:$SOCK" >/dev/null 2>&1
  elif command -v nc >/dev/null 2>&1; then
    printf '%s\n' "$LINE" | nc -U -w1 "$SOCK" >/dev/null 2>&1
  elif command -v python3 >/dev/null 2>&1; then
    RANA_LINE="$LINE" RANA_SOCK="$SOCK" python3 - <<'PY' >/dev/null 2>&1
import os, socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect(os.environ["RANA_SOCK"])
    s.sendall((os.environ["RANA_LINE"] + "\n").encode())
finally:
    try: s.close()
    except Exception: pass
PY
  elif command -v node >/dev/null 2>&1; then
    RANA_LINE="$LINE" RANA_SOCK="$SOCK" node -e '
const net=require("net");
const s=net.createConnection(process.env.RANA_SOCK);
s.setTimeout(1000,()=>s.destroy());
s.on("error",()=>s.destroy());
s.on("connect",()=>s.write(process.env.RANA_LINE+"\n",()=>s.end()));
' >/dev/null 2>&1
  fi
  return 0
}

# Never let a wedged sender hold up a hook slot: background + short guard.
( send ) &
SEND_PID=$!
( sleep 2; kill "$SEND_PID" >/dev/null 2>&1 ) &
wait "$SEND_PID" 2>/dev/null

exit 0
