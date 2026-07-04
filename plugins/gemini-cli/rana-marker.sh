#!/bin/sh
# rana-marker.sh — RanA marker bridge for Gemini CLI (Google)
# ---------------------------------------------------------------------------
# Emits a single run-lifecycle MARKER to the local RanA marker socket so the
# RanA timeline can render "session start -> these execs -> these egress
# connects -> this file changed" (causality) instead of a raw undifferentiated
# event river.
#
# WHAT THIS SENDS (and the hard rule it enforces):
#   Identifiers + lifecycle ONLY: { runId, agentId, channel, status, phase, ts }
#   NEVER prompts, completions, transcript, GEMINI.md text, or any model I/O.
# This mirrors RanA principle P7 ("effects, not thoughts") and P1 (markers are
# ENRICHMENT — origin=enrichment; a marker can mislabel, never fabricate a
# kernel event). This script parses only the session_id, event name, and the
# source/reason LABEL from the hook payload; it never reads message content and
# never forwards a free-text field.
#
# WIRING: registered as a Gemini CLI command hook for the SessionStart and
# SessionEnd lifecycle events (see README.md). Gemini CLI passes the hook a JSON
# payload on STDIN:
#   SessionStart: { session_id, cwd, hook_event_name, timestamp, source }
#   SessionEnd:   { session_id, cwd, hook_event_name, timestamp, reason }
# We derive run.start from SessionStart and run.end from SessionEnd.
#
# TRANSPORT: one newline-delimited JSON line over the Unix domain socket whose
# path + per-session token RanA provides via RANA_MARKER_SOCKET /
# RANA_MARKER_TOKEN. If RANA_MARKER_SOCKET is absent, this script is INERT (no
# socket, no error, exit 0) — safe to leave wired even when RanA isn't running.
#
# SAFETY: best-effort and crash-proof. It always exits 0 so it can never block
# or fail the agent loop (P2). No dependency beyond a POSIX shell; uses a Unix
# socket writer (python3 -> nc fallback), and no-ops silently if neither exists.
#
# LICENSE: Apache-2.0 (same as RanA).

# --- Inert when RanA isn't present ------------------------------------------
[ -n "$RANA_MARKER_SOCKET" ] || exit 0

# Read the hook payload from stdin (bounded; we only need a few small fields).
payload="$(head -c 65536 2>/dev/null)"

# --- Extract ONLY allowlisted scalar fields from the JSON -------------------
# We never parse or forward free-text/content fields. These greps pull a single
# JSON string value by key without a JSON library, tolerating whitespace.
json_str() {
  # $1 = key. Prints the first "key":"value" string value, or empty.
  printf '%s' "$payload" \
    | tr -d '\n' \
    | grep -o "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
    | head -n1 \
    | sed 's/.*:[[:space:]]*"\([^"]*\)"$/\1/'
}

event_name="$(json_str hook_event_name)"
run_id="$(json_str session_id)"
# `source` (SessionStart) / `reason` (SessionEnd) are short lifecycle LABELS,
# not content — safe to forward as status context.
source_label="$(json_str source)"
reason_label="$(json_str reason)"

# Fall back to the argument if Gemini didn't send hook_event_name (some builds
# pass the event as $1). Never trust anything but a known label.
[ -n "$event_name" ] || event_name="$1"

case "$event_name" in
  SessionStart|session_start|start)
    event="run.start"
    status="${source_label:-accepted}"
    phase="start"
    ;;
  SessionEnd|session_end|end|stop|Stop)
    event="run.end"
    status="${reason_label:-completed}"
    phase="end"
    ;;
  *)
    # Unknown event -> do nothing rather than guess.
    exit 0
    ;;
esac

# Guard the status label to a small alnum set (defense-in-depth: never let an
# unexpected value smuggle characters into the JSON we emit).
status="$(printf '%s' "$status" | tr -cd 'A-Za-z0-9_-' | cut -c1-32)"
[ -n "$status" ] || status="unknown"

ts="$(date +%s000 2>/dev/null)"
token="${RANA_MARKER_TOKEN:-}"

# --- Build the marker line (identifiers + lifecycle ONLY) -------------------
# Note: run_id is a session UUID; if it contained a quote it would break JSON,
# so we strip to the UUID-safe charset. No content field is ever included.
run_id="$(printf '%s' "$run_id" | tr -cd 'A-Za-z0-9_.:-' | cut -c1-128)"

line="{\"v\":1,\"token\":\"$token\",\"event\":\"$event\",\"origin\":\"enrichment\",\"runId\":\"$run_id\",\"agentId\":\"gemini-cli\",\"channel\":\"cli\",\"status\":\"$status\",\"phase\":\"$phase\",\"ts\":$ts}"

# --- Send it, best-effort, short timeout, one connection --------------------
send() {
  # Prefer python3 (present on most dev machines) for a clean AF_UNIX write.
  if command -v python3 >/dev/null 2>&1; then
    RANA_LINE="$line" python3 - "$RANA_MARKER_SOCKET" <<'PY' 2>/dev/null
import os, socket, sys
path = sys.argv[1]
data = (os.environ.get("RANA_LINE", "") + "\n").encode("utf-8")
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(0.25)
try:
    s.connect(path)
    s.sendall(data)
finally:
    try:
        s.close()
    except Exception:
        pass
PY
    return 0
  fi
  # Fallback: OpenBSD/nmap netcat with -U (Unix socket) if available.
  if command -v nc >/dev/null 2>&1; then
    printf '%s\n' "$line" | nc -U -w1 "$RANA_MARKER_SOCKET" >/dev/null 2>&1
    return 0
  fi
  return 0
}

send

# Always succeed — a marker must never break or delay the agent (P2).
exit 0
