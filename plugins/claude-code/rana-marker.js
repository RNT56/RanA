#!/usr/bin/env node
/**
 * rana-marker.js — RanA marker bridge for Claude Code
 * ------------------------------------------------------------------
 * Emits run-lifecycle MARKERS to the local RanA marker socket so the RanA
 * timeline can cluster "session started -> these execs -> these egress
 * connects -> this file changed" (causality) instead of a raw undifferentiated
 * event river.
 *
 * HOW CLAUDE CODE DRIVES IT:
 *   This is a Claude Code *hook* command (settings.json `hooks`). Claude Code
 *   runs it as a short-lived subprocess on each lifecycle event and passes the
 *   event JSON on stdin. We do NOT stay resident; we read one JSON object, emit
 *   at most one marker, and exit. See README.md for the exact settings.json
 *   snippet. Hook mechanism: https://code.claude.com/docs/en/hooks
 *
 *   Lifecycle mapping (kept to session granularity so a "run" is one session):
 *     SessionStart            -> run.start  { status:"accepted" }
 *     SessionEnd (or Stop)    -> run.end    { status:"completed"|"error" }
 *   The event we emit is selected from stdin's `hook_event_name`, so ONE hook
 *   command wired to both events is all that is needed.
 *
 * WHAT THIS SENDS (and the hard rule it enforces):
 *   Identifiers + lifecycle ONLY: { runId, agentId, channel, status, phase, ts }
 *   NEVER message text, prompts, completions, summaries, transcript paths, or
 *   any content. This mirrors RanA principle P7 ("effects, not thoughts") and
 *   P1 (markers are ENRICHMENT — origin=enrichment; a marker can mislabel,
 *   never fabricate a kernel event). The allowlist below is defense-in-depth:
 *   even if a future Claude Code hook payload grows a content field, the
 *   sanitizer strips everything outside the allowlist before it leaves this
 *   process. (Note: we deliberately never read `transcript_path`, `prompt`,
 *   `message`, `session_title`, or `additionalContext` — those can carry
 *   model or user text.)
 *
 * TRANSPORT: newline-delimited JSON over a Unix domain socket whose path +
 * per-session token are provided by RanA via the RANA_MARKER_SOCKET /
 * RANA_MARKER_TOKEN environment variables. If RANA_MARKER_SOCKET is absent or
 * empty, this script is completely inert (no socket, no error, clean exit) —
 * RanA simply isn't present and Claude Code is unaffected (P2).
 *
 * LICENSE: Apache-2.0 (same as RanA).
 */

'use strict';

const net = require('node:net');

// ---- The allowlist. Only these keys may ever leave this process. -----------
const ALLOWED_FIELDS = ['runId', 'agentId', 'channel', 'status', 'phase', 'ts'];
// Belt and suspenders: keys we explicitly refuse even if someone adds them.
const FORBIDDEN_FIELDS = ['text', 'prompt', 'completion', 'message', 'content', 'summary', 'body'];

const SOCKET_PATH = process.env.RANA_MARKER_SOCKET || null;
const SOCKET_TOKEN = process.env.RANA_MARKER_TOKEN || '';

/** Reduce an arbitrary object to the allowlisted, content-free marker payload. */
function sanitize(obj) {
  const out = {};
  for (const k of ALLOWED_FIELDS) {
    if (obj[k] === undefined || obj[k] === null) continue;
    if (FORBIDDEN_FIELDS.includes(k)) continue; // unreachable given the allowlist, kept as intent
    const v = obj[k];
    // Only primitives survive; no nested objects that could smuggle content.
    if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
      out[k] = v;
    }
  }
  return out;
}

/**
 * Fire-and-forget marker send. Never throws into Claude Code, never blocks the
 * agent (P2: enrichment must not affect the workload). One short-lived
 * connection per marker keeps this stateless and crash-proof.
 */
function sendMarker(event, fields, done) {
  if (!SOCKET_PATH) return done(); // inert when RanA isn't present
  let payload;
  try {
    payload = JSON.stringify({
      v: 1,
      token: SOCKET_TOKEN,
      event: event,               // "run.start" | "run.end" — the listener keys
                                  // the marker.<event> type off the "event"
                                  // field (internal/service/marker.go), NOT "kind".
      origin: 'enrichment',       // P1: never authoritative
      ...sanitize(fields),
    }) + '\n';
  } catch {
    return done(); // if we can't even serialize identifiers, drop silently
  }
  let finished = false;
  const finish = () => { if (!finished) { finished = true; done(); } };
  try {
    const sock = net.createConnection(SOCKET_PATH);
    sock.on('error', () => { sock.destroy(); finish(); }); // RanA down? no-op.
    sock.on('close', finish);
    sock.on('connect', () => {
      sock.write(payload, () => sock.end());
    });
    // Hard timeout so a wedged socket never lingers.
    sock.setTimeout(250, () => { sock.destroy(); finish(); });
  } catch {
    finish(); // swallow — markers are best-effort by design
  }
}

/**
 * Map a Claude Code hook payload to a RanA marker, or to null when the event
 * is not one we translate. Claude Code hook input fields we rely on (all
 * identifiers, never content):
 *   session_id       -> runId   (stable per Claude Code session)
 *   agent_id         -> agentId (present for subagents; omitted otherwise)
 *   hook_event_name  -> selects run.start vs run.end
 *   source           -> SessionStart origin ("startup"|"resume"|...) as `channel`
 *   reason           -> SessionEnd reason, used only to derive status label
 * (see https://code.claude.com/docs/en/hooks)
 */
function toMarker(input) {
  const eventName = input.hook_event_name;
  const runId = input.session_id;
  const agentId = input.agent_id; // undefined for the top-level session

  if (eventName === 'SessionStart') {
    return {
      event: 'run.start',
      fields: {
        runId,
        agentId,
        channel: input.source, // "startup" | "resume" | "clear" | "compact" — a label, not content
        status: 'accepted',
        phase: 'start',
        ts: Date.now(),
      },
    };
  }

  if (eventName === 'SessionEnd' || eventName === 'Stop') {
    // Only "error"-class SessionEnd reasons map to error; everything else is a
    // normal completion. `reason` here is a fixed enum label, never free text.
    const errored = input.reason === 'error';
    return {
      event: 'run.end',
      fields: {
        runId,
        agentId,
        status: errored ? 'error' : 'completed',
        phase: 'end',
        ts: Date.now(),
      },
    };
  }

  return null; // any other hook event is ignored
}

// ---- Entry point: read one JSON object from stdin, emit, exit. -------------
// Best-effort throughout: a parse failure, RanA being down, or no socket all
// end in a clean exit(0) so Claude Code is never disrupted (P2).
function main() {
  // Fast path: if RanA isn't present, don't even read stdin.
  if (!SOCKET_PATH) { process.exit(0); return; }

  let buf = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    buf += chunk;
    if (buf.length > 65536) buf = buf.slice(0, 65536); // never accumulate unboundedly
  });
  process.stdin.on('error', () => process.exit(0));
  process.stdin.on('end', () => {
    let input;
    try {
      input = JSON.parse(buf);
    } catch {
      process.exit(0); return; // not JSON we understand — silently ignore
    }
    if (!input || typeof input !== 'object') { process.exit(0); return; }

    const marker = toMarker(input);
    if (!marker) { process.exit(0); return; }

    sendMarker(marker.event, marker.fields, () => process.exit(0));
  });

  // Absolute backstop: never hang holding up a hook slot.
  setTimeout(() => process.exit(0), 500).unref();
}

main();
