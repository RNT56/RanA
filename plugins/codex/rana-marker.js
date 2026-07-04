#!/usr/bin/env node
/**
 * rana-marker.js — RanA marker bridge for OpenAI Codex CLI
 * ------------------------------------------------------------------
 * Emits run-lifecycle MARKERS to the local RanA marker socket so the RanA
 * timeline can cluster "session started -> these execs -> these egress
 * connects -> this file changed" (causality) instead of a raw undifferentiated
 * event river.
 *
 * HOW CODEX INVOKES THIS:
 *   Codex's lifecycle-hook facility (~/.codex/config.toml, `[[hooks.*]]`) runs
 *   a `type = "command"` hook for each lifecycle event and passes the event as
 *   a single JSON object on STDIN. See:
 *     https://developers.openai.com/codex/hooks
 *   The shared stdin fields are:
 *     session_id, transcript_path, cwd, hook_event_name, model, permission_mode
 *   SessionStart adds `source` (startup|resume|clear|compact); Stop adds
 *   `stop_hook_active` and `last_assistant_message`.
 *   We map:  SessionStart -> run.start    Stop -> run.end
 *   The event name is taken from `hook_event_name` (or argv[2] as a fallback,
 *   see the README's registration snippet) — never from message content.
 *
 * WHAT THIS SENDS (and the hard rule it enforces):
 *   Identifiers + lifecycle ONLY: { runId, agentId, channel, status, phase, ts }
 *   NEVER message text, prompts, completions, summaries, or any content.
 * This mirrors RanA principle P7 ("effects, not thoughts") and P1 (markers are
 * ENRICHMENT — origin=enrichment; a marker can mislabel, never fabricate a
 * kernel event). Codex's stdin payload DOES include model-authored content
 * (`last_assistant_message`, `transcript_path`); the allowlist below is the
 * wall — those fields are read into a variable we never forward. Only
 * `session_id` (an identifier) and a derived status label ever leave here.
 *
 * TRANSPORT: newline-delimited JSON over a Unix domain socket whose path +
 * per-session token are provided by RanA via the RANA_MARKER_SOCKET /
 * RANA_MARKER_TOKEN environment variables. If RANA_MARKER_SOCKET is absent or
 * empty, this script is completely inert (no socket, no error, exit 0) — RanA
 * simply isn't present and Codex runs untouched.
 *
 * BEST-EFFORT / CRASH-PROOF (P2: enrichment must not affect the workload):
 *   Any failure — RanA down, bad stdin, serialize error, wedged socket — is
 *   swallowed silently and the process still exits 0 so Codex never sees a hook
 *   failure. A 250ms socket timeout guarantees a stuck socket never lingers.
 *
 * INSTALL: see plugins/codex/README.md for the exact `~/.codex/config.toml`
 * `[[hooks.SessionStart]]` / `[[hooks.Stop]]` registration snippet.
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
 * Fire-and-forget marker send. Never throws, never blocks Codex's turn (P2).
 * One short-lived connection per marker keeps this stateless and crash-proof.
 * Calls `done` exactly once when the socket is finished with (success or fail),
 * so the caller can exit cleanly instead of hanging on an open handle.
 */
function sendMarker(kind, fields, done) {
  if (!SOCKET_PATH) return done(); // inert when RanA isn't present
  let payload;
  try {
    payload = JSON.stringify({
      v: 1,
      token: SOCKET_TOKEN,
      event: kind,                // "run.start" | "run.end" — the listener keys
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
    sock.on('error', () => { sock.destroy(); finish(); });   // RanA down? no-op.
    sock.on('close', finish);
    sock.on('connect', () => {
      sock.write(payload, () => sock.end());
    });
    // Hard timeout so a wedged socket never lingers.
    sock.setTimeout(250, () => sock.destroy());
  } catch {
    finish(); // swallow — markers are best-effort by design
  }
}

/**
 * Read the Codex hook JSON payload from stdin (best-effort), returning {} on any
 * problem. We never let a malformed payload throw — Codex must not see a hook
 * failure because RanA had a bad byte.
 */
function readStdin() {
  return new Promise((resolve) => {
    let buf = '';
    let settled = false;
    const settle = (obj) => { if (!settled) { settled = true; resolve(obj); } };
    try {
      if (process.stdin.isTTY) return settle({}); // invoked without a payload
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', (c) => { buf += c; });
      process.stdin.on('end', () => {
        try { settle(buf.trim() ? JSON.parse(buf) : {}); }
        catch { settle({}); }
      });
      process.stdin.on('error', () => settle({}));
      // Never wait forever for stdin.
      setTimeout(() => settle({}), 250);
    } catch {
      settle({});
    }
  });
}

/**
 * Map a Codex hook event to a RanA marker. The event name comes from the
 * payload's `hook_event_name`, falling back to argv[2] (the README registers
 * the hook with the event name as an explicit argument so this works even if a
 * Codex build omits it from stdin). Content fields on the payload
 * (last_assistant_message, transcript_path, model, ...) are deliberately NOT
 * forwarded — only session_id (an identifier) and a fixed status label.
 */
async function main() {
  const payload = await readStdin();
  const eventName = String(payload.hook_event_name || process.argv[2] || '').trim();
  const runId = payload.session_id; // Codex's stable per-session identifier

  let kind = null;
  let status = null;
  if (eventName === 'SessionStart') {
    kind = 'run.start';
    status = 'accepted';
  } else if (eventName === 'Stop') {
    kind = 'run.end';
    // Codex's Stop fires at turn completion; there is no error signal in the
    // payload, so we report "completed". A crash never reaches a Stop hook.
    status = 'completed';
  } else {
    // Any other lifecycle event (PreToolUse, PostCompact, ...) is not a run
    // boundary — do nothing. Exit clean so Codex is never blocked.
    return;
  }

  sendMarker(kind, {
    runId,
    agentId: 'codex',
    channel: 'cli',
    status,
    phase: kind === 'run.start' ? 'start' : 'end',
    ts: Date.now(),
  }, () => process.exit(0));
}

// Absolute crash guard: whatever happens, exit 0 so Codex's turn is unaffected.
main().catch(() => process.exit(0));
