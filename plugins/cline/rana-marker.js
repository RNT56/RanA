#!/usr/bin/env node
/**
 * rana-marker.js — RanA marker bridge for Cline
 * ------------------------------------------------------------------
 * Emits run-lifecycle MARKERS to the local RanA marker socket so the RanA
 * timeline can cluster "task started -> these execs -> these egress connects
 * -> this file changed" (causality) instead of a raw undifferentiated event
 * river.
 *
 * HOW CLINE DRIVES IT:
 *   Cline's hook system (cline.bot, v3.36+) discovers hooks as EXECUTABLE FILES
 *   NAMED EXACTLY AFTER each lifecycle event (`TaskStart`, `TaskComplete`,
 *   `TaskCancel`, ...) placed in a hooks directory, and runs the matching file
 *   as a short-lived subprocess on that event, passing a `HookInput` JSON on
 *   stdin. This file is the shared IMPLEMENTATION; the three thin wrappers in
 *   this folder (TaskStart / TaskComplete / TaskCancel) just `exec` it, so all
 *   the logic + the P7 allowlist live in one reviewed place. We do NOT stay
 *   resident: read one JSON object, emit at most one marker, exit.
 *   Hook mechanism: https://docs.cline.bot/features/hooks
 *
 *   Lifecycle mapping (a "run" == one Cline task):
 *     TaskStart     -> run.start  { status:"accepted" }
 *     TaskComplete  -> run.end    { status:"completed" }   (after attempt_completion)
 *     TaskCancel    -> run.end    { status:"cancelled" }
 *   The event is taken from stdin's `hookName` (falling back to argv[2] passed
 *   by the wrapper), so this one implementation covers all three.
 *   Content-bearing hooks (UserPromptSubmit, PreToolUse, PostToolUse) are
 *   deliberately NOT wired — they carry prompt/tool text we must never touch.
 *
 * WHAT THIS SENDS (and the hard rule it enforces):
 *   Identifiers + lifecycle ONLY: { runId, agentId, channel, status, phase, ts }
 *   NEVER message text, prompts, completions, summaries, workspace paths, or any
 *   content. This mirrors RanA principle P7 ("effects, not thoughts") and P1
 *   (markers are ENRICHMENT — origin=enrichment; a marker can mislabel, never
 *   fabricate a kernel event). The allowlist below is defense-in-depth: even if
 *   a future Cline HookInput grows a content field, the sanitizer strips
 *   everything outside the allowlist before a byte leaves this process. (Note:
 *   we deliberately never read `task`, `description`, `prompt`, `workspaceRoots`,
 *   or any tool params — those can carry model/user text or path content.)
 *
 * TRANSPORT: newline-delimited JSON over a Unix domain socket whose path +
 * per-session token are provided by RanA via the RANA_MARKER_SOCKET /
 * RANA_MARKER_TOKEN environment variables. If RANA_MARKER_SOCKET is absent or
 * empty, this script is completely inert (no socket, no error, clean exit) —
 * RanA simply isn't present and Cline is unaffected (P2).
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
 * Fire-and-forget marker send. Never throws into Cline, never blocks the agent
 * (P2: enrichment must not affect the workload). One short-lived connection per
 * marker keeps this stateless and crash-proof.
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
 * Map a Cline HookInput payload to a RanA marker, or to null when the event is
 * not one we translate. Cline HookInput fields we rely on (all identifiers,
 * never content; see https://docs.cline.bot/features/hooks):
 *   taskId    -> runId   (stable per Cline task)
 *   hookName  -> selects run.start vs run.end and the status label
 * We take the event name from the payload's `hookName`, and fall back to
 * argv[2] (the name the wrapper passes) if the payload omits it.
 * We deliberately read NOTHING else — not `task`, `description`,
 * `workspaceRoots`, tool params, or results.
 */
function toMarker(input, argvEvent) {
  const eventName = (input && input.hookName) || argvEvent;
  const runId = input && input.taskId;

  if (eventName === 'TaskStart' || eventName === 'TaskResume') {
    return {
      event: 'run.start',
      fields: {
        runId,
        agentId: 'cline',
        channel: 'cli',       // fixed label; Cline runs as CLI/hub or the VS Code extension host
        status: 'accepted',
        phase: 'start',
        ts: Date.now(),
      },
    };
  }

  if (eventName === 'TaskComplete') {
    return {
      event: 'run.end',
      fields: { runId, agentId: 'cline', status: 'completed', phase: 'end', ts: Date.now() },
    };
  }

  if (eventName === 'TaskCancel') {
    return {
      event: 'run.end',
      fields: { runId, agentId: 'cline', status: 'cancelled', phase: 'end', ts: Date.now() },
    };
  }

  return null; // any other hook event (UserPromptSubmit, Pre/PostToolUse, ...) is ignored
}

// ---- Entry point: read one JSON object from stdin, emit, exit. -------------
// Best-effort throughout: a parse failure, RanA being down, or no socket all
// end in a clean exit(0) so Cline is never disrupted (P2). We ALWAYS exit 0 and
// print nothing on stdout so Cline treats the hook as a no-op "allow".
function main() {
  const argvEvent = process.argv[2]; // wrapper passes the event name as argv[2]

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
    let input = {};
    try {
      if (buf.trim()) input = JSON.parse(buf);
    } catch {
      input = {}; // not JSON — fall back to the argv event name below
    }
    if (!input || typeof input !== 'object') input = {};

    const marker = toMarker(input, argvEvent);
    if (!marker) { process.exit(0); return; }

    sendMarker(marker.event, marker.fields, () => process.exit(0));
  });

  // Absolute backstop: never hang holding up a hook slot.
  setTimeout(() => process.exit(0), 500).unref();
}

main();
