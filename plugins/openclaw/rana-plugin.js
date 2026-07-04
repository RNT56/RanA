/**
 * rana-plugin.js — RanA marker bridge for OpenClaw
 * ------------------------------------------------------------------
 * Emits run-lifecycle MARKERS to the local RanA marker socket so the RanA
 * timeline can render "inbound message -> these execs -> these egress connects
 * -> this file changed" (causality), instead of a raw undifferentiated event
 * river.
 *
 * WHAT THIS SENDS (and the hard rule it enforces):
 *   Identifiers + lifecycle ONLY: { runId, agentId, channel, status, phase, ts }
 *   NEVER message text, prompts, completions, summaries, or any content.
 * This mirrors RanA principle P7 ("effects, not thoughts") and P1 (markers are
 * ENRICHMENT — origin=enrichment; a marker can mislabel, never fabricate a
 * kernel event). The redaction below is defense-in-depth: even if a future
 * OpenClaw event shape leaks content into a field we forward, the allowlist
 * strips it before it leaves this process.
 *
 * TRANSPORT: newline-delimited JSON over a Unix domain socket whose path +
 * per-session token are provided by RanA at `rana adopt openclaw` time via the
 * RANA_MARKER_SOCKET / RANA_MARKER_TOKEN environment variables. If they are
 * absent, the plugin is inert (no socket, no error) — RanA simply falls back to
 * inferred causality.
 *
 * INSTALL: drop into OpenClaw's plugin directory (see docs/OPENCLAW.md). RanA's
 * `rana adopt openclaw` offers to do this for you and to set the env vars on the
 * gateway unit. Consent is prompted; default yes; fully optional.
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
 * Fire-and-forget marker send. Never throws into the gateway, never blocks the
 * agent loop (P2: enrichment must not affect the workload). One short-lived
 * connection per marker keeps the plugin stateless and crash-proof.
 */
function sendMarker(kind, fields) {
  if (!SOCKET_PATH) return; // inert when RanA isn't present
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
    return; // if we can't even serialize identifiers, drop silently
  }
  try {
    const sock = net.createConnection(SOCKET_PATH);
    sock.on('error', () => sock.destroy());   // RanA down? no-op.
    sock.on('connect', () => {
      sock.write(payload, () => sock.end());
    });
    // Hard timeout so a wedged socket never lingers.
    sock.setTimeout(250, () => sock.destroy());
  } catch {
    /* swallow — markers are best-effort by design */
  }
}

/**
 * OpenClaw plugin entry point.
 *
 * OpenClaw's agent run lifecycle (see docs.openclaw.ai/concepts/architecture):
 *   req:agent  -> res:agent ack   { runId, status: "accepted" }   => run.start
 *   event:agent (streaming...)                                     (ignored: content)
 *   res:agent final               { runId, status, summary }      => run.end
 *
 * We hook the accepted/final transitions and forward the runId + status. The
 * streaming content frames are deliberately NOT hooked.
 *
 * The exact registration API name may vary by OpenClaw version; adapt the two
 * `on(...)` bindings to the installed gateway's plugin surface. Everything
 * below the bindings is version-independent.
 */
module.exports = function register(api) {
  // Run accepted -> mark the start of a causal cluster.
  api.on('agent:accepted', (ev) => {
    sendMarker('run.start', {
      runId: ev.runId,
      agentId: ev.agentId,
      channel: ev.channel,
      status: 'accepted',
      phase: 'start',
      ts: Date.now(),
    });
  });

  // Run final -> close the cluster. Note we forward `status` (ok/error) but
  // NOT `summary`, which may contain model-authored content.
  api.on('agent:final', (ev) => {
    sendMarker('run.end', {
      runId: ev.runId,
      agentId: ev.agentId,
      channel: ev.channel,
      status: ev.status,   // e.g. "ok" | "error" — a label, not content
      phase: 'end',
      ts: Date.now(),
    });
  });

  return {
    name: 'rana-marker-bridge',
    version: '1.0.0',
    description: 'Emits content-free run-lifecycle markers to RanA for causality.',
  };
};
