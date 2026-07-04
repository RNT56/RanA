/**
 * rana-plugin.ts — RanA marker bridge for OpenCode (opencode.ai, the SST agent/TUI)
 * ------------------------------------------------------------------------------
 * Emits run-lifecycle MARKERS to the local RanA marker socket so the RanA
 * timeline can render "inbound request -> these execs -> these egress connects
 * -> this file changed" (causality), instead of a raw undifferentiated event
 * river.
 *
 * WHAT THIS SENDS (and the hard rule it enforces):
 *   Identifiers + lifecycle ONLY: { runId, agentId, channel, status, phase, ts }
 *   NEVER message text, prompts, completions, summaries, or any model I/O.
 * This mirrors RanA principle P7 ("effects, not thoughts") and P1 (markers are
 * ENRICHMENT — origin=enrichment; a marker can mislabel, never fabricate a
 * kernel event). The allowlist below is defense-in-depth: even if a future
 * OpenCode event shape leaks content into a field we might forward, the
 * allowlist strips it before it leaves this process.
 *
 * TRANSPORT: newline-delimited JSON over a Unix domain socket whose path +
 * per-session token are provided by RanA at adopt/run time via the
 * RANA_MARKER_SOCKET / RANA_MARKER_TOKEN environment variables. If they are
 * absent, the plugin is inert (no socket, no error) — RanA simply falls back to
 * inferred (time + process-tree) causality.
 *
 * INSTALL: drop into OpenCode's plugin directory and register it (see README.md
 * in this folder). OpenCode auto-loads .ts/.js files from:
 *   .opencode/plugin/            (project-level)
 *   ~/.config/opencode/plugin/   (global)
 *
 * LIFECYCLE MAPPING (OpenCode `event` hook — https://opencode.ai/docs/plugins/):
 *   event.type === "session.created" { properties.sessionID }  => run.start
 *   event.type === "session.idle"    { properties.sessionID }  => run.end (completed)
 *   event.type === "session.error"   { properties.sessionID }  => run.end (error)
 * session.idle fires when the agent finishes responding (the run's effects are
 * done); session.error when the run terminates in error. Content-bearing events
 * (message.updated, message.part.updated, tool.execute.*) are deliberately NOT
 * hooked — they carry model I/O we must never touch (P7).
 *
 * LICENSE: Apache-2.0 (same as RanA).
 */

import net from "node:net";

// ---- The allowlist. Only these keys may ever leave this process. -----------
const ALLOWED_FIELDS = ["runId", "agentId", "channel", "status", "phase", "ts"] as const;
// Belt and suspenders: keys we explicitly refuse even if someone adds them.
const FORBIDDEN_FIELDS = ["text", "prompt", "completion", "message", "content", "summary", "body"];

const SOCKET_PATH = process.env.RANA_MARKER_SOCKET || null;
const SOCKET_TOKEN = process.env.RANA_MARKER_TOKEN || "";

type MarkerFields = {
  runId?: string;
  agentId?: string;
  channel?: string;
  status?: string;
  phase?: string;
  ts?: number;
};

/** Reduce an arbitrary object to the allowlisted, content-free marker payload. */
function sanitize(obj: Record<string, unknown>): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  for (const k of ALLOWED_FIELDS) {
    const v = obj[k];
    if (v === undefined || v === null) continue;
    if (FORBIDDEN_FIELDS.includes(k)) continue; // unreachable given the allowlist, kept as intent
    // Only primitives survive; no nested objects that could smuggle content.
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
      out[k] = v;
    }
  }
  return out;
}

/**
 * Fire-and-forget marker send. Never throws into OpenCode, never blocks the
 * agent loop (P2: enrichment must not affect the workload). One short-lived
 * connection per marker keeps the plugin stateless and crash-proof.
 */
function sendMarker(event: "run.start" | "run.end", fields: MarkerFields): void {
  if (!SOCKET_PATH) return; // inert when RanA isn't present
  let payload: string;
  try {
    payload =
      JSON.stringify({
        v: 1,
        token: SOCKET_TOKEN,
        event, // "run.start" | "run.end" — the listener keys the marker
        //         type off the "event" field (internal/service/marker.go),
        //         NOT "kind". A marker with no "event" field is rejected.
        origin: "enrichment", // P1: never authoritative
        ...sanitize(fields as Record<string, unknown>),
      }) + "\n";
  } catch {
    return; // if we can't even serialize identifiers, drop silently
  }
  try {
    const sock = net.createConnection(SOCKET_PATH);
    sock.on("error", () => sock.destroy()); // RanA down? no-op.
    sock.on("connect", () => {
      sock.write(payload, () => sock.end());
    });
    // Hard timeout so a wedged socket never lingers.
    sock.setTimeout(250, () => sock.destroy());
  } catch {
    /* swallow — markers are best-effort by design */
  }
}

/** Pull the session id out of an OpenCode event payload, tolerating shape drift. */
function sessionIdOf(properties: Record<string, unknown> | undefined): string | undefined {
  if (!properties) return undefined;
  const cand =
    (properties as any).sessionID ??
    (properties as any).sessionId ??
    (properties as any).session_id ??
    ((properties as any).info && (properties as any).info.id);
  return typeof cand === "string" ? cand : undefined;
}

/**
 * OpenCode plugin entry point.
 *
 * The `Plugin` type comes from "@opencode-ai/plugin"; we avoid importing it so
 * this file works whether loaded as .ts or transpiled .js without the dev dep.
 * The single `event` hook receives { event: { type, properties } }.
 */
export const RanaMarkerBridge = async () => {
  return {
    event: async ({ event }: { event: { type: string; properties?: Record<string, unknown> } }) => {
      // Inert fast-path: do nothing (not even inspect) when RanA isn't present.
      if (!SOCKET_PATH) return;

      const runId = sessionIdOf(event.properties);
      const ts = Date.now();

      switch (event.type) {
        // A session begins handling work -> open a causal cluster.
        case "session.created":
          sendMarker("run.start", { runId, status: "accepted", phase: "start", ts });
          break;

        // Agent finished responding for this turn -> close the cluster (ok).
        case "session.idle":
          sendMarker("run.end", { runId, status: "completed", phase: "end", ts });
          break;

        // Run terminated in error -> close the cluster (error). We forward the
        // "error" LABEL only, never the error text/content.
        case "session.error":
          sendMarker("run.end", { runId, status: "error", phase: "end", ts });
          break;

        // All other events (message.*, tool.execute.*, permission.*, etc.) carry
        // model I/O or are irrelevant — deliberately NOT forwarded (P7).
        default:
          break;
      }
    },
  };
};

export default RanaMarkerBridge;
