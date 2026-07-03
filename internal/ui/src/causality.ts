// causality.ts — run-cluster causality view: groups events into clusters
// keyed by marker-provided run identifiers (origin=enrichment; markers are
// never authoritative for facts, only for grouping/labeling — P1, P7).
// A "run" cluster is the span between a marker.*.start-shaped event and its
// matching end, or simply all events sharing the same runId marker data.

import type { RanaEvent } from "./types.js";
import { isMarker } from "./types.js";

export interface RunCluster {
  runId: string;
  label: string;
  events: RanaEvent[];
  startNs: number;
  endNs: number;
}

// buildClusters groups a session's events by the "run_id" field carried on
// marker.* events (enrichment-only grouping key, never a fact source), and
// buckets any non-marker events whose ts_wall falls within a cluster's
// [startNs, endNs] span into that cluster for display.
export function buildClusters(events: RanaEvent[]): RunCluster[] {
  const byRun = new Map<string, RunCluster>();

  for (const ev of events) {
    if (!isMarker(ev)) continue;
    const runId = asString(ev.data["run_id"]);
    if (!runId) continue;
    let c = byRun.get(runId);
    if (!c) {
      c = { runId, label: labelFor(ev, runId), events: [], startNs: ev.ts_wall, endNs: ev.ts_wall };
      byRun.set(runId, c);
    }
    c.events.push(ev);
    if (ev.ts_wall < c.startNs) c.startNs = ev.ts_wall;
    if (ev.ts_wall > c.endNs) c.endNs = ev.ts_wall;
  }

  const clusters = Array.from(byRun.values());
  clusters.sort((a, b) => a.startNs - b.startNs);

  // Fold in non-marker (kernel-truth) events whose timestamp falls inside a
  // cluster's observed span, so the causality view shows what the run
  // actually *did*, not just the markers it emitted (P1: markers enrich,
  // they never replace the kernel-truth events).
  for (const ev of events) {
    if (isMarker(ev)) continue;
    for (const c of clusters) {
      if (ev.ts_wall >= c.startNs && ev.ts_wall <= c.endNs) {
        c.events.push(ev);
      }
    }
  }
  for (const c of clusters) {
    c.events.sort((a, b) => a.idx - b.idx);
  }

  return clusters;
}

function asString(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function labelFor(ev: RanaEvent, runId: string): string {
  const name = asString(ev.data["name"]);
  return name ? `${name} (${runId})` : runId;
}
