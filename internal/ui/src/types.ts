// Shared types mirroring internal/schema.Event and the SessionSummary the
// Go handler serializes as JSON (see internal/ui/handler.go). Keep field
// names in sync with the Go json tags.

export interface SessionSummary {
  id: string;
  profile: string;
  started_ns: number;
  ended_ns: number;
}

export interface RanaEvent {
  v: number;
  type: string;
  session: string;
  seg: number;
  idx: number;
  ts_mono: number;
  ts_wall: number;
  pid: number;
  origin: string;
  state: string;
  data: Record<string, unknown>;
}

// Lane classifies an event type into one of the three event-river lanes.
export type Lane = "process" | "filesystem" | "network" | "other";

export function laneFor(ev: RanaEvent): Lane {
  if (ev.type.startsWith("proc.") || ev.type === "session.start" || ev.type === "session.end") {
    return "process";
  }
  if (ev.type.startsWith("fs.")) return "filesystem";
  if (ev.type.startsWith("net.") || ev.type === "unix.connect") return "network";
  return "other";
}

// isSensitive reports whether an event should render as a "pops" marker on
// its lane: sensitive-reads and first-contact-domain alerts (plan D19).
export function isSensitive(ev: RanaEvent): boolean {
  return (
    ev.type === "fs.sensitive_read" ||
    ev.type === "alert.sensitive_read" ||
    ev.type === "alert.new_domain" ||
    ev.type === "alert.cgroup_escape" ||
    ev.type === "alert.escape_precursor"
  );
}

export function isMarker(ev: RanaEvent): boolean {
  return ev.type.startsWith("marker.");
}

export function isGap(ev: RanaEvent): boolean {
  return ev.type === "gap";
}
