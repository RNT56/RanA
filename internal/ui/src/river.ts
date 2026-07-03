// river.ts — the canvas "event river": three horizontal lanes
// (process tree / filesystem / network) plotted against a shared time
// x-axis, with sensitive-read and new-domain markers rendered as
// eye-catching "pop" glyphs (plan D19 / CONTRACTS §internal/ui).
//
// No framework, no dependency beyond the Canvas2D API.

import { type RanaEvent, laneFor, isSensitive, isGap } from "./types.js";

const LANES: { key: string; label: string; color: string }[] = [
  { key: "process", label: "Process", color: "#7aa2f7" },
  { key: "filesystem", label: "Filesystem", color: "#9ece6a" },
  { key: "network", label: "Network", color: "#e0af68" },
];

const LANE_HEIGHT = 70;
const TOP_MARGIN = 28;
const LEFT_MARGIN = 90;

export interface RiverOptions {
  onHover?: (ev: RanaEvent | null, x: number, y: number) => void;
  onSelect?: (ev: RanaEvent) => void;
}

export class EventRiver {
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D;
  private events: RanaEvent[] = [];
  private minTs = 0;
  private maxTs = 1;
  private dpr = window.devicePixelRatio || 1;
  private opts: RiverOptions;
  private hitboxes: { x: number; y: number; r: number; ev: RanaEvent }[] = [];

  constructor(canvas: HTMLCanvasElement, opts: RiverOptions = {}) {
    this.canvas = canvas;
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("2d context unavailable");
    this.ctx = ctx;
    this.opts = opts;

    canvas.addEventListener("mousemove", (e) => this.handleMouseMove(e));
    canvas.addEventListener("mouseleave", () => this.opts.onHover?.(null, 0, 0));
    canvas.addEventListener("click", (e) => this.handleClick(e));
  }

  setEvents(events: RanaEvent[]): void {
    this.events = events;
    if (events.length === 0) {
      this.minTs = 0;
      this.maxTs = 1;
    } else {
      let lo = Infinity;
      let hi = -Infinity;
      for (const ev of events) {
        if (ev.ts_wall < lo) lo = ev.ts_wall;
        if (ev.ts_wall > hi) hi = ev.ts_wall;
      }
      this.minTs = lo;
      this.maxTs = hi > lo ? hi : lo + 1;
    }
    this.render();
  }

  addEvent(ev: RanaEvent): void {
    this.events.push(ev);
    if (ev.ts_wall > this.maxTs) this.maxTs = ev.ts_wall;
    if (ev.ts_wall < this.minTs || this.events.length === 1) this.minTs = ev.ts_wall;
    this.render();
  }

  resize(width: number, height: number): void {
    this.dpr = window.devicePixelRatio || 1;
    this.canvas.width = Math.floor(width * this.dpr);
    this.canvas.height = Math.floor(height * this.dpr);
    this.canvas.style.width = width + "px";
    this.canvas.style.height = height + "px";
    this.ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    this.render();
  }

  private xForTs(ts: number, width: number): number {
    const span = this.maxTs - this.minTs || 1;
    const usable = width - LEFT_MARGIN - 20;
    return LEFT_MARGIN + ((ts - this.minTs) / span) * usable;
  }

  render(): void {
    const width = this.canvas.width / this.dpr;
    const height = this.canvas.height / this.dpr;
    const ctx = this.ctx;
    ctx.clearRect(0, 0, width, height);
    this.hitboxes = [];

    // lane backgrounds + labels
    LANES.forEach((lane, i) => {
      const y = TOP_MARGIN + i * LANE_HEIGHT;
      ctx.fillStyle = i % 2 === 0 ? "rgba(255,255,255,0.02)" : "rgba(255,255,255,0.00)";
      ctx.fillRect(0, y, width, LANE_HEIGHT);
      ctx.strokeStyle = "rgba(255,255,255,0.08)";
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();

      ctx.fillStyle = "#c0caf5";
      ctx.font = "12px ui-monospace, monospace";
      ctx.textBaseline = "middle";
      ctx.fillText(lane.label, 10, y + LANE_HEIGHT / 2);
    });

    // time axis ticks
    ctx.strokeStyle = "rgba(255,255,255,0.15)";
    ctx.fillStyle = "#8b93b8";
    ctx.font = "10px ui-monospace, monospace";
    const ticks = 6;
    for (let i = 0; i <= ticks; i++) {
      const ts = this.minTs + ((this.maxTs - this.minTs) * i) / ticks;
      const x = this.xForTs(ts, width);
      ctx.beginPath();
      ctx.moveTo(x, TOP_MARGIN);
      ctx.lineTo(x, TOP_MARGIN + LANES.length * LANE_HEIGHT);
      ctx.stroke();
      const label = formatTs(ts);
      ctx.fillText(label, x - 20, TOP_MARGIN + LANES.length * LANE_HEIGHT + 14);
    }

    // gap bands (P5: losses are loud — render visibly, not silently omitted)
    for (const ev of this.events) {
      if (!isGap(ev)) continue;
      const fromNs = Number(ev.data["from_ns"] ?? ev.ts_wall);
      const toNs = Number(ev.data["to_ns"] ?? ev.ts_wall);
      const x1 = this.xForTs(fromNs, width);
      const x2 = this.xForTs(toNs, width);
      ctx.fillStyle = "rgba(247,118,142,0.18)";
      ctx.fillRect(x1, TOP_MARGIN, Math.max(2, x2 - x1), LANES.length * LANE_HEIGHT);
    }

    // events
    for (const ev of this.events) {
      if (isGap(ev)) continue;
      const laneKey = laneFor(ev);
      const laneIdx = LANES.findIndex((l) => l.key === laneKey);
      if (laneIdx === -1) continue; // "other" lane events (markers) skip the river dots for now
      const lane = LANES[laneIdx];
      const x = this.xForTs(ev.ts_wall, width);
      const y = TOP_MARGIN + laneIdx * LANE_HEIGHT + LANE_HEIGHT / 2;

      const sensitive = isSensitive(ev);
      const r = sensitive ? 7 : 4;

      if (sensitive) {
        // "pop": a halo ring behind the dot
        ctx.beginPath();
        ctx.arc(x, y, r + 5, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(247,118,142,0.35)";
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = sensitive ? "#f7768e" : lane.color;
      ctx.fill();

      this.hitboxes.push({ x, y, r: r + 4, ev });
    }
  }

  private eventAt(px: number, py: number): RanaEvent | null {
    for (let i = this.hitboxes.length - 1; i >= 0; i--) {
      const h = this.hitboxes[i];
      const dx = px - h.x;
      const dy = py - h.y;
      if (dx * dx + dy * dy <= h.r * h.r) return h.ev;
    }
    return null;
  }

  private handleMouseMove(e: MouseEvent): void {
    const rect = this.canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const ev = this.eventAt(x, y);
    this.opts.onHover?.(ev, e.clientX, e.clientY);
  }

  private handleClick(e: MouseEvent): void {
    const rect = this.canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const ev = this.eventAt(x, y);
    if (ev) this.opts.onSelect?.(ev);
  }
}

function formatTs(ns: number): string {
  const ms = ns / 1e6;
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
