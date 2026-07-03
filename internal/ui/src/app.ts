// app.ts — entry point: session picker, live SSE tail, wiring the canvas
// event river and the run-cluster causality view. No framework (D19).

import { ApiClient } from "./api.js";
import { EventRiver } from "./river.js";
import { buildClusters } from "./causality.js";
import type { RanaEvent, SessionSummary } from "./types.js";

function tokenFromLocation(): string {
  const params = new URLSearchParams(window.location.search);
  const t = params.get("token");
  if (t) return t;
  // Fallback: a page embedding this UI may inject the token as a global
  // (set by the server-rendered index.html) — see index.html.
  const w = window as unknown as { RANA_TOKEN?: string };
  return w.RANA_TOKEN ?? "";
}

class App {
  private api: ApiClient;
  private river: EventRiver;
  private picker: HTMLSelectElement;
  private tooltip: HTMLDivElement;
  private detail: HTMLDivElement;
  private clustersEl: HTMLDivElement;
  private statusEl: HTMLDivElement;
  private currentSession = "";
  private events: RanaEvent[] = [];
  private eventSource: EventSource | null = null;
  private maxIdxSeen = 0;

  constructor() {
    const token = tokenFromLocation();
    this.api = new ApiClient(token);

    const canvas = document.getElementById("river") as HTMLCanvasElement;
    this.river = new EventRiver(canvas, {
      onHover: (ev, x, y) => this.showTooltip(ev, x, y),
      onSelect: (ev) => this.showDetail(ev),
    });

    this.picker = document.getElementById("session-picker") as HTMLSelectElement;
    this.tooltip = document.getElementById("tooltip") as HTMLDivElement;
    this.detail = document.getElementById("detail") as HTMLDivElement;
    this.clustersEl = document.getElementById("clusters") as HTMLDivElement;
    this.statusEl = document.getElementById("status") as HTMLDivElement;

    this.picker.addEventListener("change", () => {
      void this.selectSession(this.picker.value);
    });

    window.addEventListener("resize", () => this.resizeCanvas());
    this.resizeCanvas();
  }

  private resizeCanvas(): void {
    const canvas = document.getElementById("river") as HTMLCanvasElement;
    const wrap = canvas.parentElement!;
    this.river.resize(wrap.clientWidth, 260);
  }

  async start(): Promise<void> {
    try {
      const sessions = await this.api.sessions();
      this.populatePicker(sessions);
      if (sessions.length > 0) {
        await this.selectSession(sessions[0].id);
      } else {
        this.setStatus("No sessions recorded yet.");
      }
    } catch (err) {
      this.setStatus(`Failed to load sessions: ${(err as Error).message}`);
    }
  }

  private populatePicker(sessions: SessionSummary[]): void {
    this.picker.innerHTML = "";
    for (const s of sessions) {
      const opt = document.createElement("option");
      opt.value = s.id;
      const state = s.ended_ns ? "ended" : "live";
      opt.textContent = `${s.id} — ${s.profile} (${state})`;
      this.picker.appendChild(opt);
    }
  }

  private async selectSession(sessionID: string): Promise<void> {
    this.currentSession = sessionID;
    this.maxIdxSeen = 0;
    this.stopStream();
    this.setStatus(`Loading ${sessionID}…`);

    try {
      const events = await this.api.events(sessionID, 0);
      this.events = events;
      for (const ev of events) if (ev.idx > this.maxIdxSeen) this.maxIdxSeen = ev.idx;
      this.river.setEvents(this.events);
      this.renderClusters();
      this.setStatus(`${events.length} events`);
    } catch (err) {
      this.setStatus(`Failed to load events: ${(err as Error).message}`);
    }

    this.startStream(sessionID);
  }

  private startStream(sessionID: string): void {
    const es = new EventSource(this.api.streamURL(sessionID));
    es.onmessage = (msg) => {
      try {
        const ev = JSON.parse(msg.data) as RanaEvent;
        if (ev.idx <= this.maxIdxSeen && this.events.length > 0) return;
        this.maxIdxSeen = Math.max(this.maxIdxSeen, ev.idx);
        this.events.push(ev);
        this.river.addEvent(ev);
        this.renderClusters();
      } catch {
        // malformed frame — ignore, never crash the tail
      }
    };
    es.onerror = () => {
      this.setStatus("Live tail disconnected — retrying…");
    };
    this.eventSource = es;
  }

  private stopStream(): void {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
  }

  private renderClusters(): void {
    const clusters = buildClusters(this.events);
    this.clustersEl.innerHTML = "";
    if (clusters.length === 0) {
      this.clustersEl.textContent = "No marker-labeled runs in this session yet.";
      return;
    }
    for (const c of clusters) {
      const div = document.createElement("div");
      div.className = "cluster";
      div.innerHTML = `<strong>${escapeHtml(c.label)}</strong> — ${c.events.length} events`;
      this.clustersEl.appendChild(div);
    }
  }

  private showTooltip(ev: RanaEvent | null, x: number, y: number): void {
    if (!ev) {
      this.tooltip.style.display = "none";
      return;
    }
    this.tooltip.style.display = "block";
    this.tooltip.style.left = x + 12 + "px";
    this.tooltip.style.top = y + 12 + "px";
    this.tooltip.textContent = `${ev.type} @ pid ${ev.pid}`;
  }

  private showDetail(ev: RanaEvent): void {
    this.detail.textContent = JSON.stringify(ev, null, 2);
  }

  private setStatus(msg: string): void {
    this.statusEl.textContent = msg;
  }
}

function escapeHtml(s: string): string {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

window.addEventListener("DOMContentLoaded", () => {
  const app = new App();
  void app.start();
});
