// Thin fetch wrapper for the localhost-only, bearer-token-gated API
// (internal/ui/handler.go). The token travels as a query param for the
// SSE endpoint (EventSource cannot set custom headers) and as an
// Authorization header everywhere else.

import type { RanaEvent, SessionSummary } from "./types.js";

export class ApiClient {
  private token: string;

  constructor(token: string) {
    this.token = token;
  }

  private async getJSON<T>(path: string): Promise<T> {
    const res = await fetch(path, {
      headers: { Authorization: "Bearer " + this.token },
    });
    if (!res.ok) {
      throw new Error(`${path}: ${res.status} ${res.statusText}`);
    }
    return (await res.json()) as T;
  }

  sessions(): Promise<SessionSummary[]> {
    return this.getJSON<SessionSummary[]>("/api/sessions");
  }

  events(session: string, after: number, limit?: number): Promise<RanaEvent[]> {
    let path = `/api/events?session=${encodeURIComponent(session)}&after=${after}`;
    if (limit) path += `&limit=${limit}`;
    return this.getJSON<RanaEvent[]>(path);
  }

  alerts(session: string): Promise<RanaEvent[]> {
    return this.getJSON<RanaEvent[]>(`/api/alerts?session=${encodeURIComponent(session)}`);
  }

  // streamURL builds the SSE URL for a given session; the token rides on
  // the query string since EventSource offers no header hook.
  streamURL(session: string): string {
    return `/api/stream?session=${encodeURIComponent(session)}&token=${encodeURIComponent(this.token)}`;
  }
}
