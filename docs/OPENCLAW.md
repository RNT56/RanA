# OpenClaw — Adopt Flow & Causality

OpenClaw is RanA's hero profile. The whole pitch is one line:

```
rana adopt openclaw
```

This document explains what that line does, why it works, and how the timeline turns a raw event stream into *"a message arrived → here's everything that happened because of it."* The marketing says the line; this says the truth behind it.

---

## Why OpenClaw is the ideal case

OpenClaw is a single long-lived **Gateway** daemon (one per host, `openclaw gateway`, launchd/systemd-supervised, default bind `127.0.0.1:18789`, config under `~/.openclaw/`). It owns every messaging surface and **fans out**: multi-agent routing, delegate architecture, parallel specialist lanes, tool processes, MCP servers — all descend from the gateway.

That fan-out is exactly what makes RanA's attribution model shine. **One cgroup leaf per session** captures the gateway *and every descendant* by kernel inheritance. RanA doesn't need to understand OpenClaw's internals to follow a sub-agent three hops deep spawning a shell that hits the network — it's all in the slice. OpenClaw's own architecture does RanA's attribution work.

And OpenClaw is the case that *matters*: the CIK safety evaluation (arXiv 2604.04759) documents that it runs with full local access to Gmail, Stripe, and the filesystem. "The safest way to run OpenClaw is with a recorder watching" is a real sentence.

## What `rana adopt openclaw` does

1. **Detect** an existing install: `~/.openclaw/` present, a gateway listening on `:18789`.
2. **Slot it into a session** (with your confirmation):
   - **Linux:** write a systemd drop-in placing the gateway unit under `rana.slice/rana-openclaw.scope`, then restart. From that moment, the gateway and all its children are one attributed RanA session.
   - **macOS:** host the gateway **inside the RanA guest VM** — the only recording path on macOS (a native macOS process produces *zero* kernel events; there is no degraded native mode, and RanA won't pretend there is — `LIMITS.md §5`). Adopt installs the Linux build of the gateway onto the guest's persistent data volume (first adopt runs a guest-side `npm install`; host `node_modules` are Mach-O and can't be reused), projects your `~/.openclaw` config and workspace via virtiofs, and port-forwards `:18789` back to host localhost so everything that talked to your gateway still does. Decline, and adopt exits with exactly that explanation.
3. **Optionally install the marker plugin** (`plugins/openclaw/rana-plugin.js`, ~100 LOC) and set `RANA_MARKER_SOCKET` + `RANA_MARKER_TOKEN` on the gateway unit. Consent is prompted; default yes; entirely optional.
4. **Open the timeline** — live, causality lens.

Nothing here touches message content. Adoption is about *process placement* and *lifecycle identifiers*, never what was said.

## Causality: how "conversation → consequences" is built

OpenClaw's agent run has a real, observable lifecycle over its WebSocket API:

```
req:agent  ─▶  res:agent ack   { runId, status: "accepted" }     ── run starts
event:agent (streaming tokens…)                                  ── (content — RanA ignores this)
res:agent final               { runId, status, summary }         ── run ends
```

The marker plugin hooks the **accepted** and **final** transitions and forwards `{ runId, agentId, channel, status }` — and nothing else — to RanA's marker socket. RanA then **clusters kernel events by `runId`**: every exec, file write, and egress connect that happened between a run's start and end marker becomes the *consequences* of that run.

The result in the timeline:

```
▸ run  a9f2  (channel: telegram, agent: default)      [accepted 21:03:12 → ok 21:03:19]
    exec   /bin/sh -lc "…"                              21:03:13
    net    api.stripe.com:443                           21:03:14
    read   ~/.openclaw/credentials.json   ⚠ sensitive   21:03:14
    write  ~/.openclaw/workspace/report.md              21:03:17
```

You read *down* a run and see what an inbound message caused. You never see the message.

### Without the plugin

Causality falls back to **inferred** clustering: time proximity + process-tree lineage, labeled `inferred` in the UI so you know it's a heuristic, not ground truth. Still useful; just not runId-exact.

## The privacy line, stated plainly (P7 / P1)

- **Carried:** `runId`, `agentId`, `channel`, `status`. Identifiers and lifecycle.
- **Never carried:** message text, prompts, completions, the run `summary`, or any content. The plugin enforces this with an allowlist *and* a forbidden-field list; the profile (`profiles/openclaw.toml`) declares `forbid_fields`; and RanA treats every marker as `origin=enrichment` — a forged or malformed marker can mislabel a cluster, but can never fabricate a kernel event or inject content into the ledger.

RanA records what OpenClaw *did to your machine*. It has no interest in, and no access path to, what OpenClaw *said*.

## The one-line promise, and why it holds

> *Already running OpenClaw? `rana adopt openclaw`. Open the timeline. That's it.*

It holds because: cgroup inheritance captures the fan-out for free; the systemd drop-in is a mechanical, reversible placement; the marker plugin is optional and inert if declined; and the causality lens needs only identifiers OpenClaw already emits. Everything hard is done by the kernel and by OpenClaw's own structure — RanA just watches and remembers.
