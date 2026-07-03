# RanA — Record an Agent

**The flight recorder for AI agents.** A kernel-truth, tamper-evident ledger of everything your agents *execute, touch, and contact* — across every agent on your machine, with zero configuration.

> *Chain of custody for AI agents.*

```
Already running OpenClaw?

    curl -fsSL https://get.rana.dev | sh
    rana adopt openclaw

Open the timeline. That's it.
```

**Before you trust it, read [`LIMITS.md`](./LIMITS.md).** RanA is an *observation* tool, not a wall. It records what happened; it does not (in v1) prevent it. It sees through first-party sandboxes because it reads the kernel, but an attacker who is already on your machine at recording time — root, *or your own uid, which is what a fully-subverted agent is* — can suppress *future* events. That's detectable (gaps, checkpoint breaks, a root-owned mirror of chain heads that even a stolen signing key can't rewrite), not preventable. We state exactly what we deliver, in plain language, because in a security tool candor *is* the feature. LIMITS.md enumerates every known blind spot.

---

## Why this exists

Every existing agent-safety tool is a **wall**. Sandboxes (Claude Code's `/sandbox`, Codex's Landlock, `srt`, bubblewrap, microVMs) *prevent*. MCP gateways *permit or deny* wire traffic. All of them answer one question: **"may the agent do this?"**

None of them answer the question you actually have the morning after:

> **"What *did* it do — provably, across all my agents, and can I trust the record?"**

Walls are per-vendor and per-mode. Claude Code sandboxes Claude Code. Codex sandboxes Codex. OpenClaw's exec sandbox ships an `elevated` bypass *by design*. Nothing watches across agents, and nothing records what the walls themselves let through. Prevention without memory means every incident review starts from zero — and personal agents fail *quietly*:

- **Cline, Feb 2026** (5M+ users): a prompt-injection chain exfiltrated npm release tokens and published a malicious package.
- **OpenClaw CIK evaluation** (arXiv 2604.04759): the most-deployed personal agent runs with full local access to Gmail, Stripe, and the filesystem — an attack surface sandboxed evals don't capture.

RanA's answer is **kernel truth**: an eBPF collector records every `exec`, write-intent file op, network flow, and credential-file read attributable to an agent session; a non-optional redaction stage strips secrets *before* anything is written; the result lands in a hash-chained, Merkle-segmented, Ed25519-signed ledger you can `verify`, `export`, and browse in a local timeline. It works identically for Claude Code, Codex, OpenClaw, and any custom agent, and it costs you one command.

## What RanA is / isn't

| RanA **is** | RanA **is not** |
|---|---|
| A cross-agent flight recorder | A sandbox or firewall (v1) |
| Kernel-truth (eBPF), not agent self-report | An MCP wire proxy / TLS interceptor |
| A tamper-evident, signed ledger you own | A cloud service (no telemetry, no accounts, ever) |
| A record of **effects** — exec, files, network | A record of **thoughts** — it never captures prompts, completions, or keystrokes |
| Composable with sandboxes (observe an `srt`-wrapped agent) | A replacement for them |

The **effects-not-thoughts** line (`P7` in the plan) is both a privacy stance and a scope weapon: RanA records what an agent *did to your machine*, never what it *said*.

## Install

```sh
# Linux (kernel ≥ 5.15, cgroup v2) or macOS ≥ 13 (Apple Silicon)
curl -fsSL https://get.rana.dev | sh

# then check your machine's capability tier
rana doctor
```

Release binaries are reproducible-built, cosign-signed, and ship an SBOM. There is no phone-home and no background update check. Everything is one static binary (`rana`) plus a privileged collector (`ranad`); on macOS the Linux guest image is embedded.

## Quickstart

**Record any agent for one run:**

```sh
rana run --profile claude-code -- claude
# ... work as usual ...
rana timeline            # opens a localhost UI, token-gated
```

**Adopt a long-running agent (the hero path):**

```sh
rana adopt openclaw      # slots the gateway + all its children into one session
rana timeline            # watch "conversation → consequences" live
```

**Prove the record wasn't touched:**

```sh
rana verify              # recomputes the whole chain; seconds even at millions of events
rana export --session <id> out/     # portable proof pack a third party can verify with no RanA installed
```

## The two demos worth seeing

1. **Exfil, caught.** A poisoned webpage tries to get your agent to read `~/.ssh/id_ed25519` and POST it out. Your phone buzzes the moment the credential is read; the timeline shows the read, the new domain, and the exact process chain that did it.
2. **Destruction, reversible** *(gated mode, post-1.0)*. An agent runs `rm -rf` — into a copy-on-write overlay. You open `rana diff`, see *everything* it changed (not just the git-tracked files), commit the good parts, discard the rest. Your machine was never touched.

## How it works (30 seconds)

```
agent processes ─ cgroup: rana.slice/rana-<session>.scope
      │
  [kernel] eBPF (exec / file / connect / sensitive-read)
      │ ringbuf
   ranad (root) ─ decode → REDACT secrets → rate-govern
      │ unix socket (peer-authenticated)
   rana session service (your user)
      ├─ SQLite ledger + hash chain + Ed25519 checkpoints
      ├─ content-digest worker (profile scopes only)
      └─ localhost timeline UI
```

One **cgroup v2 leaf per session** is the attribution primitive: an agent's entire process tree — OpenClaw's gateway spawning sub-agents spawning tool processes — is captured by inheritance, which is *why* cross-agent works for free. See [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md).

## Trust, briefly

- **Integrity after persistence** — any edit, deletion, or reorder of stored events is detected by `rana verify`.
- **Secret-freedom** — environment values are *never* captured; every other string is redacted before it's hashed. See [`docs/REDACTION.md`](./docs/REDACTION.md).
- **Inertness** — observe mode cannot alter or break your agent. If `ranad` dies, agents keep running; the gap becomes a visible `gap` event.
- **Portable proof** — the chain spec and a standalone verifier are documented in [`docs/TRUST.md`](./docs/TRUST.md).

And the honest limits are in [`LIMITS.md`](./LIMITS.md). Read them.

## Platform support

| | Linux | macOS | Windows |
|---|---|---|---|
| **v1** | Native (eBPF, kernel ≥ 5.15, cgroup v2) | Embedded Linux microVM (Apple Virtualization, AS primary) | Non-goal |

Native macOS process recording needs Endpoint Security entitlements Apple grants case-by-case — closed to open-source distribution. The microVM is the only recording path, and the *same* capture stack runs inside it; the guest ships a Node.js runtime layer so real agents (OpenClaw, Claude Code) actually run there, with your config and workspace projected in from the host. The honest limitations: an agent running *natively* on macOS is not recorded at all, and an agent inside the guest can't drive native macOS apps (AppleScript, iMessage); OpenClaw's network-centric core is unaffected. Details in [`docs/MACOS.md`](./docs/MACOS.md).

## Documentation

- [`RANA-plan-v1.md`](./RANA-plan-v1.md) — the binding plan (principles, decisions, roadmap, gates)
- [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) · [`docs/THREAT-MODEL.md`](./docs/THREAT-MODEL.md) · [`docs/TRUST.md`](./docs/TRUST.md) · [`docs/REDACTION.md`](./docs/REDACTION.md)
- [`docs/OPENCLAW.md`](./docs/OPENCLAW.md) — the adopt flow and causality explainer
- [`CLAUDE.md`](./CLAUDE.md) — the execution contract for autonomous builds
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — DCO, no CLA, the test rig

## License

Apache-2.0. DCO sign-off required; no CLA. Security disclosures: see [`docs/SECURITY.md`](./docs/SECURITY.md).
