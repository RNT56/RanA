<div align="center">

<img src="assets/header/RanA-head.png" alt="RanA" width="880">

<h3>The flight recorder for AI agents</h3>

<p><strong>A kernel-truth, tamper-evident ledger of everything your agents execute, touch, and contact &mdash; across every agent on your machine, with zero configuration.</strong></p>

<p><em>Chain of custody for AI agents.</em></p>

<p>
<img src="https://img.shields.io/badge/status-under%20development-F2A93B" alt="Status: under development">
<img src="https://img.shields.io/badge/stage-alpha-F2A93B" alt="Stage: alpha">
<img src="https://img.shields.io/badge/license-Apache--2.0-1E6FE0" alt="License Apache-2.0">
<img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go 1.26+">
<img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-2b7fff" alt="Linux and macOS">
<img src="https://img.shields.io/badge/kernel-5.15+-1E6FE0" alt="Kernel 5.15+">
<img src="https://img.shields.io/badge/telemetry-none-2ea043" alt="No telemetry">
<img src="https://img.shields.io/badge/ledger-signed%20%26%20verifiable-1E6FE0" alt="Signed and verifiable ledger">
</p>

<sub>◆ &nbsp; kernel truth &nbsp; ◆ &nbsp; effects, not thoughts &nbsp; ◆ &nbsp; secret-free by construction &nbsp; ◆</sub>

</div>

---

RanA records what an AI agent *did to your machine* &mdash; every process it ran, every file it wrote, every credential it read, every host it contacted &mdash; and writes it into a hash-chained, signed ledger you can verify, export, browse, and query with an agent. It reads the kernel, so it sees through first-party sandboxes and works the same for Claude Code, Codex, Gemini CLI, goose, OpenClaw, Hermes, and anything you build yourself.

It never reads prompts or completions. It records **effects, not thoughts**.

> ### ⚠ &nbsp; Under active development
>
> RanA is **alpha**. Here is exactly where it stands, because in a security tool candor is the point:
>
> - ✅ **The trust core is solid and gate-tested** &mdash; the pure-Go ledger, hash chain, Ed25519 signing, redaction pipeline, canonical encoding, wire protocol, profile engine, alerts, the timeline UI, the standalone verifier, and the `rana-mcp` server all build and pass `go test -race`, with regression gates for throughput (G1), redaction recall/leak-freedom (G4), and chain-mutation detection (G5).
> - 🚧 **Live capture is being brought up in CI.** The eBPF collector (the kernel-truth pillar) and the macOS Linux-guest image compile/build in CI but have **not yet run end-to-end on a live kernel** &mdash; that is the current work, and it is what turns "built" into "records." Until it is green, no agent has been recorded end-to-end.
> - 🚧 **Marker emitters** for 7 agent frameworks are written and loopback-tested but not yet validated against the live frameworks.
>
> **Do not rely on RanA for anything that matters yet.** Watch the [Actions tab](https://github.com/RNT56/RanA/actions) for the eBPF/guest milestone. And before you rely on it *ever*, read [`LIMITS.md`](./LIMITS.md).

```text
Already running OpenClaw?

    curl -fsSL https://raw.githubusercontent.com/RNT56/RanA/main/install/get-rana.sh | sh
    rana adopt openclaw

Open the timeline. That's the intended one-command experience.
```

> RanA is an *observation* tool, not a wall &mdash; it records what happened, it does not (in v1) prevent it. An attacker already on your machine at recording time, whether root or *your own uid* (which is what a fully-subverted agent is), can suppress *future* events. That is detectable &mdash; through gap markers, checkpoint breaks, and a root-owned mirror of chain heads that even a stolen signing key cannot rewrite &mdash; but not preventable. We say exactly what we deliver, in plain language. See [`LIMITS.md`](./LIMITS.md).

## Why it exists

Every agent-safety tool today is a **wall**. Sandboxes prevent. Gateways permit or deny wire traffic. They all answer one question: *may the agent do this?*

None of them answer the question you actually have the morning after:

> **What *did* it do &mdash; provably, across all my agents, and can I trust the record?**

Walls are per-vendor and per-mode. Claude Code sandboxes Claude Code. Codex sandboxes Codex. OpenClaw ships an `elevated` bypass by design. Nothing watches across agents, and nothing records what the walls themselves let through. Prevention without memory means every incident review starts from zero &mdash; and personal agents fail quietly:

- **Cline, Feb 2026** (5M+ users) &mdash; a prompt-injection chain exfiltrated npm release tokens and published a malicious package.
- **OpenClaw CIK evaluation** (arXiv 2604.04759) &mdash; the most-deployed personal agent runs with full local access to Gmail, Stripe, and the filesystem.

RanA's answer is kernel truth: an eBPF collector records every `exec`, write-intent file op, network flow, and credential-file read attributable to an agent session &rarr; a non-optional redaction stage strips secrets before anything is written &rarr; the result lands in a hash-chained, Merkle-segmented, Ed25519-signed ledger you can `verify`, `export`, browse, and query.

## What RanA is, and is not

| ✓ &nbsp; RanA is | ✗ &nbsp; RanA is not |
|---|---|
| A cross-agent flight recorder | A sandbox or firewall (v1) |
| Kernel-truth (eBPF), not agent self-report | An MCP wire proxy or TLS interceptor |
| A tamper-evident, signed ledger you own | A cloud service &mdash; no telemetry, no accounts, ever |
| A record of **effects**: exec, files, network | A record of **thoughts** &mdash; never prompts, completions, or keystrokes |
| Composable with sandboxes (record an `srt`-wrapped agent) | A replacement for them |

The **effects-not-thoughts** line is both a privacy stance and a scope boundary: RanA records what an agent did to your machine, never what it said. It is *safe to run* precisely because it cannot leak your conversations, prompts, or secrets.

## Quickstart

Install &mdash; one static binary plus a privileged collector; on macOS a Linux guest image does the recording:

```sh
# Linux (kernel 5.15+, cgroup v2) or macOS 13+ (Apple Silicon)
curl -fsSL https://raw.githubusercontent.com/RNT56/RanA/main/install/get-rana.sh | sh

# check your machine's capability tier (works today — kernel recon)
rana doctor
```

▸ &nbsp;**Record any agent for one run**

```sh
rana run --profile claude-code -- claude
rana timeline            # localhost UI, token-gated
```

▸ &nbsp;**Adopt a long-running agent** (the hero path)

```sh
rana adopt openclaw      # slots the gateway and all its children into one session
rana timeline            # watch conversation → consequences, live
```

▸ &nbsp;**Prove the record was not touched**

```sh
rana verify              # recomputes the whole chain; seconds even at millions of events
rana export --session <id> out/     # portable proof pack a third party can verify with no RanA installed
```

▸ &nbsp;**Let an agent reason over the record** &mdash; [`rana-mcp`](./docs/MCP.md)

```sh
rana-mcp --data ~/.local/share/rana     # a read-only MCP server over your ledger
```

Point any MCP client at it and ask *"which recorded session has a critical alert, and is its chain intact?"* &mdash; the agent answers from the signed, **secret-free** effects record, never seeing a prompt or a credential.

## Supported agents

RanA captures at the **kernel** (one cgroup-v2 leaf per session), so it records *any* agent's process tree identically &mdash; the `generic` profile captures anything with zero configuration. On top of that, RanA ships tuned **profiles** (recognition, digest scopes, credential watchlists) and, where a framework exposes a lifecycle hook, optional **marker emitters** that correlate effects to a run by `runId` (identifiers only &mdash; never prompt text, P7).

| Agent | Profile | Marker emitter |
|---|---|---|
| OpenClaw | ✓ | ✓ (JS gateway plugin) |
| Claude Code | ✓ | ✓ (settings.json hook) |
| Codex (OpenAI CLI) | ✓ | ✓ (config hook) |
| Gemini CLI (Google) | ✓ | ✓ (SessionStart/End hook) |
| goose (Block) | ✓ | ✓ (command hook) |
| Hermes (Nous Research) | ✓ | ✓ (Python plugin) |
| OpenCode | ✓ | ✓ (TS plugin) |
| Cline | ✓ | ✓ (task hooks) |
| Aider | ✓ | — (no lifecycle hook exists) |
| Cursor · generic-CI · any custom agent | ✓ / generic | — |

Adding a new agent is a profile (~10 minutes) plus an optional emitter &mdash; the capture already works. See [`docs/PROFILES.md`](./docs/PROFILES.md) and the emitters in [`plugins/`](./plugins).

## The two demos worth seeing

1. **Exfil, caught.** A poisoned webpage tries to get your agent to read `~/.ssh/id_ed25519` and POST it out. The moment the credential is read RanA correlates it with the never-before-seen host it then contacts &mdash; the "exfil precursor" trifecta &mdash; and the timeline shows the read, the new domain, and the exact process chain that did it.
2. **Destruction, reversible** *(gated mode, post-1.0)*. An agent runs `rm -rf` into a copy-on-write overlay. You open `rana diff`, see everything it changed (not just the git-tracked files), commit the good parts, discard the rest. Your machine was never touched.

## How it works

One **cgroup v2 leaf per session** is the attribution primitive: an agent's entire process tree &mdash; a gateway spawning sub-agents spawning tool processes &mdash; is captured by kernel inheritance, which is why cross-agent works for free.

```text
   agent process tree ── cgroup: rana.slice/rana-<session>.scope
          │
   ┌──────┴──────────────────────────────────────────────────┐
   │ [kernel] eBPF   exec · file · connect · sensitive-read  │
   └──────┬──────────────────────────────────────────────────┘
          │ ring buffer
   ┌──────┴──────────────────────────────────────────────────┐
   │ ranad (root)    decode → REDACT secrets → rate-govern   │
   └──────┬──────────────────────────────────────────────────┘
          │ unix socket, peer-authenticated
   ┌──────┴──────────────────────────────────────────────────┐
   │ rana session service (your user)                        │
   │   ▸ SQLite ledger + hash chain + Ed25519 checkpoints    │
   │   ▸ content-digest worker (profile scopes only)         │
   │   ▸ localhost timeline UI  ·  rana-mcp read API         │
   └─────────────────────────────────────────────────────────┘
```

The collector is inert by construction: no hook can block, delay, or modify a syscall. If `ranad` dies, your agents keep running &mdash; the missing window becomes a visible `gap` event, never a silent hole. See [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md).

## Trust, briefly

- **Integrity after persistence** &rarr; any edit, deletion, reorder, or wholesale session removal is detected by `rana verify`.
- **Secret-freedom** &rarr; environment values are never captured; every other string is redacted before it is hashed. See [`docs/REDACTION.md`](./docs/REDACTION.md).
- **Inertness** &rarr; observe mode cannot alter or break your agent.
- **Portable proof** &rarr; the chain spec and a standalone (and WASM/browser) verifier are documented in [`docs/TRUST.md`](./docs/TRUST.md); an export verifies with no RanA installed.

And the honest limits are in [`LIMITS.md`](./LIMITS.md). Read them.

## Platform support

| | Linux | macOS | Windows |
|---|---|---|---|
| **v1** | Native eBPF (kernel 5.15+, cgroup v2) | Embedded Linux microVM (Apple Virtualization, Apple Silicon primary) | Non-goal |

Native macOS process recording needs Endpoint Security entitlements Apple grants case-by-case &mdash; closed to open-source distribution. The microVM is the only recording path, and the same capture stack runs inside it; the guest ships a Node.js runtime layer so real agents actually run there, with your config and workspace projected in from the host. Two honest limits: a *natively*-running macOS agent is not recorded at all, and an agent inside the guest cannot drive native macOS apps (AppleScript, iMessage). Details in [`docs/MACOS.md`](./docs/MACOS.md) and the native-path design in [`docs/MACOS-NATIVE.md`](./docs/MACOS-NATIVE.md).

## Engineering posture

- **One static binary per host role.** No Python, Node, or Docker runtime dependency. Pure-Go SQLite and a pure-Go eBPF loader; the only CGO is the macOS host binary.
- **Reproducible builds**, cosign-signed release artifacts, and an SBOM from the first release. No phone-home, no background update check. Continuous fuzzing of every trust-boundary parser, and a call-graph vulnerability scan, run in CI.
- **Strict TDD, gate-enforced.** Ledger sustains 10k+ events/second with zero loss · redaction holds 99%+ recall on a permanent seeded-secret corpus with a zero-raw-secret-leak gate · `verify` detects 100% of a chain-mutation suite. These are regression gates, not one-time checks.

## Documentation

- Core specs &mdash; [`ARCHITECTURE`](./docs/ARCHITECTURE.md) · [`THREAT-MODEL`](./docs/THREAT-MODEL.md) · [`TRUST`](./docs/TRUST.md) · [`REDACTION`](./docs/REDACTION.md)
- [`docs/OPENCLAW.md`](./docs/OPENCLAW.md) &mdash; the adopt flow and causality explainer
- [`docs/MCP.md`](./docs/MCP.md) &mdash; `rana-mcp`: query the ledger from an agent (read-only, effects-only, secret-free)
- Platform and process &mdash; [`MACOS`](./docs/MACOS.md) · [`PROFILES`](./docs/PROFILES.md) · [`SECURITY`](./docs/SECURITY.md) · [`CONTRIBUTING`](./CONTRIBUTING.md)
- Design notes &mdash; [`MULTIUSER`](./docs/MULTIUSER.md) (system-wide ranad) · [`MACOS-NATIVE`](./docs/MACOS-NATIVE.md) (native ES path)
- For contributors &mdash; [`docs/CONTRACTS.md`](./docs/CONTRACTS.md): the per-package interface contract every layer is built and tested against

## License

Apache-2.0. DCO sign-off required; no CLA. Security disclosures: see [`docs/SECURITY.md`](./docs/SECURITY.md).

<div align="center">
<br>
<img src="assets/logo/RanA.png" alt="RanA" width="80">
<br>
<sub><em>rana</em> is Latin for frog. It sits on the lilypad. It sees everything. It does not interfere.</sub>
<br><br>
<sub><strong>Nothing was blocked that shouldn't have been · Nothing happened that wasn't recorded · Nothing left that wasn't seen · And every byte of proof belongs to you.</strong></sub>
</div>
