# CLAUDE.md — Execution Contract for RanA

This file governs autonomous work on RanA. It is **binding**. When any instruction conflicts with `RANA-plan-v1.md`, the plan wins and you stop to flag the conflict. When principles below conflict with each other, the lower-numbered principle wins (they are ranked).

You are building a **security and forensics tool**. The bar is higher than "works." The bar is: *a stranger relies on this to know what their AI agent did, and is right to.*

---

## 0. Mission (one paragraph)

RanA is the cross-agent flight recorder for AI agents: a kernel-truth (eBPF), tamper-evident (hash-chained, signed), secret-free ledger of everything an agent *executes, touches, and contacts*, browsable in a local timeline, portable and independently verifiable, that works identically for Claude Code, Codex, OpenClaw, and any custom agent, and costs the user one command. It records **effects, never thoughts**.

## 1. The ten principles as enforceable rules

Every one of these is a rule you can be *wrong about*. Treat a violation as a failing test.

- **P1 — Kernel truth over agent self-report.** Load-bearing events MUST originate from eBPF hooks. Agent-provided data (markers) is enrichment only, MUST carry `origin=enrichment` in-schema, and MUST NOT be required to reconstruct the record. *If you find yourself trusting an agent's log for a fact the kernel could provide, stop.*
- **P2 — Observation is inert.** No code in observe mode may block, delay meaningfully, modify, or proxy a syscall. No `LD_PRELOAD`, no `ptrace`-interposition, no syscall-notify blocking. If `ranad` dies, agents keep running. *Any PR that can break the workload in observe mode is rejected regardless of its other merits.*
- **P3 — Secrets never persist.** `envp`/`environ` MUST NOT be read anywhere. Every captured string MUST pass the redaction pipeline (`docs/REDACTION.md`) **before** it is hashed. There is NO flag that disables redaction. Raw secret bytes may exist only transiently in `ranad` RAM.
- **P4 — Tamper-evidence, not tamper-proofing.** Claim exactly what the chain delivers. Detection of post-persistence modification: yes. Prevention of a contemporaneous root attacker suppressing future events: no. `LIMITS.md` states this plainly; code comments and docs MUST NOT overclaim.
- **P5 — Losses are loud.** Ring-buffer drops, governor sheds, daemon restarts MUST each produce a first-class `gap` event inside the chain, with counts and reason. The ledger MUST NEVER silently omit.
- **P6 — Zero-config value in ten minutes.** Every feature is measured against: does a stranger get a meaningful timeline the same evening? Configuration that could be a sensible default MUST be a default.
- **P7 — Effects, not thoughts.** NEVER capture model I/O: prompts, completions, message content, keystrokes. This is permanent and not an option. Markers carry identifiers and lifecycle only (`runId` yes, message text never).
- **P8 — Compose with walls, never rebuild them.** `srt`, bubblewrap, Landlock, microVMs are integration targets, not competitors. Do not reimplement a sandbox in v1.
- **P9 — One static binary per host role.** No Python, Node, or Docker runtime dependency. Linux builds are static (pure-Go SQLite via `modernc.org/sqlite`, cilium/ebpf loader — no libbpf C linkage). The only CGO is the macOS host binary (vz requires it). The macOS guest image is embedded or fetched-once-with-signature-check.
- **P10 — Documented honesty is a feature.** `LIMITS.md` ships at launch with README-grade polish. New escapes or blind spots discovered during work MUST be added to `LIMITS.md` in the same PR.

## 2. Scope walls (reject on contact)

These are not "later" — they are **never** for this project. A request touching them is out of scope by definition:

- Capturing prompts/completions/keystrokes (P7).
- MCP wire inspection, TLS interception, payload capture.
- Telemetry, phone-home, background update checks, accounts, cloud sync.
- Windows support (v1).
- Being a wall / enforcement in v1 (gated mode is Phase G, pre-designed, not v1).
- General host-wide security monitoring (RanA is cgroup-bound to agent sessions; it is not Falco/Tetragon).

When you hit one of these, do not implement it. Note it, cite the principle or `RANA-plan-v1.md §10`, and move on.

## 3. How we work

### 3.1 Strict TDD — non-negotiable

Red → green → refactor, every unit. No production code without a failing test first.

- **Pure-Go layers** (ledger, chain, sign, verify, redaction, profile engine, path translation, governor): high unit coverage, table-driven, property tests where shape allows. `internal/redact` and `internal/ledger` are held to the strictest bar — they are the trust core.
- **eBPF programs**: tested via the cilium/ebpf userspace harness + a golden-trace corpus (`test/golden-traces/`). Each program has a deterministic fixture: known syscalls in → known events out.
- **Chain integrity**: `test/chain-mutations/` is a permanent suite that mutates sealed ledgers (edit/delete/reorder/re-sign) and asserts `verify` catches 100%.
- **Redaction**: `test/redaction-corpus/` (500+ seeded secret shapes) is a permanent regression gate; a real secret reaching a leaf hash in any test is a build failure.

### 3.2 Maximum-DAG parallelism

Structure work as a dependency graph and run independent nodes concurrently. The layers are deliberately decoupled so this is possible:

- `internal/ledger`, `internal/redact`, `internal/profile`, `internal/ui` have **no dependency** on `internal/bpf` and can be built and fully tested against synthetic event streams in parallel with kernel work.
- `internal/vm` (macOS) depends only on the event-stream contract, not on the Linux collector internals.
- Define the **event schema (plan §4.3) first and freeze it**; every other node codes against the schema, not against each other.

Serialize only where the graph truly forces it (schema before consumers; capture backend before end-to-end tests).

### 3.3 Definition of Done (per unit)

A unit is done when: failing test written first → implementation passes → refactored → relevant success gates (§4) still green in CI → `LIMITS.md`/docs updated if behavior or coverage changed → DCO-signed commit. Not before.

### 3.4 Commits & reviews

- Conventional-commit style, DCO `Signed-off-by` on every commit, no CLA.
- Security-relevant changes (anything in `ranad`, `internal/redact`, `internal/ledger`, the systemd unit, the vz host path) get an explicit threat note in the PR body: *what surface does this touch, and why is it still safe?*

## 4. Success gates (CI-enforced — the build is red if these regress)

From the phase each lands, these are **regression gates**, not one-time checks:

| Gate | Rule | Lands |
|---|---|---|
| **G1** | Ledger sustains ≥10k events/s, zero loss, p99 commit <15ms (laptop-class) | Phase 1 |
| **G4** | Redaction ≥99% recall on the corpus; **zero** env values ever captured | Phase 1 |
| **G5** | `verify` detects 100% of the chain-mutation suite; distinguishes gap-honest from broken | Phase 1 |
| **G7** | Recorded vs unrecorded agent run: no behavioral change; wall-time overhead <2%; zero RanA-attributable agent failures | Phase 1 |
| **G2** | Timeline open + live tail adds <3% CPU; no event backpressure | Phase 2 |
| **G3** | macOS cold boot ≤10s; warm (≥14) ≤1s to recording | Phase 3 |
| **G6** | Fresh user → meaningful timeline <10 min; narrates agent behavior <5 min | Phase 2/4 |
| **G8** | Reproducible build verified on 2 machines; artifacts cosign-signed; SBOM present | Phase 5 |

**No phase after a gate's owning phase begins until that gate is green.** Launch is blocked on all gates + `LIMITS.md` complete.

## 5. Build & test commands (canonical)

> Fill in as scaffolding lands; these are the intended entry points. Agents MUST keep them working.

```sh
make gen          # bpf2go codegen (CO-RE objects, embedded) — no clang at runtime after this
make build        # static Linux binaries (rana, ranad); macOS: CGO + codesign
make test         # all Go unit + harness tests
make test-e2e     # adopt → record → verify → export, per platform
make gate         # runs G1/G4/G5/G7 perf+security gates locally
make guest        # reproducible Buildroot guest image (macOS path)
make doctor       # build + run `rana doctor` against the current kernel
```

CI matrix: LTS kernels (5.15, 6.1, 6.6, latest) on amd64 + arm64; a macOS runner for the vz path; reproducible-build verification on two runners; cosign + SBOM on release.

## 6. Non-negotiable invariants (assert these in code and tests)

1. No path reads `envp` or `/proc/<pid>/environ`. (grep-able CI check.)
2. No string is written to the ledger before passing `redact`. (Enforced by making the writer accept only a `Redacted` type; raw strings can't reach it by construction.)
3. `verify` on an untouched ledger returns success; on any mutation, failure with a precise reason.
4. Observe-mode hooks have no `bpf_probe_write`, no return-value override, no blocking helper. (CI greps the compiled program list.)
5. Every `gap` has counts + reason; no code path drops events without emitting one.
6. Marker events always carry `origin=enrichment`; nothing marker-sourced is treated as authoritative.
7. Every string reaching the ledger writer passes redaction **in the process it arrives in** — ranad for kernel events, the session service for markers/metadata/digest paths. The `Redacted`-only writer type enforces this in both. (Plan D13, v1.1.)
8. Every checkpoint carries `prev_checkpoint_hash` (ledger-wide chain) and its head is reported to ranad's root-owned mirror; `test/chain-mutations/` includes whole-session deletion and rewrite-and-re-sign-with-the-real-key, both caught (the latter by `verify --mirror`). (Plan D12/D27, v1.1.)
9. File events carry `path_source` (`resolved` | `claimed`); nothing treats a `claimed` path as kernel ground truth. (Plan D7, v1.1.)

## 7. When in doubt

Optimize for the stranger who trusts the record. If a choice trades a little convenience for a stronger or more honest guarantee, take the guarantee. If you're unsure whether something is in scope, it probably isn't — check §2 and `RANA-plan-v1.md §10`. If a decision isn't covered by the plan, stop and surface it rather than inventing policy.
