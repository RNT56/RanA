# Threat Model

This is the reference for RanA's threat model. It names the adversaries RanA is built against, the ones it explicitly is not, and the exact trust claims that survive contact with each. If a claim here is stronger than what the code delivers, that is a launch-blocking bug (`P4`, `P10`).

---

## 1. Adversaries in scope

| ID | Adversary | Representative incident | What RanA gives you |
|----|-----------|--------------------------|---------------------|
| **A1** | **Prompt-injected agent** — a well-behaved agent binary driven by hostile instructions (poisoned webpage, email, tool description, ClawHub skill). | Cline Feb-2026 chain (npm token exfil, 5M+ users); ClawHavoc skill wave. | The full effect record: the sensitive-read the moment it happens (alert), the new domain it exfiltrates to, the exact process chain — kernel-attributed, not self-reported. |
| **A2** | **Malicious tool / dependency** — an MCP server, plugin, or package the agent legitimately invokes. | Supply-chain packages spawning exfil subprocesses. | The subprocess exec, its file touches, its egress — attributed to the session even three forks deep, because attribution is cgroup inheritance, not process-name matching. |
| **A3** | **Over-permissioned automation** — no attacker; a cron'd agent with broad grants does something expensive or destructive quietly. | Rewritten dotfiles; surprise API spend; "why is my home directory different." | A browsable, verifiable timeline of everything it did, discoverable days later. |
| **A4** | **Post-incident uncertainty** — your own inability to reconstruct events after A1–A3. | Every incident review that starts from zero. | `verify`-able history plus portable, independently checkable exports (`docs/TRUST.md §7–8`). |

## 2. Adversaries explicitly out of scope

- **The ledger owner as adversary.** You hold the key. No DRM, no anti-forensics against yourself.
- **A compromised kernel.** eBPF reads kernel state; a rootkit that lies to the kernel makes RanA lie too.
- **Model-layer attacks as such** (jailbreaks). RanA sees their *effects* only — that is the product, not a gap.

## 3. The two contemporaneous-attacker boundaries

These are the claims most tempting to overstate, so they get their own section. Both are **detectable, not preventable** (`P4`).

### 3.1 Root at recording time
Can kill `ranad` or prevent it starting → *future* events suppressed. Detection: `gap{daemon_restart}` on resume, checkpoint-cadence break, `verify` boundary flag. Cannot silently rewrite sealed history (signatures + the root-owned head mirror).

### 3.2 Your own uid at recording time — which is what a subverted A1 *is*
The recorded agent typically runs as the ledger owner. A fully-subverted agent can kill the user session service, **read the signing key**, and attempt a rewrite-and-re-sign of the user-owned ledger. RanA's answer (the D27 custody guarantee, `LIMITS.md §6.1`):

1. **Root-owned head mirror.** Every checkpoint head is reported to `ranad` and appended to `/var/lib/rana/heads.log` (root-owned, append-only). Heads mirrored before the compromise pin the past beyond a user-privileged attacker's reach; `rana verify --mirror` detects any rewrite, even one signed with the stolen key.
2. **The recorder watches itself.** RanA's data directory (ledger, key, salt) is on the built-in sensitive watchlist — reading the key or opening the ledger for write is a recorded, alertable event until the moment capture is suppressed.
3. **Honest boundary.** For events *after* the compromise, same-uid ≈ root: suppression is detectable, not preventable.

## 4. RanA's own attack surface

RanA's own attack surface and its mitigations:

| Surface | Exposure | Mitigation |
|---|---|---|
| `ranad` (root) | The privileged component. | No listening TCP; single unix socket, SO_PEERCRED-gated to the owning uid; systemd hardening (`ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`); caps limited to `CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE` where the kernel allows; no parsing of untrusted input beyond validated watchlist paths. |
| Timeline UI | Local browser surface. | 127.0.0.1 bind, random port, per-launch bearer token, strict CSP, no CORS, no cookies. Optional tsnet exposure (Phase 5) is read-only + tailnet-identity, off by default. |
| Marker socket | Reachable by session processes. | Per-session random token; markers are enrichment (`origin=enrichment`) — a forged marker can mislabel a cluster, never fabricate a kernel event or carry content (allowlist + forbid-list). |
| Ledger + key files | User-owned 0600. | §3.2 above: head mirror, self-watchlist, stated boundary. |
| Supply chain | You are installing a root daemon. | Reproducible builds, cosign-signed artifacts, SBOM, pinned deps, no postinstall scripts (D23). Verify before you trust us — that's the point of the tool, applied to itself. |

## 5. Trust properties (the claims the README may make)

1. **Completeness within scope** — every exec, write-intent fs op, egress connect/send, and sensitive read inside a session's cgroup is captured or accounted for by a `gap` event (escape caveats: `LIMITS.md §3`).
2. **Integrity after persistence** — any post-hoc edit, deletion (including whole-session deletion — ledger-wide checkpoint chain), or reorder is detected by `verify`.
3. **Secret-freedom** — env values never captured; all strings redacted pre-hash (`docs/REDACTION.md`; residual: `LIMITS.md §4`).
4. **Inertness** — observe mode cannot alter or break the workload; `ranad` death leaves agents running.
5. **Guest-compromise containment (macOS)** — a fully-owned guest can suppress/forge its own future events, never rewrite the host-persisted chain.
