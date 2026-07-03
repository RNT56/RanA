# LIMITS — What RanA does and does not guarantee

This document is a **launch blocker**: v1.0 does not ship until every entry here is accurate. In a security tool, an honest account of coverage is worth more than a wall that lies. If you find a gap not listed here, that is a bug in *this file* — please report it.

RanA records the **effects** of AI agents with kernel-level fidelity. It is an observation tool, not an enforcement tool (in v1). Read this before you rely on it for anything that matters.

---

## 1. What we claim (and will defend)

Within a recorded session's cgroup, these hold:

1. **Completeness within scope.** Every process `exec`, write-intent filesystem operation, outbound `connect`, and credential-file *read* by a process inside the session is either captured or accounted for by an explicit `gap` event. Losses are never silent. *(Caveat: §3 escapes.)*
2. **Integrity after persistence.** Any post-hoc edit, deletion, reordering, or re-signing of stored events — including deletion of an *entire session*, which the ledger-wide checkpoint chain catches — is detected by `rana verify`. See `docs/TRUST.md`. *(Same-uid attacker boundary: §6.1.)*
3. **Secret-freedom.** Environment variable *values* are never captured by any code path. Every other captured string is redacted before it is hashed into the chain. *(Residual risk: §4.)*
4. **Inertness.** Observe mode cannot alter agent behavior or availability. No hook blocks, delays, or modifies a syscall. If `ranad` crashes, agents keep running.
5. **Guest-compromise containment (macOS).** An agent that fully owns the guest VM can forge or suppress its *own future* events but cannot rewrite the host-persisted chain.

## 2. What we explicitly do NOT claim

- **We do not prevent anything (v1).** RanA is a recorder. Enforcement (gated/transactional mode) is a post-1.0 feature. Do not deploy RanA expecting it to *stop* an agent.
- **We are not tamper-*proof*, only tamper-*evident*.** We detect modification after the fact. We do not make modification impossible.
- **We do not defend against a compromised kernel.** eBPF reads kernel state. A rootkit that lies to the kernel makes RanA lie too. RanA assumes an honest kernel.
- **We do not treat the ledger owner as an adversary.** You hold the signing key. There is no DRM and no anti-forensics against yourself.
- **We do not record model I/O — ever.** No prompts, no completions, no message content, no keystrokes. This is permanent and not configurable. If you need prompt logging, RanA is the wrong tool by design.

## 3. Known attribution escapes

cgroup-based attribution is strong for cooperative process trees and has known escapes. RanA **surfaces the seam** rather than hiding it — where we can't claim a process, we emit an alert about the attempt.

| Escape | What's missed | What RanA still emits | Roadmap |
|---|---|---|---|
| **Delegated spawn via `systemd-run` / D-Bus activation** | The spawned unit is a child of PID 1 in a foreign cgroup — its *consequences are not attributable to the session*. RanA cannot follow it. | `alert.escape_precursor` on the observable request: the in-session exec of `systemd-run`/`busctl`/`dbus-send` and the `unix.connect` to the bus socket. The request is recorded; the delegated work is not. | Phase G can deny the escape primitive under enforcement. |
| **Self-migration out of the session cgroup** | A process that writes itself into another cgroup leaves the recorded scope. | Detected: the in-kernel session pid-map + the `cgroup_attach_task` migration hook raise `alert.cgroup_escape{pid, from, to}`; a later exec by a known session pid outside the session cgroup is also flagged. | Phase G denies the migration under enforcement. |
| **`io_uring` socket ops** | On the 5.15 baseline, some `io_uring`-issued network operations bypass the syscall/`connect` tracepoints. | Coverage table below; where covered, normal `net.connect`. | `io_uring` op hooks as kernels stabilize them; enumerated per-version. |
| **`LD_PRELOAD` / direct-syscall file ops** | A process that avoids the kernel paths we hook for *files* can write without an `fs.*` event. | **Network is still caught** at the cgroup socket layer (a different hook family it can't dodge from userspace); exec of the preloading process is recorded. | Broaden fs hook coverage (LSM hooks under evaluation). |
| **setuid transitions** | A setuid binary changes credentials mid-tree; ownership context shifts. | `proc.exec` with uid change is recorded and flagged. | Documented; enforcement-mode policy in Phase G. |
| **Hardlinks into the sensitive watchlist** | The watchlist matches resolved paths, which defeats symlinks; files present at session start are additionally pinned by `(dev,inode)`. A **new hardlink** created during the session to a file *not* on the pinned list can be read under an unwatched name. | The `fs.*` event of creating the link (if made by a session process) and the read under the alias path. | Inode-set refresh on watchlist-dir change events. |
| **Encrypted DNS (DoH / DoT)** | Query names are invisible inside TLS — `net.dns` events do not exist for agents using encrypted resolvers. | `net.connect` to the resolver (:443/:853) and every subsequent IP-level `net.connect`; the `alert.new_domain` rule degrades to new-*IP*. | Documented; no interception will ever be added (P7-adjacent: no payload capture). |
| **Claimed vs. resolved file paths** | On kernels/paths where the resolved-path hook is unavailable and RanA falls back to syscall-argument paths, the recorded path is what the process *asked for* (TOCTOU-racy, agent-influenceable), not kernel ground truth. | Such events carry `path_source=claimed` in-schema, so the record itself tells you which kind of truth you're holding. `rana doctor` reports which tier your kernel gets. | Fallback tier shrinks as fentry coverage grows. |

**`io_uring` network coverage by kernel:**

| Kernel | `connect` via `io_uring` | Notes |
|---|---|---|
| 5.15 (baseline) | Partial | Classic `connect()` fully covered; `IORING_OP_CONNECT` may bypass. |
| ≥ 5.18 | Improved | kprobe-multi paths tighten coverage. |
| ≥ 6.6 | Preferred | tcx flow accounting closes most of the gap. |

`rana doctor` reports your machine's exact tier and which escapes apply.

## 4. Redaction residual risk

The redaction pipeline (see `docs/REDACTION.md`) achieves ≥99% recall on a permanent corpus of 500+ seeded secret shapes (gate **G4**). The residual ≤1% is real:

- **Secrets embedded in exotic file *paths*.** A token-shaped basename is caught by the entropy pass; a low-entropy secret split across path segments could slip. Mitigated, not eliminated.
- **Novel credential formats** not yet in the structural pattern set. The entropy net catches most; misses are catalogued and drive additions. The corpus is a regression gate, so a miss found once is caught forever after.
- **What can never leak:** environment values (never captured at all) and anything already redacted (raw bytes exist only transiently in `ranad` RAM, never on disk, never in the chain).

If your threat model cannot tolerate a ≤1% path-embedded-secret risk, do not point RanA's digest scopes at directories containing such paths.

## 5. Platform gaps

- **Windows: not supported.** Not a port-in-progress — a deliberate non-goal for v1.
- **macOS records only what runs inside the guest.** There is **no native macOS capture path at all** — Apple gates native process recording behind case-by-case Endpoint Security entitlements closed to open-source distribution. An agent running natively on macOS produces **zero events**; RanA will tell you this rather than show you a plausible-looking partial timeline. Recording on macOS means running the agent inside RanA's Linux guest VM.
- **The guest must be able to run your agent.** The guest ships a base recorder plus a runtime layer (Node.js LTS, git, POSIX toolchain) — enough for OpenClaw and Claude Code, which are Node apps. Host-installed `node_modules` contain macOS-native binaries and are **not** reusable in-guest; `rana adopt openclaw` performs a guest-side install onto a persistent data volume. Project-specific toolchains (compilers, interpreters your build needs) are yours to provision in-guest; without them, a coding agent inside the guest can edit and fetch but not build.
- **macOS native-app automation is invisible.** An agent inside the guest **cannot** drive AppleScript, iMessage, or native GUI automation, and RanA therefore cannot record those effects. All shell, file, and network behavior — and OpenClaw's network-centric core — are covered.
- **virtiofs seams.** Host-side file changes do not generate inotify events in-guest (file-watchers may not fire), and projected-directory lock semantics are weaker than a local filesystem. Both affect the *agent's* behavior in-guest, not the record's integrity.
- **macOS cold-boot latency.** First `rana run` on a cold VM costs up to ~10s. On macOS ≥ 14, VM save/restore makes subsequent runs near-instant. On macOS 13, every cold start pays the boot cost.
- **cgroup v1-only hosts are unsupported.** RanA requires cgroup v2. `rana doctor` fails loudly with remediation. This is rare on kernels ≥ 5.15.

## 6. The contemporaneous-adversary caveat (the important one)

RanA's integrity guarantee is about *persisted* events. An attacker who **already has root on your machine at the moment of recording** can:

- kill `ranad`, halting capture of *future* events, or
- prevent `ranad` from starting.

RanA makes this **detectable** — a killed daemon produces a `gap` event on restart, checkpoint cadence breaks, and `rana verify` flags the boundary — but it does **not** make it *preventable*. If your adversary has contemporaneous root, RanA gives you evidence of tampering, not immunity from it.

### 6.1 The same-user adversary (read this twice)

The agents RanA records usually run **as you** — the same uid that owns the ledger and the signing key. A fully-subverted agent (the A1 adversary this tool exists for) therefore *is* an attacker with your uid, and an attacker with your uid can kill the user-level session service, read the signing key, and attempt to rewrite and re-sign the ledger.

What holds, and why:

- **History up to the compromise is pinned outside your uid.** At every checkpoint, the session service reports the chain head to `ranad`, which appends it to a **root-owned, append-only mirror** (`/var/lib/rana/heads.log`). A user-privileged attacker cannot alter that file. `rana verify --mirror` cross-checks the ledger against it: a rewritten-and-re-signed ledger no longer matches the heads recorded before the compromise.
- **Touching the recorder is itself recorded.** RanA's own data directory (ledger, key, salt) is on the built-in sensitive watchlist — an agent reading your signing key or opening the ledger for write is a first-class, alertable event, captured up to the moment the attacker suppresses capture.
- **The boundary, plainly:** for events *after* the compromise, a same-uid attacker is equivalent to the root attacker above — suppression and forgery of the *future* are detectable (mirror divergence, cadence break, gaps), not preventable.

What RanA *does* protect against, even from a later attacker of either kind: **rewriting the pinned past**. Once events are sealed, signed, and head-mirrored, they cannot be silently altered — not even with the stolen key. An attacker can stop the recording; they cannot forge a clean past.

## 7. Scope reminders (things people ask for that RanA won't do)

- No prompt/completion capture (permanent).
- No MCP wire inspection, no TLS interception, no payload capture — gateways own that lane; RanA's privacy stance forbids it.
- No fleet management, multi-user, RBAC, or SIEM export in v1.
- No cloud sync, no accounts, no telemetry.

---

*If any statement here is wrong, that is the highest-priority bug in the project.*
