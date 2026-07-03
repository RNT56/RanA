# RANA — Record an Agent
## Canonical Plan v1.1 — Chain of Custody for AI Agents

**Status:** BINDING. Decisions in §2 are commitments, not options. Changes require a versioned amendment (v1.1, v2) with a changelog entry.
**Version:** v1.2 (amendments 2026-07-03 — see `CHANGELOG.md`: v1.1 same-user-adversary custody, file-hook mechanism, escape-detection mechanics, chain/export spec fixes, macOS guest runtime reality; v1.2 post-implementation review — verify gap-summary cross-check, `rana run` svc-hosting + socket contract, robustness/P5 fixes).
**Date:** 2026-07-03
**License:** Apache-2.0
**One-liner:** RanA is the flight recorder for AI agents — a kernel-truth, tamper-evident ledger of everything your agents execute, touch, and contact, across every agent on your machine, with zero configuration.

---

## 0. Thesis

Every existing agent-safety tool is a **wall**: sandboxes (srt, bubblewrap, Landlock, microVMs) prevent, gateways (MCP firewalls) permit or deny wire traffic. Nobody holds the layer of **accountability and reversibility**: after the fact, across all agents, *what exactly happened to this machine — provably, reviewably, and eventually undoably?*

Walls have two structural gaps RanA exploits:

1. **They are per-vendor and per-mode.** Claude Code sandboxes Claude Code. Codex sandboxes Codex. OpenClaw's exec sandbox has an `elevated` bypass by design. Nothing observes *across* agents, and nothing observes what the walls themselves permitted.
2. **They answer "may it?" — never "what did it?"** Prevention without memory means every incident review starts from nothing. The Cline supply-chain compromise (Feb 2026, 5M+ users, exfiltrated npm tokens via prompt-injection chain) and the OpenClaw CIK safety evaluation (arXiv 2604.04759) both demonstrate the same lesson: personal agents fail *quietly*, and the operator finds out late or never.

RanA's answer is **kernel truth**: an eBPF collector that records every exec, write-intent file operation, and network flow attributable to an agent session, feeds it through a secrets-redaction stage, and persists it into a hash-chained, Merkle-segmented, signed ledger the user can `verify`, `export`, and browse in a local timeline UI. It sees through first-party sandboxes (they run on the same kernel), it works identically for Claude Code, Codex, OpenClaw, and any custom agent, and it costs the user one command.

**Adoption psychology (Little Snitch pattern):** shadow mode gates nothing and requires no policy. Install → run agents as usual → open the timeline → feel slightly ill → tell someone. The gated mode (transactional overlay, commit/discard) is designed now, built later, and slots into the same ledger schema.

**Tagline:** *Chain of custody for AI agents.*
**Mascot logic:** *rana* is Latin for frog. It sits on the lilypad. It sees everything. It does not interfere.

---

## 1. Principles (ranked; higher wins on conflict)

| # | Principle | Consequence |
|---|-----------|-------------|
| P1 | **Kernel truth over agent self-report.** | Events originate from eBPF hooks, never from agent logs. Agent-provided data (markers) is enrichment, labeled as such, never load-bearing for the record. |
| P2 | **Observation is inert.** | The recorder must be physically incapable of breaking the workload: no interposition, no LD_PRELOAD, no syscall blocking, no proxying in observe mode. If ranad dies, agents keep running. |
| P3 | **Secrets never persist.** | Env is never captured. All captured strings pass redaction *before* chain hashing. There is no configuration flag that disables this. An append-only tamper-evident log must never become a credential honeypot. |
| P4 | **Tamper-evidence over tamper-proofing.** | We claim exactly what the design delivers: post-persistence modification is detectable; a root-level adversary contemporaneous with recording can suppress *future* events. LIMITS.md states this in the README's second paragraph, not a footnote. |
| P5 | **Losses are loud.** | Ring-buffer drops, rate-governor sheds, daemon restarts — every gap becomes a first-class `gap` event inside the chain. The ledger never silently omits. |
| P6 | **Zero-config value in ten minutes.** | `curl -fsSL get.rana.dev | sh && rana adopt openclaw` must produce a meaningful timeline the same evening, on a machine we've never seen. |
| P7 | **Effects, not thoughts.** | RanA never records model I/O, prompts, completions, message contents, or keystrokes. We record what the agent *did to the machine*, not what it said. This is both a privacy stance and a scope weapon. |
| P8 | **Compose with walls, never rebuild them.** | Enforcement backends (srt, bubblewrap, Landlock) are integration targets for gated mode, not competitors. RanA observing an srt-wrapped agent is a documented, recommended recipe. |
| P9 | **One static binary per host role.** | No Python, no Node, no Docker requirement, no runtime deps beyond the kernel. `rana` (CLI+user service), `ranad` (privileged collector). The macOS guest image is embedded. |
| P10 | **Documented honesty is a feature.** | LIMITS.md ships at launch with the same polish as the README. Known escapes, known blind spots, known platform gaps — enumerated. In this category, candor is differentiation. |

---

## 2. Binding Decisions

| # | Decision | Rationale (compressed) |
|----|----------|------------------------|
| D1 | **Product = cross-agent flight recorder; gated (transactional) mode is Phase G, designed in v1 schema, built post-launch.** | Pinned with Jay 2026-07. Recorder-first adoption; schema carries `proposed/committed` effect states from day one so gating needs no migration. |
| D2 | **Platforms v1: Linux native + macOS via embedded Linux microVM. Windows: non-goal.** | Pinned. Native macOS process recording requires Endpoint Security entitlements Apple grants case-by-case — closed to OSS distribution. The VM is the only distributable macOS path. |
| D3 | **Language: Go ≥1.24, CGO only in the macOS host binary (vz requires it).** | Team-of-one velocity; proven personal stack (Drift); static Linux binaries. |
| D4 | **eBPF via cilium/ebpf + bpf2go, CO-RE, BTF required.** | Pure-Go loader, LTS-kernel CI upstream, amd64+arm64. No libbpf C linkage. |
| D5 | **Kernel floor: 5.15 LTS. Optional fast paths (kprobe-multi ≥5.18, tcx ≥6.6) feature-probed at start.** | 5.15 ships everywhere that matters (Ubuntu 22.04+, Debian 12+, Fedora, Arch); gives ringbuf, fentry, cgroup sock_addr, BTF. `rana doctor` reports capability tier. |
| D6 | **Attribution primitive: one cgroup v2 leaf per session** (`rana.slice/rana-<id>.scope`), created via systemd transient scope when available, raw cgroupfs fallback. cgid→session map pinned in BPF. | Reliable subtree membership for long-lived trees (OpenClaw gateway + spawned tools); in-kernel filtering keeps non-session noise out of the ringbuf entirely. |
| D7 | **Hook set v1 (amended v1.1):** `sched_process_exec/fork/exit` tracepoints (fork/exit also maintain an **in-kernel session pid-map**, updated in-program so governor shedding never degrades it); `cgroup/connect4+6` **plus `cgroup/sendmsg4+6`** (BPF_CGROUP_SOCK_ADDR — sendmsg covers unconnected-UDP `sendto`, which plain connect hooks miss) for TCP/UDP egress; fentry `unix_stream_connect` for AF_UNIX; **file ops via fentry on VFS/security-layer functions with an in-BPF resolved-path (dentry+mount) walk** (Tracee/Tetragon-proven on ≥5.15) for write-intent open, unlink, rename, mkdir, chmod, truncate — syscall tracepoints remain a fallback tier whose argument-derived paths are TOCTOU-racy and are recorded with `path_source=claimed` (resolved hooks emit `path_source=resolved`); sensitive-read matching on the **resolved** path prefix plus pinned `(dev,inode)` identity for watched files that exist at session start (defeats symlink and most hardlink dodges); `cgroup_attach_task` tracepoint filtered by the session pid-map for **cgroup-migration/escape detection**. DNS via cgroup-scoped `cgroup_skb/egress` port-53 qname parse (qname/answers only, never other payload) with userspace qname↔IP cache; **DoH/DoT is a documented blind spot** (LIMITS.md) — encrypted resolvers yield `net.connect` to the resolver, no qname. | Covers exec/file/network at event granularity that survives 10k ev/s without recording payloads; resolved-path capture is what makes file events *forensic* rather than *claimed*. `connect4/6/sendmsg4/6` is the same hook family that can *deny* — observe now, enforce in Phase G with zero re-architecture. |
| D8 | **Per-file write events record intent + metadata, never content.** Content digests (BLAKE3) computed in userspace on close-write debounce, only inside profile-declared scopes. | Kernel path stays cheap; digests give before/after evidence where it matters; P7 preserved. |
| D9 | **Sensitive-read watchlist:** in-kernel prefix match on a pinned map (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config/gcloud`, browser profile dirs, `~/.openclaw/credentials*`, user-extendable). Reads outside the list are NOT recorded. | The trifecta precursor ("agent read a credential") is the single highest-signal event class; recording *all* reads is noise and a privacy risk. |
| D10 | **Privilege split:** `ranad` (root: BPF attach, ringbuf read, redaction, no listening sockets, ships hardened systemd unit) → per-user `rana` session service (owns SQLite ledger, chain, signing key, timeline UI) over a SO_PEERCRED-authenticated unix socket. Ledger is user-owned data. | Minimal root surface; the valuable artifact (ledger) lives at user privilege; UI never runs as root. |
| D11 | **Ledger: SQLite via modernc.org/sqlite** (pure Go), WAL, single writer goroutine, group-commit ≤10ms batches. | Drift-proven; zero cgo on Linux; embeddable backup/export semantics. |
| D12 | **Chain spec (amended v1.1):** deterministic CBOR canonical event encoding → BLAKE3 leaf hash → Merkle segment (≤4096 events or 60s after the segment's first event) → segment header chains prev-segment hash → Ed25519-signed checkpoint every 64 segments **or 5 minutes with sealed-but-unsigned segments pending, whichever first**, and at `session.end`. Checkpoints form a **single ledger-wide chain** (`prev_checkpoint_hash` spans sessions), so deleting an entire session wholesale breaks the checkpoint chain and is detected — per-session chains alone cannot see whole-session removal. The tail after the last checkpoint is **unattested**: hash-linked but not yet signed; `verify` reports it as such (distinct from broken). Device key generated at first run, 0600, optional passphrase wrap. | `rana verify` is O(events) hashing, seconds for millions of events; segmenting makes multi-week OpenClaw sessions verifiable in epochs; signing binds the chain to an identity; the global checkpoint chain plus the D27 root mirror bound what any post-hoc editor can silently remove. |
| D13 | **Redaction is pre-chain and non-optional** (spec §5): env never captured; pattern set + entropy pass over argv/paths/URLs/markers; replacement tokens preserve type/length-class + per-ledger-salted CRC16 so identical secrets correlate in-ledger but leak nothing. **(Amended v1.1)** The pipeline runs at *every writer ingress*, not only in ranad: ranad redacts kernel-event strings; the session service runs the same library over markers, session metadata, and digest paths (markers never transit ranad). The enforcement is the type system — the ledger writer accepts only the `Redacted` string type, so an unredacted string cannot reach a leaf from any process by construction. | P3. Raw secrets never touch disk; hash chain never contains scrubbing-resistant material. |
| D14 | **Event flood control:** per-session token-bucket governor in ranad; sheds lowest-value classes first (fork/exit → fs metadata → never exec/connect/sensitive-read); every shed interval emits a `gap` event with counts. | P5. A pathological agent can't DoS the ledger, and can't do so *silently*. |
| D15 | **macOS: `rana` boots a Buildroot-built Linux guest** via Apple Virtualization.framework through Code-Hex/vz. **(Amended v1.1 — the guest must be able to *run real agents*, not just record:)** the guest is layered: a **base layer** (kernel w/ BTF+virtiofs+overlayfs, initramfs, ranad+guest-svc, ≤60MB, reproducible, embedded in the host binary) plus a **runtime layer** (Node.js LTS + git + coreutils toolchain — what OpenClaw and Claude Code, both Node apps, actually need; ≤150MB, reproducible, fetched once with signature check to `~/Library/Application Support/rana/`). A **persistent ext4 data volume** (host-file-backed) holds guest-side installs (e.g. OpenClaw's Linux `node_modules` — host-installed native addons are Mach-O and cannot run in-guest). Granted host dirs → one virtiofs tag each, mounted `/mnt/host/<name>`; guest agent uid fixed at 1000; ledger lives on the **host**. Control + event stream over vsock; a **vsock↔TCP port-forward proxy** re-exposes adopted services' listening ports (e.g. gateway :18789) on host localhost so existing local clients keep working. VM save/restore warm-pool where macOS ≥14; cold boot budget ≤10s. **There is no native macOS capture path**: an agent running natively on macOS produces zero kernel events (Endpoint Security entitlements are closed to OSS — D2); RanA never pretends otherwise. | Identical capture stack both platforms (the unification, not a port); the runtime layer + data volume are what make the guest *usable* by real agents rather than merely bootable; virtiofs uid/gid quirks sidestepped by never using it as rootfs and normalizing at mount; guest compromise cannot rewrite host-persisted chain (liveness may suffer, integrity doesn't — documented trust property). |
| D16 | **macOS floor: 13 (Ventura).** Save/restore feature-gated ≥14. Apple Silicon primary; Intel best-effort. | vz API coverage; AS is where the users are. |
| D17 | **Profiles are TOML packs** (match rules, digest scopes, sensitive-list extensions, marker integration, timeline lens, retention). Shipped v1: `generic`, `claude-code`, `codex`, `openclaw`. | Profiles are the product's opinion layer; everything else is mechanism. |
| D18 | **OpenClaw is the hero profile, marketed with one line.** `rana adopt openclaw` handles the whole lifecycle: systemd unit adoption into the session slice (Linux) or guest-hosted gateway (macOS: install the Linux build of the gateway onto the guest data volume, project `~/.openclaw` config/workspace via virtiofs, port-forward :18789 back to host localhost — D15), plus an optional ~100-line OpenClaw plugin that emits run-lifecycle markers ({runId, agentId, channel}) to the rana socket. Consent prompt at adopt-time, default yes. Without the plugin, causality falls back to time+process-tree clustering labeled *inferred*. **(Amended v1.1)** On macOS there is no "keep it native, degraded recording" option — native macOS processes generate no kernel events (D15), so adopt either hosts the gateway in the guest or declines with a plain explanation. *Inferred* refers only to running **without the marker plugin**, never to native-macOS operation. | Pinned with Jay: hero feature, quiet marketing — it just works. Markers turn the timeline into "conversation → consequences" without ever touching message content (P7: runId yes, message text never). |
| D19 | **Timeline UI: embedded, localhost-only, single-user.** Random port + per-launch bearer token, strict CSP, no CORS, no build-time framework — vanilla TS + lit-html bundled by esbuild at build time, custom canvas rendering for the event river. Optional read-only phone access via tsnet (Phase 5) with Tailscale identity, off by default. | One binary (P9); Jay's proven canvas/viz strength; tsnet is the Drift pattern. |
| D20 | **CLI surface v1 frozen:** `run, adopt, ps, timeline, show, tail, verify, export, gc, doctor, vm` (mac). Anything else waits. | Surface discipline; docs and tests scale with verbs. |
| D21 | **Model I/O is out of scope permanently** (P7). RanA records effects; prompts/completions are never captured, even as an option. | Privacy stance = positioning; prevents scope-creep into observability-SaaS territory. |
| D22 | **Naming:** binary `rana`, privileged daemon `ranad`, project "RanA — Record an Agent". Known collisions (dormant GPL multi-agent simulator `sojoe02/RANA`; NVlabs research repo) assessed low-risk; launch tasks: secure `rana.dev` or `getrana.dev`, GitHub org, crates/npm squat check. | Pinned with Jay. |
| D23 | **License Apache-2.0; DCO sign-off; no CLA.** Reproducible builds + cosign-signed release artifacts + SBOM from v0.1. | Permissive-license position is open (nearest OSS neighbor chose AGPL); supply-chain posture is table stakes for a security tool. |
| D24 | **Telemetry: none. Ever. No phone-home, no update check by default** (`rana doctor --check-update` is explicit and documented). | Non-negotiable for the audience; also one less attack surface. |
| D25 | **Success gates are binding** (§8): perf gates must be green before any phase after their owning phase begins; launch blocked on all gates + LIMITS.md complete. | Mechanical enforcement over aspiration. |
| D26 | **Windows, fleet management, cloud sync, MCP wire inspection, TLS interception, payload capture: rejected for v1 and not designed for.** | §10 Non-goals; each is a different product. |
| D27 | **(New in v1.1) Same-user-adversary custody.** The primary adversary (A1, a prompt-injected agent) runs *as the ledger owner's uid* — the very uid that owns the ledger and signing key under D10. Therefore: (a) `ranad` keeps a **root-owned, append-only mirror of checkpoint heads** (`/var/lib/rana/heads.log`; the session service reports each checkpoint head over the existing socket; ~40 bytes per checkpoint). A user-privileged attacker can rewrite and re-sign the user-owned ledger, but every head reported *before* the compromise is pinned at root — `rana verify --mirror` detects the rewrite. (b) RanA's **own data directory (ledger, key, salt) is on the built-in sensitive-read/write watchlist**, so a recorded agent touching the recorder is itself a first-class, alertable event up to the moment of suppression. (c) LIMITS.md states the boundary plainly: an attacker with your uid is, for *future* events, equivalent to the root attacker of P4 — detectable, not preventable. | Without this, the flight recorder's tape is writable by the pilot it records, and `verify` would bless a forged history signed with the legitimately-stolen key. The mirror costs nothing and converts "silently rewritable" into "detectable up to compromise time." |

---

## 3. Threat Model & Trust Properties

### 3.1 Adversaries in scope

| ID | Adversary | Representative incident class |
|----|-----------|-------------------------------|
| A1 | **Prompt-injected agent** — a well-behaved agent binary driven by hostile instructions (poisoned webpage, email, tool description, ClawHub skill). | Cline Feb-2026 chain; OpenClaw ClawHavoc skill wave; GitHub-MCP private-repo exfil pattern. |
| A2 | **Malicious tool/dependency** — an MCP server, plugin, or npm package the agent legitimately invokes. | Supply-chain packages spawning exfil subprocesses. |
| A3 | **Over-permissioned automation** — no attacker at all; a cron'd agent with broad grants does something expensive/destructive and nobody notices for days. | "Why is my home directory different"; surprise API spend; quietly rewritten dotfiles. |
| A4 | **Post-incident uncertainty** — the operator's own inability to reconstruct events after A1–A3. | Every incident review that currently starts from zero. |

### 3.2 Explicitly out of scope

- **The user as adversary** (no DRM, no anti-forensics resistance against the ledger owner — they hold the key).
- **Kernel-level malware / rootkits.** If the kernel lies, eBPF lies. RanA assumes an honest kernel.
- **A root-privileged attacker acting *during* recording** can kill ranad and suppress *future* events. Chain property: this is *detectable* (gap events, checkpoint cadence break, `verify` boundary) but not *preventable*. → P4, LIMITS.md.
- **An attacker with the ledger owner's uid acting *during or after* recording** (which is what a fully-subverted A1 agent *is*) can kill the user session service, read the signing key, and rewrite + re-sign the user-owned ledger. Mitigated, not prevented, by D27: pre-compromise history is pinned in the root-owned head mirror and the tampering itself is recorded until suppressed. For future events, same-uid ≈ root. → P4, D27, LIMITS.md.
- **Model-layer attacks** (jailbreaks as such). RanA sees their *effects* only.

### 3.3 Trust properties (the claims we may make in the README)

1. **Completeness within scope:** every exec, write-intent fs op, egress connect, and sensitive-read by a process inside a recorded session's cgroup is captured or accounted for by an explicit `gap` event. (Escape caveat: §6.4.)
2. **Integrity after persistence:** any post-hoc modification, deletion, or reordering of persisted events is detected by `rana verify` (Merkle segment + chain + signed checkpoints).
3. **Secret-freedom:** no environment values ever; captured strings are redacted before hashing (D13). Residual risk: secrets embedded in *file paths* of exotic shape — mitigated by the entropy pass, documented in LIMITS.md.
4. **Inertness:** observe mode cannot alter agent behavior or availability (P2). No hook in D7 can block, delay meaningfully, or modify a syscall.
5. **Guest-compromise containment (macOS):** an agent that fully owns the guest VM can forge or suppress its own *future* events but cannot rewrite the host-persisted chain.

### 3.4 RanA's own attack surface (and its minimization)

| Surface | Mitigation |
|---|---|
| ranad (root) | No listening TCP; single unix socket, SO_PEERCRED-gated to the owning uid; systemd hardening (`ProtectSystem=strict`, `ProtectHome=read-only` + explicit socket path, `NoNewPrivileges`, `MemoryDenyWriteExecute`, caps limited to `CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE` on ≥5.11, documented root fallback below); no config parsing of untrusted input beyond validated watchlist paths. |
| Timeline UI | 127.0.0.1 bind, random port, per-launch bearer token, strict CSP, no CORS, no cookies. tsnet exposure (Phase 5) authenticates via tailnet identity, read-only endpoints only. |
| Ledger file | User-owned 0600; signing key 0600 with optional passphrase; `export` output carries proofs, not the key. Same-uid tampering bounded by the D27 root-owned checkpoint-head mirror; RanA's own datadir is on the built-in sensitive watchlist. |
| Marker socket | Per-session random token issued at adopt/run time; markers are enrichment (P1) — a forged marker can mislabel, never fabricate kernel events; marker events carry `origin=enrichment` in-schema. |
| Supply chain | D23: reproducible builds, cosign, SBOM, pinned deps, no postinstall scripts anywhere. |

---

## 4. Architecture

### 4.1 Component map

```
┌────────────────────────── host (Linux, or macOS guest VM) ─────────────────────────┐
│                                                                                    │
│  agent processes ──── cgroup: rana.slice/rana-<sess>.scope                         │
│        │                                                                           │
│  [kernel] eBPF programs (D7) ──ringbuf──▶ ranad (root)                             │
│                                            ├─ decode + enrich (paths, cgid→sess)   │
│                                            ├─ REDACT (D13, §5)                     │
│                                            ├─ rate governor (D14)                  │
│                                            └─ unix socket ──▶ rana session svc     │
│                                                               (user)               │
│                                                                ├─ ledger (SQLite)  │
│                                                                ├─ chain/sign (D12) │
│                                                                ├─ digest worker    │
│                                                                ├─ marker ingest    │
│                                                                └─ timeline UI      │
└────────────────────────────────────────────────────────────────────────────────────┘
macOS host: rana (vz) ── vsock ── guest ranad/rana-svc event stream ──▶ HOST ledger
```

### 4.2 Session lifecycle

1. `rana run --profile openclaw -- openclaw gateway` → transient scope created (systemd D-Bus when present; cgroupfs mkdir fallback), child exec'd inside it, `session.start` written, cgid pinned into the BPF filter map.
2. `rana adopt openclaw` (daemon case) → generates a systemd drop-in placing the unit under `rana.slice` + restarts it (with confirmation); launchd path on macOS delegates to the VM flow (§6.3). `--pid N` adoption migrates a live tree with documented caveats (threads migrate; already-open fds predate the record — noted in session metadata).
3. Descendants are session members by cgroup inheritance. Escape detection **(mechanics amended v1.1 — the old wording was unimplementable under in-kernel cgid filtering, which never surfaces foreign-cgroup execs):** the in-kernel session **pid-map** (maintained by the fork/exit programs, D7) makes a session member visible even after it leaves the cgroup — a `cgroup_attach_task` migration of an in-session pid to a foreign cgroup, or an exec by a pid-map member whose cgid is no longer in the session map, raises `alert.cgroup_escape{pid, from, to}`. **Delegated spawns** (`systemd-run`, D-Bus activation) re-parent to PID 1 and are *not* attributable — RanA sees only the precursors (the in-session exec of `systemd-run`/`busctl`, the `unix.connect` to the bus socket) and raises `alert.escape_precursor` on them; the seam is observed honestly rather than pretended away (§6.4, LIMITS.md).
4. Session ends on scope-empty or explicit `rana stop`; `session.end` seals the final segment.

### 4.3 Event taxonomy & schema (v1, frozen fields ⊕ extensible attrs)

Canonical encoding: deterministic CBOR; `data` keys sorted; times as (CLOCK_MONOTONIC ns, CLOCK_REALTIME ns) pairs captured in-kernel.

| Type | Emitted by | Key fields |
|---|---|---|
| `session.start / session.end` | svc | profile, argv⟦R⟧, host fingerprint (os, kernel, rana version, boot_id), adopt-mode caveats |
| `proc.exec` | eBPF | pid, ppid, cgid, comm, exe_path, argv⟦R⟧ (truncated 8KB), cwd, uid; exe BLAKE3 backfilled lazily by svc |
| `proc.fork / proc.exit` | eBPF | lineage / exit code + rusage summary |
| `fs.write_open` | eBPF | resolved path, `path_source` (resolved \| claimed — D7), flags (O_WRONLY/O_RDWR/O_CREAT/O_TRUNC), mode |
| `fs.unlink / fs.rename / fs.mkdir / fs.chmod / fs.truncate` | eBPF | path(s), `path_source`, mode |
| `fs.settle` | svc digest worker | path, prev_digest?, new_digest, size Δ, mtime — debounced close-write, **profile scopes only** (D8) |
| `fs.sensitive_read` | eBPF | path, matched rule id (D9) |
| `net.connect` | eBPF (cgroup/connect4·6 + sendmsg4·6 for unconnected UDP) | proto, daddr, dport, pid |
| `net.dns` | ranad DNS observer (cgroup_skb/egress port-53 parse) | qname, answers[], ttl — joined to subsequent connects by (addr, window); absent under DoH/DoT (LIMITS.md) |
| `net.flow_close` | eBPF (inet_sock_set_state) | bytes_tx/rx, duration |
| `unix.connect` | eBPF fentry | socket path (docker.sock, ssh-agent, dbus → each also on the sensitive list) |
| `marker.*` | profile integrations | origin=enrichment, e.g. `marker.openclaw.run {runId, agentId, channel}` — never message content (P7) |
| `alert.*` | svc rules | `new_domain`, `sensitive_read`, `cgroup_escape`, `escape_precursor`, `burst` (Phase 5) |
| `gap` | ranad governor | class shed counts, interval, reason (ringbuf_full / governor / daemon_restart) |

**Gated-mode forward-compat (D1):** every effect-class event carries `state: observed` in v1; Phase G introduces `proposed → committed|discarded` without schema migration.

### 4.4 Ledger & chain mechanics (spec level)

- Tables: `sessions`, `events(rowid, session, seg, ts_mono, ts_wall, type, pid, data BLOB)`, `segments(id, session, first_rowid, last_rowid, merkle_root, prev_hash, sealed_at)`, `checkpoints(seg_range, chain_head, prev_checkpoint_hash, sig, signed_at)`, `paths(id, canonical)` interning table, `digests`.
- Writer: single goroutine, prepared statements, batched tx (≤10ms or 512 events), `synchronous=NORMAL`, WAL autocheckpoint tuned; **perf gate G1 owns this path** (§8).
- Sealing: segment closes at 4096 events or 60s after its first event → Merkle root over leaf hashes → header (root, prev, counts, gap summary) hashed into chain. Checkpoint every 64 segments or 5 minutes with sealed segments pending (D12): Ed25519 over chain head + wall time; checkpoints chain ledger-wide via `prev_checkpoint_hash`, and each head is mirrored into ranad's root-owned `heads.log` (D27).
- `rana verify [--session S]`: streams events, recomputes leaves/roots/chain/sigs + checkpoint-chain continuity; `--mirror` cross-checks against the D27 root mirror; exit codes distinguish *broken chain* from *gap-bearing but honest* history, and report an *unattested tail* (sealed after the last checkpoint) distinctly.
- `rana export`: **`events.cbor` (canonical bytes — the authoritative verification artifact)** + `events.jsonl` (human-readable convenience; JSON cannot round-trip int64 nanosecond timestamps, so JSONL is never hashed) + `manifest.json` (segment proofs, checkpoint sigs, pubkey) — a third party can verify an export without RanA installed (verifier spec is ~a page; ships in docs/TRUST.md).
- Retention: profile TTLs; `rana gc` compacts sealed segments to zstd cold archives; chain continuity preserved by checkpoint stubs referencing archived roots.


---

## 5. Redaction Specification (D13 — normative)

Redaction is a pipeline stage in ranad between decode and the socket send. It is not configurable off (P3). It runs on: `argv`, file paths, DNS qnames, URLs inside markers, and any string field. It never runs on env because env is never captured.

**Stage 1 — Env exclusion.** eBPF never reads `envp`. ranad never reads `/proc/<pid>/environ`. There is no code path that captures environment values. (Env *variable names* may appear in a future opt-in, never values.)

**Stage 2 — Structural pattern set** (ordered, extensible via profile, additive only — profiles cannot *remove* built-ins):
- Cloud/API keys: AWS (`AKIA|ASIA[0-9A-Z]{16}`), GCP, Azure, `sk-`/`sk-ant-`/OpenAI-style, GitHub (`gh[posru]_`), Slack (`xox[baprs]-`), Stripe (`[sr]k_live_`), JWTs (`eyJ...\.eyJ...`), Google API (`AIza`), private-key PEM headers.
- Generic secrets: `password=`, `token=`, `authorization: bearer`, connection strings with inline creds (`proto://user:pass@`), `.env`-style `KEY=<highentropy>`.
- Credential-file path bodies (keep the *fact* `~/.ssh/id_ed25519` was touched, redact any embedded token-shaped basename).

**Stage 3 — Entropy pass.** Tokens length ≥20 with Shannon entropy ≥4.0 bits/char and non-dictionary → redacted. Base64/hex-looking blobs ≥32 chars → redacted. Threshold tunable *up* (stricter) per profile, never down.

**Stage 4 — Typed replacement.** Redacted span → `⟦R:<class>:<lenclass>:<crc>⟧` where class ∈ {awskey, jwt, bearer, entropy, pem, …}, lenclass bucketed (s/m/l/xl), crc = CRC16 of (value ‖ per-ledger-random-salt). Two identical secrets in one ledger share a crc (correlation preserved); the crc is useless across ledgers and non-invertible. The salt lives with the ledger, never in exports.

**Ordering guarantee:** redaction completes *before* the event is handed to the writer, therefore before it is hashed into any leaf. Raw secret bytes exist only transiently in ranad RAM and are never written to disk, never sent over the socket, never hashed.

**Test obligation (owned by G4):** a red-team corpus of 500+ seeded secret shapes must achieve ≥99% redaction with the built-in set; misses are catalogued and drive additions; the corpus is a permanent regression gate.

---

## 6. Platform Engineering

### 6.1 Linux collector

- Build: `bpf2go` compiles CO-RE objects for amd64+arm64, embedded via `go:embed`; no clang at runtime.
- Attach order & liveness: programs pinned under `/sys/fs/bpf/rana/`; ranad re-attaches idempotently on restart and immediately emits `gap{reason:daemon_restart}` covering the dark window.
- Feature tiers (probed at start, surfaced by `rana doctor`):
  - **Baseline (5.15):** tracepoints, ringbuf, cgroup/connect4·6, fentry, sensitive-read map. Full product.
  - **Enhanced (≥5.18):** kprobe-multi for cheaper fs attach.
  - **Preferred (≥6.6):** tcx flow accounting.
- cgroup driver: systemd transient scope via private D-Bus when systemd present; raw cgroup v2 fs (`cgroup.procs` write + `cgroup.subtree_control`) fallback for non-systemd (containers, minimal distros). Hybrid-hierarchy (cgroup v1-only) hosts → `doctor` fails loudly with remediation (rare on ≥5.15 targets).
- Root-capability fallback: on kernels/distros where `CAP_BPF`+`CAP_PERFMON` are insufficient for a given attach, ranad documents and (only if the operator opts in) runs that attach with fuller privilege, logging exactly which program needed it. No silent privilege escalation.

### 6.2 macOS collector via microVM

- **Guest image (layered, D15):** *base layer* — Buildroot, custom-configured Linux (BTF on, virtiofs, overlayfs, the D7 hooks' tracepoints/BTF), minimal initramfs, `ranad`+`rana-svc` guest builds baked in; ≤60MB, reproducible, checksum-pinned, embedded in the `rana` binary. *Runtime layer* — Node.js LTS, git, and a POSIX toolchain (what real agents need to actually run); ≤150MB, reproducible, fetched once to `~/Library/Application Support/rana/` with signature check. *Data volume* — persistent host-file-backed ext4 for guest-side installs (host `node_modules` contain Mach-O native addons and cannot be reused in-guest).
- **Service re-exposure:** a vsock↔TCP proxy forwards adopted services' listening ports (gateway :18789) to host localhost, so existing local clients work unchanged.
- **Runtime:** Code-Hex/vz/v3 (Apple Virtualization.framework). VZ requires CGO + the `com.apple.security.virtualization` entitlement + a signed binary → release builds are codesigned; `docs/MACOS.md` covers the self-signing path for source builds.
- **Filesystem projection:** each granted host dir → its own `VZVirtioFileSystemDeviceConfiguration` tag, mounted read-write at `/mnt/host/<name>` in-guest (never as rootfs — sidesteps the documented virtiofs uid/gid rootfs breakage). Guest agent uid pinned 1000; a mount-time normalization layer maps ownership so tools behave. Path events translate `/mnt/host/<name>/...` → host path in the timeline.
- **Control/data plane:** vsock (vz routes it via the framework; Code-Hex/vz exposes it as `net.Conn`). Guest event stream → host `rana`; **host writes the ledger** (D15 integrity property).
- **Boot budget:** cold ≤10s; on macOS ≥14, `SaveMachineStateToURL`/restore warm-pool makes `rana run` feel instant. Budget is **perf gate G3**.
- **Limitations (LIMITS.md, stated plainly):** an agent inside the guest cannot drive native macOS apps (AppleScript, iMessage, native GUI automation); a *natively-running* macOS agent is **not recorded at all** (no ES entitlement path — D2/D15); virtiofs does not deliver inotify events for host-side changes and file-lock semantics need verification (spike S0.2); project toolchains beyond the runtime layer are the user's to provision in-guest. OpenClaw's network-centric core and all shell/file/network agent behavior are covered.

### 6.3 OpenClaw hero integration (D18)

Two cooperating pieces, both optional-to-max but on by default:

1. **`rana adopt openclaw`** — detects an existing OpenClaw install (`~/.openclaw/openclaw.json`, running gateway on :18789), and:
   - *Linux:* writes a systemd drop-in slotting the gateway unit into `rana.slice`, confirms, restarts. Descendants (spawned sub-agents, exec tool children, MCP servers) inherit the session cgroup automatically — this is why cross-agent works: OpenClaw's own fan-out becomes RanA's tree for free.
   - *macOS:* installs the Linux build of the gateway onto the guest data volume (guest-side `npm install` on first adopt), projects `~/.openclaw` config/workspace via virtiofs, port-forwards :18789 back to host localhost, and supervises the guest-hosted gateway. If the user declines, adopt exits with a plain statement that a native gateway cannot be recorded on macOS (D15/D18) — there is no degraded native mode to mislead them with.
2. **Optional OpenClaw plugin (~100 LOC, `api.registerTool`-style lifecycle hooks)** — emits `marker.openclaw.run{runId, agentId, channel, ts}` at run start/end to the rana marker socket. This is what turns the raw event river into **"inbound message → these execs → these egress connects → this file changed."** It transmits *identifiers and lifecycle only* — never prompt or message content (P7, P1: markers are enrichment).

**Marketing line (the entire pitch):** *Already running OpenClaw? `rana adopt openclaw`. Open the timeline. That's it.*
Everything above is what makes that line true; the README says the line and links to depth.

### 6.4 The escape honesty (P4, P10, LIMITS.md)

cgroup attribution has known escapes we **surface** rather than hide:
- **Self-migration / exec-after-migration:** detected via the session pid-map + `cgroup_attach_task` (§4.2.3) → `alert.cgroup_escape`.
- **Delegated spawns** (`systemd-run`, D-Bus activation): the spawned unit re-parents to PID 1 and is *not attributable*; RanA emits `alert.escape_precursor` on the observable precursors (in-session exec of the delegation tool, `unix.connect` to the bus socket). The consequence is missed; the request is not.
- **Sensitive-watchlist dodges:** symlinks are defeated by resolved-path matching (D7); pre-existing **hardlinks** from unwatched paths to watched inodes are caught only for files pinned by `(dev,inode)` at session start — new hardlinks to unlisted files are a documented residual.
- setuid transitions, direct-syscall network via `io_uring` sockets (partial coverage on baseline; `io_uring` connect paths enumerated in LIMITS.md with the kernel versions where the hook covers them), and `LD_PRELOAD`-based syscall avoidance for *file* ops (network still caught at the cgroup sock layer).
- **Encrypted DNS (DoH/DoT):** qnames are invisible; only the resolver `net.connect` and subsequent IP connects are recorded.
Every one of these is enumerated in LIMITS.md with: what's missed, why, what partial signal RanA still emits, and the roadmap item that closes it. **This candor is the moat** — a security tool that lies about coverage is worse than none.


---

## 7. Phase Roadmap

Each phase lists **Goal / Deliverables / Exit criteria**. Strict TDD throughout (Jay's standing workflow): kernel programs get userspace harness tests via the cilium/ebpf test rig + a golden-trace corpus; the ledger/chain/redaction layers are pure-Go and unit-tested to high coverage; each phase ends green or the next doesn't start (D25).

### Phase 0 — De-risk spikes (kill-risk order)
**Goal:** prove the four load-bearing bets before committing architecture.
- **S0.1** eBPF exec+connect capture of a live Claude Code session, filtered by cgroup, events decoded in Go — **plus resolved-path file-open capture via fentry + in-BPF dentry walk on a 5.15 kernel** (v1.1: this is now the load-bearing file mechanism, so it de-risks here). *Kills: does kernel-truth cross-agent capture actually work on a real agent?*
- **S0.2** vz microVM boot + virtiofs projection + identical eBPF capture in-guest, host receives events over vsock — **plus a real Node-based agent actually running in-guest, virtiofs lock/inotify behavior checked, and a host↔guest port-forward** (v1.1). *Kills: is the macOS path real — including* running *agents, not just booting?*
- **S0.3** Ledger write path at **10k events/s sustained** on an M-series laptop and a mid Linux box, WAL, group-commit, no loss. *Kills: does the ledger keep up with a busy agent?*
- **S0.4** OpenClaw smoke: adopt a real gateway into a slice, drive a channel message, confirm the tree (gateway → sub-agent → exec → egress) shows up attributed, with plugin markers labeling causality. *Kills: is the hero experience achievable?*

**Exit:** all four green with written spike reports; any red → architecture amendment before Phase 1. Perf numbers from S0.3 seed gate G1.

### Phase 1 — Linux recorder core (MVP-internal)
**Goal:** end-to-end record → ledger → verify on Linux, one agent.
**Deliverables:** ranad with D7 hook set (baseline tier), cgid→session filter map, ringbuf decode, redaction pipeline (§5) with initial corpus, SQLite ledger + chain + Ed25519 checkpoints, `rana run/ps/verify/show`, privilege split (D10) + hardened unit.
**Exit:** record a full `claude-code` session; `verify` passes; kill -9 ranad mid-session → restart → `gap` present, chain intact; **G1 (10k ev/s), G4 (≥99% redaction), G5 (verify integrity) green.**

### Phase 2 — Timeline UI
**Goal:** the wow artifact.
**Deliverables:** embedded localhost UI (D19), canvas "event river" (lanes: process tree / filesystem / network; time x-axis; sensitive-read + new-domain markers pop), session picker, `rana show <id>` deep view, live `rana tail`. Causality rendering from markers + process tree.
**Exit:** a non-author, handed only the binary, records an agent and correctly narrates what it did from the timeline in <5 min (usability gate G6). **G2 (UI overhead) green.**

### Phase 3 — macOS via microVM
**Goal:** platform parity through the guest.
**Deliverables:** Buildroot guest image (base + runtime layers, reproducible), persistent guest data volume, `rana vm` lifecycle, virtiofs projection + path translation, vsock event stream to host ledger, vsock↔TCP port-forward proxy, codesigned release + self-sign docs, warm-pool on ≥14.
**Exit:** a real `claude-code` session **runs in-guest on the runtime layer** against a virtiofs-projected workspace and is captured with the same event types as Linux (translated paths); **G3 (≤10s cold boot, warm instant) green**; guest-compromise integrity property demonstrated (corrupt guest → host chain still verifies).

### Phase 4 — Profiles & the OpenClaw hero
**Goal:** ship the opinion layer and the headline.
**Deliverables:** profile engine (TOML, D17), `generic/claude-code/codex/openclaw` packs, `rana adopt` (systemd drop-in + launchd/guest paths), the OpenClaw marker plugin, digest worker (D8) scoped by profile, sensitive-list extension mechanism, `net.dns` join, `net.flow_close` accounting.
**Exit:** `rana adopt openclaw` on a fresh machine → timeline reads "conversation → consequences"; cross-agent demo (Claude Code *and* OpenClaw simultaneously, one timeline) works; retention/`gc` functional.

### Phase 5 — Alerts, export, remote view, polish → **v1.0 launch**
**Goal:** ship.
**Deliverables:** `alert.*` rules (new-domain, sensitive-read, burst) with local desktop notification; `rana export` + standalone verifier spec (docs/TRUST.md); optional tsnet read-only phone timeline (off by default); `rana doctor` full capability report; `docs/` complete; **LIMITS.md complete and honest (launch blocker)**; reproducible-build + cosign + SBOM pipeline; install one-liner; screencast.
**Exit:** all §8 gates green; LIMITS.md reviewed; the two hero demos (rm -rf-in-overlay preview *narrated from timeline*; poisoned-page → `~/.ssh` read → desktop alert) reproduce from a clean install.

### Phase G — Gated / transactional mode (post-1.0, pre-designed)
**Goal:** the airlock — merge-requests for your filesystem.
**Design already bound into v1 schema (D1):** overlay writes via OverlayFS (Linux) / guest-overlay (macOS) so agent writes land in an upper layer; `net.connect` denial reuses the *same* cgroup/connect hook family already attached for observation (observe→enforce is a mode flip, not a rewrite); `rana diff <session>` shows *everything* changed (not just git-tracked); `rana commit`/`rana discard`. Enforcement composes with srt/bubblewrap (P8) rather than replacing them.
**Not in v1; no v1 code assumes its absence blocks anything.**

---

## 8. Success Gates (binding — D25)

| Gate | Metric | Threshold | Owning phase | Blocks |
|------|--------|-----------|--------------|--------|
| **G1** | Ledger sustained write | ≥10k events/s, zero loss, p99 commit <15ms, laptop-class | 1 | all later phases |
| **G2** | UI overhead | timeline open + live tail adds <3% CPU to a recorded session; no event backpressure | 2 | launch |
| **G3** | macOS boot | cold ≤10s; warm (≥14) ≤1s to recording | 3 | launch (mac) |
| **G4** | Redaction recall | ≥99% on the seeded-secret corpus (500+); zero env values ever captured | 1 | all later phases |
| **G5** | Chain integrity | `verify` detects 100% of a mutation test-suite (edit/delete/reorder/re-sign); distinguishes gap-honest from broken | 1 | all later phases |
| **G6** | Cold usability | fresh user → meaningful timeline in <10 min; narrates agent behavior in <5 min | 2/4 | launch |
| **G7** | Inertness | recorded vs unrecorded agent run: no behavioral change; wall-time overhead <2%; zero agent failures attributable to RanA across the test matrix | 1 | launch |
| **G8** | Supply chain | reproducible build verified on 2 machines; release artifacts cosign-signed; SBOM present | 5 | launch |

Perf/security gates (G1, G4, G5, G7) are **regression gates** in CI from the phase they land — a later commit that breaks them fails the build.

---

## 9. Repository & Deliverable Layout

```
rana/
├── README.md                 # thesis + the OpenClaw one-liner + 90s demo gif; LIMITS in ¶2
├── LIMITS.md                 # launch blocker: escapes, blind spots, platform gaps, trust properties
├── docs/
│   ├── ARCHITECTURE.md       # §4 expanded
│   ├── THREAT-MODEL.md       # §3 expanded
│   ├── TRUST.md              # chain spec + standalone export-verifier spec (§4.4)
│   ├── REDACTION.md          # §5 normative + corpus method
│   ├── PROFILES.md           # authoring guide
│   ├── MACOS.md              # entitlements, self-signing, guest image build/verify
│   ├── OPENCLAW.md           # adopt flow + plugin install + causality explainer
│   └── SECURITY.md           # disclosure policy, ranad surface, hardening rationale
├── CHANGELOG.md              # Keep-a-Changelog; plan amendments referenced
├── CONTRIBUTING.md           # DCO, no CLA, build, test rig
├── cmd/rana/                 # CLI + user session service + UI host (Linux static; macOS CGO+vz)
├── cmd/ranad/                # privileged collector (Linux static)
├── internal/
│   ├── bpf/                  # *.c CO-RE sources + bpf2go generated + harness tests
│   ├── collector/            # decode, enrich, governor
│   ├── redact/               # §5 pipeline + corpus tests
│   ├── ledger/               # SQLite, writer, chain, sign, verify, export, gc
│   ├── session/              # cgroup drivers (systemd + raw), lifecycle, adopt
│   ├── profile/              # TOML engine + embedded packs
│   ├── vm/                   # macOS: vz lifecycle, virtiofs, vsock, path xlate
│   └── ui/                   # esbuild-bundled vanilla TS canvas timeline
├── guest/                    # Buildroot config, kernel config, initramfs, reproducible build
├── profiles/                 # generic, claude-code, codex, openclaw (+ openclaw plugin)
├── test/
│   ├── golden-traces/        # recorded agent sessions → deterministic verify fixtures
│   ├── redaction-corpus/     # 500+ seeded secrets (G4 regression)
│   ├── chain-mutations/      # G5 tamper suite
│   └── e2e/                  # adopt→record→verify→export per platform
├── .github/workflows/        # multi-kernel CI (LTS matrix), macOS runner, reproducible+cosign+SBOM
└── install/                  # get.rana.dev script, systemd unit, launchd plist, packages
```

**Canonical artifacts to generate alongside this plan** (Jay's usual pack): `README.md`, `LIMITS.md`, `docs/ARCHITECTURE.md`, `docs/TRUST.md`, `docs/REDACTION.md`, the four profile TOMLs, the OpenClaw plugin skeleton, `CLAUDE.md` (agent-execution rules encoding P1–P10 + the gates), and the Phase-0 spike specs as runnable task files.

---

## 10. Non-Goals (v1) — D26

Rejected deliberately; each is a *different product* and listing them protects scope:
- **Windows.** (Restricted-token model exists in srt; out of scope here.)
- **MCP wire inspection / TLS interception / payload capture.** Gateways own that lane; P7 forbids it anyway.
- **Model I/O capture** (prompts/completions/keystrokes) — permanently (D21).
- **Fleet/team management, multi-user, RBAC, SIEM export, compliance report generation.** Enterprise governance is the gateways' turf.
- **Cloud sync / hosted backend / accounts.** Local-first, no telemetry (D24).
- **Being a wall in v1.** Enforcement is Phase G and composes with existing walls, never a v1 claim.
- **General eBPF observability** (it's not Falco/Tetragon; scope is *agent effects*, cgroup-bound, not host-wide security monitoring).

---

## 11. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| First-party vendors add cross-agent recording | Low | High | Structural: each vendor instruments *itself*; cross-agent + effect-level + tamper-evident + your-key is the moat (P1/P8). Ship fast, own the OpenClaw relationship. |
| eBPF portability pain across distros/kernels | Med | Med | CO-RE + BTF + LTS-matrix CI + tiered feature probing + `doctor`; 5.15 floor cuts the long tail (D5). |
| macOS guest UX feels heavy | Med | High | Warm-pool restore (G3); embed the base image; make `rana run` feel instant or the mac story suffers — hence G3 is a launch blocker. |
| macOS guest can't *run* real agents (runtime/toolchain gap) | Med | **Critical (mac)** | D15 runtime layer (Node LTS + git) covers OpenClaw and Claude Code, the two agents that matter; persistent data volume for guest-side installs; S0.2 spike now requires a real agent running in-guest before Phase 1 commits the architecture. Project-specific toolchains remain user-provisioned and documented in LIMITS.md. |
| Same-uid agent tampers with the user-owned ledger/key | Med | Critical | D27: root-owned checkpoint-head mirror in ranad; own-datadir on the sensitive watchlist; `verify --mirror`; LIMITS.md states the boundary. |
| Redaction misses a secret → honeypot | Low | Critical | Pre-chain non-optional pipeline (§5), entropy net, permanent 99% corpus gate (G4), env never captured at all. |
| Perf: busy agent DoSes the ledger | Med | Med | Token-bucket governor sheds by value + loud `gap` (D14); G1 regression-gated. |
| Name collision (RANA) | Low | Low | Dormant/niche prior uses; secure domain+org early (D22). |
| Scope creep toward observability-SaaS | Med | Med | §10 + P7 + D21 as hard walls; "effects not thoughts" kills most feature requests on contact. |
| Root daemon becomes the vulnerability | Low | Critical | Minimal caps, no listening sockets, SO_PEERCRED socket, systemd hardening, no untrusted parsing, SECURITY.md + disclosure policy (§3.4). |
| Guest VM compromise (macOS) | Low | Med | Host writes ledger; guest can suppress own future events, not rewrite history — documented trust property (D15). |

---

## 12. What "done" feels like

A developer in Berlin installs `rana` with one command. That evening they run `rana adopt openclaw` and keep working. Next morning they open the timeline and *see*, for the first time, the actual shape of what their assistant has been doing all night: which repos it touched, the one time it read `~/.ssh` after reading a sketchy webpage (with a desktop alert they'd already gotten), every domain it phoned. They run `rana verify` and the chain holds. They export a session, hand it to a colleague, and the colleague verifies it without installing anything.

Then they flip on gated mode, and the next `rm -rf` an agent tries lands in an overlay they review and discard — the good changes committed, the machine untouched.

Nothing was blocked that shouldn't have been. Nothing happened that wasn't recorded. Nothing left that wasn't seen. And every byte of proof belongs to them.

*Chain of custody for AI agents.*
