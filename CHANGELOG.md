# Changelog

All notable changes to RanA and its binding plan. Format: [Keep a Changelog](https://keepachangelog.com/). Plan amendments are versioned per the plan's own rule (§Status).

## [Plan v1.1] — 2026-07-03

Pre-code amendment: an end-to-end design review found one threat-model hole, one unimplementable mechanism, two verification-breaking spec bugs, and an under-engineered macOS story. All resolved before Phase 0 begins. No code exists yet, so nothing migrates.

### Added
- **D27 — same-user-adversary custody.** The A1 adversary (prompt-injected agent) runs as the ledger owner's uid, which owns the ledger *and* the signing key — it could rewrite history and re-sign it, and `verify` would pass. Now: `ranad` keeps a root-owned append-only mirror of checkpoint heads (`/var/lib/rana/heads.log`, reported by the session service at each checkpoint); `rana verify --mirror` cross-checks; RanA's own data directory joins the built-in sensitive watchlist; LIMITS.md states the same-uid boundary plainly (for future events, same-uid ≈ root).
- **Global checkpoint chain** (D12/TRUST): checkpoints carry `prev_checkpoint_hash` across the whole ledger, making *whole-session deletion* detectable — per-session chains alone could not see it.
- **Checkpoint time bound** (D12): checkpoint every 64 segments **or 5 minutes** with sealed segments pending; the post-checkpoint tail is defined as *unattested* (hash-linked, unsigned) and `verify` reports it distinctly.
- **`cgroup/sendmsg4+6` hooks** (D7): unconnected-UDP egress (`sendto` without `connect`) was invisible to the connect-only hook set.
- **`alert.escape_precursor` event** and in-kernel session pid-map + `cgroup_attach_task` migration detection (D7/§4.2.3).
- **macOS guest runtime layer** (D15): Node.js LTS + git + toolchain layer (≤150MB, fetched-once, signature-checked), persistent ext4 data volume for guest-side installs, and a vsock↔TCP port-forward proxy re-exposing adopted services (gateway :18789) on host localhost.
- **DoH/DoT blind spot** documented (D7/§6.4/LIMITS): encrypted DNS yields no qname, only the resolver connect.
- **Hardlink residual** on the sensitive watchlist documented; watched files pinned by `(dev,inode)` at session start (D7).
- `CHANGELOG.md`, `docs/THREAT-MODEL.md`, `docs/MACOS.md`, `docs/PROFILES.md`, `docs/SECURITY.md` (previously referenced but absent).

### Changed
- **D7 file-op mechanism:** syscall-tracepoint paths (relative, TOCTOU-racy, symlink-blind) demoted to fallback tier labeled `path_source=claimed`; the primary mechanism is fentry on VFS/security-layer functions with an in-BPF resolved-path (dentry+mount) walk, emitting `path_source=resolved`. Sensitive-read matching now operates on resolved paths + `(dev,inode)`. S0.1 extended to de-risk the dentry walk.
- **Escape-detection mechanics (§4.2.3):** the old claim — "`proc.exec` whose parent is in-session but whose cgroup is foreign raises `alert.cgroup_escape`" — was unimplementable: in-kernel cgid filtering (D6) drops foreign-cgroup events before userspace, and `systemd-run` escapees re-parent to PID 1 so the parent check never matches. Replaced with pid-map + migration-tracepoint detection for self-migration, and honest precursor-only alerts for delegated spawns.
- **Export format (TRUST §7/§8):** `events.cbor` (canonical bytes) is the authoritative verification artifact. JSON cannot round-trip int64 nanosecond timestamps (> 2⁵³), so re-encoding `events.jsonl` would produce false BROKEN verdicts; JSONL is now a derived, human-readable convenience that is never hashed. The independent verifier hashes the provided canonical bytes (pinned by Merkle roots + signatures) instead of re-encoding.
- **D13 redaction placement:** the pipeline runs at *every writer ingress* — ranad for kernel events, the session service for markers/session-metadata/digest paths (markers never transit ranad, so "redaction lives in ranad" alone was a gap). Enforcement remains the `Redacted`-only writer type.
- **D15/D18 macOS honesty:** removed the "keep the gateway native → degraded/inferred causality" option — RanA has no native macOS collector, so a native agent produces *zero* kernel events; "inferred" refers only to running without the marker plugin. macOS adopt either hosts the gateway in the guest (Linux build on the data volume, config projected, port forwarded) or declines with a plain explanation.
- **Segment seal wording** unified: 4096 events or 60s after the segment's first event (plan §4.4 said "idle", TRUST said "wall" — they now agree).
- **Phase 3 exit criteria** now require a real agent running in-guest on the runtime layer, not merely identical event types.
- **Risk register:** added same-uid tampering and macOS runtime-gap rows.

### Rationale pointers
Each change traces to a principle: D27 → P4 (claim exactly what the chain delivers); path resolution → P1 (kernel truth — a claimed path is agent-influenceable); escape mechanics + DoH + hardlinks → P10 (documented honesty); UDP hooks → trust property 1 (completeness within scope); export CBOR → the TRUST spec's own "determinism is the whole game."
