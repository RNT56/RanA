# Architecture

This expands §4 of `RANA-plan-v1.md`. It is the reference for how a captured effect travels from the kernel to a verifiable line in your ledger, on both platforms.

---

## 1. The one idea

**One cgroup v2 leaf = one session.** Everything else follows from this.

When you `rana run` or `rana adopt`, RanA creates a cgroup leaf (`rana.slice/rana-<id>.scope`) and places the agent's root process in it. Every descendant — a sub-agent the gateway spawns, a shell it execs, an MCP server it launches, a `curl` three levels deep — inherits that cgroup by the kernel's normal rules. RanA's eBPF programs filter on cgroup id in-kernel, so:

- **Attribution is free and reliable** for arbitrarily deep, long-lived process trees.
- **Cross-agent works by construction**: OpenClaw's own fan-out *is* RanA's session tree. Run Claude Code and OpenClaw at once and each is a distinct slice on one timeline.
- **Noise never enters the pipeline**: processes outside the slice are dropped in-kernel, before the ring buffer.

## 2. Components

```
┌──────────────── host (Linux) OR macOS guest VM (Linux) ────────────────┐
│                                                                        │
│  agent process tree ── cgroup: rana.slice/rana-<sess>.scope            │
│         │                                                              │
│  ╔══════╧═══════════════════════════════════════════════════╗         │
│  ║ kernel: eBPF programs                                     ║         │
│  ║  • sched_process_exec/fork/exit    (tracepoints;          ║         │
│  ║    fork/exit maintain the in-kernel session pid-map)      ║         │
│  ║  • cgroup/connect4+6, sendmsg4+6   (BPF_CGROUP_SOCK_ADDR; ║         │
│  ║    sendmsg covers unconnected-UDP sendto)                 ║         │
│  ║  • fentry unix_stream_connect                             ║         │
│  ║  • file ops: fentry on VFS/security fns + in-BPF          ║         │
│  ║    resolved-path walk (open/unlink/rename/mkdir/          ║         │
│  ║    chmod/truncate); syscall-tracepoint fallback tier      ║         │
│  ║    emits path_source=claimed                              ║         │
│  ║  • cgroup_attach_task              (migration/escape)     ║         │
│  ║  • inet_sock_set_state             (flow close)           ║         │
│  ║  filter: cgid ∈ pinned session map (∪ session pid-map     ║         │
│  ║          for escape detection)                            ║         │
│  ╚══════╤═══════════════════════════════════════════════════╝         │
│         │ ring buffer (BPF_MAP_TYPE_RINGBUF)                           │
│  ┌──────┴───────────────────────────────────────────────┐             │
│  │ ranad  (root, no listening sockets)                   │             │
│  │  decode → enrich (path canon, cgid→session, exe hash  │             │
│  │           backfill request) → REDACT (pre-chain) →    │             │
│  │           rate governor (sheds by value, emits gap)   │             │
│  └──────┬───────────────────────────────────────────────┘             │
│         │ unix socket, SO_PEERCRED-gated to owner uid                  │
│  ┌──────┴───────────────────────────────────────────────┐             │
│  │ rana session service  (your user)                     │             │
│  │  • SQLite ledger (WAL, single-writer, group-commit)   │             │
│  │  • hash chain: CBOR→BLAKE3→Merkle segment→Ed25519 ckpt │             │
│  │  • digest worker (BLAKE3 close-write, profile scopes)  │             │
│  │  • marker ingest (origin=enrichment; same redact       │             │
│  │    pipeline before the writer — markers skip ranad)    │             │
│  │  • alert rules (new-domain, sensitive-read, burst)    │             │
│  │  • timeline UI host (127.0.0.1, token-gated)          │             │
│  └───────────────────────────────────────────────────────┘             │
└────────────────────────────────────────────────────────────────────────┘

macOS host process (rana, CGO+vz):
   boots the embedded Linux guest → virtiofs-projects granted dirs →
   receives the guest event stream over vsock → WRITES THE LEDGER ON THE HOST.
```

### Why the privilege split (D10)

`ranad` needs root to attach BPF and read the ring buffer. It holds the *least* it can: a minimal capability set (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` on kernels ≥ 5.11), **no listening TCP sockets**, one peer-authenticated unix socket, and a hardened systemd unit (`ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`). The valuable artifact — your ledger, your signing key, the UI — lives at **user** privilege in `rana`. The UI never runs as root. This keeps the root surface tiny and the sensitive data owned by you.

The split cuts both ways, and RanA accounts for it: the recorded agent usually runs *as the same user* who owns the ledger and key. That's why `ranad` keeps one small piece of root-owned state — an append-only mirror of checkpoint heads (`heads.log`) — so a subverted same-uid agent cannot silently rewrite and re-sign the past (plan D27, `LIMITS.md §6.1`), and why RanA's own data directory is on the built-in sensitive watchlist.

## 3. Session lifecycle

1. **`rana run --profile P -- <cmd>`**
   - Create transient scope: systemd D-Bus (`StartTransientUnit`) when systemd is present; raw `cgroupfs` (`mkdir` + write `cgroup.procs` + set `cgroup.subtree_control`) fallback for minimal/container hosts.
   - Pin `cgid → session` into the BPF filter map.
   - Write `session.start` (profile, host fingerprint: os/kernel/rana-version/boot_id, adopt caveats).
   - `exec` the child inside the scope.
   - **svc socket contract (v1.2).** `rana run` hosts the per-user session
     service (svc) *in-process* and binds the ranad socket at
     `<RANA_RUN_DIR>/ranad.sock` (default: the user runtime dir,
     `$XDG_RUNTIME_DIR/rana/`). svc is the listener; `ranad` (root) dials it
     and is SO_PEERCRED-gated to root (D10: "ranad … no listening sockets").
     `ranad` honors the same `RANA_RUN_DIR`, so a deployment points both at
     one path. This per-user, single-socket model is the one integration
     choice the original plan left open; it is settled here for the v1
     single-user target machine. **Open items** (tracked, not yet built):
     multi-user routing (one root `ranad` fanning events to several users'
     svc sockets by cgid→uid). The session-end eviction is now wired: svc
     sends a `SessionEnd` frame after sealing, and `ranad`'s outbound loop
     releases that session's Governor/segTracker/exe-provenance state (any
     final governor gap is surfaced as a normal gap event), so a long-lived
     daemon no longer accumulates state per session it ever observed.
2. **`rana adopt <target>`** (long-running daemons)
   - Detect the target (e.g. OpenClaw gateway), generate a systemd drop-in placing its unit under `rana.slice`, confirm with the user, restart.
   - `--pid N` migrates a live tree instead; caveats (already-open fds predate the record; thread migration semantics) are written into session metadata honestly.
3. **Membership** is cgroup inheritance, with escape detection layered on top: the fork/exit programs maintain an in-kernel **session pid-map**, so a member that *migrates out* of the cgroup (`cgroup_attach_task` on a mapped pid) or execs from a foreign cgroup while still in the pid-map raises `alert.cgroup_escape{pid, from, to}`. **Delegated spawns** (`systemd-run`, D-Bus activation) re-parent to PID 1 and cannot be claimed — RanA records the observable *request* (the in-session exec of the delegation tool, the `unix.connect` to the bus socket) and raises `alert.escape_precursor`. Surfaced, not pretended away (see `LIMITS.md §3`).
4. **End** on scope-empty or `rana stop`; `session.end` seals the final segment and writes a checkpoint.

## 4. Event flow, end to end (one `connect`)

1. Agent calls `connect()` to `1.2.3.4:443`.
2. `cgroup/connect4` fires; program checks `cgid ∈ session map`; in-session → emits a compact fixed-layout record to the ring buffer (pid, cgid, daddr, dport, proto, monotonic+realtime timestamps captured in-kernel). Not in-session → ignored, zero userspace cost.
3. `ranad` reads the record, resolves the process path, joins a recent `net.dns` answer for `1.2.3.4` if one exists, runs the URL/host through redaction (a hostname is rarely secret, but the pipeline is uniform), passes it to the governor.
4. Governor admits it (network events are highest-value, never shed) and forwards over the unix socket.
5. `rana` service encodes it as canonical CBOR, computes its BLAKE3 leaf, appends to the open segment's Merkle accumulator, writes the row in the next group-commit batch.
6. Alert rules see a first-contact domain → emit `alert.new_domain` → desktop notification.
7. The timeline UI, tailing over the same service, drops a marker on the network lane.

At no point did a payload byte get read, and at no point could step 2 have blocked the agent's `connect`.

## 5. Data model (tables)

- `sessions(id, profile, started, ended, host_fingerprint, adopt_caveats)`
- `events(rowid, session, seg, ts_mono, ts_wall, type, pid, data BLOB)` — `data` is canonical CBOR, already redacted
- `paths(id, canonical)` — interning table; events reference `path_id` to keep rows small at 10k ev/s
- `segments(id, session, first_rowid, last_rowid, merkle_root, prev_hash, gap_summary, sealed_at)`
- `checkpoints(seg_range, chain_head, prev_checkpoint_hash, sig, pubkey_id, signed_at)` — one ledger-wide chain across sessions (`docs/TRUST.md §5`); each head also mirrored to ranad's root-owned `heads.log`
- `digests(path_id, prev_digest, new_digest, size_delta, at)`

Every effect-class event carries `state: observed` in v1. Gated mode (Phase G) introduces `proposed → committed|discarded` in the same field — no schema migration.

## 6. macOS via microVM (detail)

The macOS story is *not a second implementation of capture*. The guest is Linux, so the entire stack in §2 runs unchanged inside it. There is **no native macOS capture path** — a natively-running macOS agent produces zero events (Endpoint Security entitlements are closed to OSS distribution), and RanA says so rather than showing a partial timeline. macOS-specific surface is only:

- **Guest image** (`guest/`), layered so real agents can *run*, not just be recorded:
  - *Base layer*: Buildroot-built Linux, BTF + virtiofs + overlayfs + the D7 hook tracepoints compiled in, minimal initramfs, `ranad`+guest-`rana` baked in. ≤60MB, reproducible, checksum-pinned, embedded in the host binary.
  - *Runtime layer*: Node.js LTS + git + POSIX toolchain — what OpenClaw and Claude Code (both Node apps) need. ≤150MB, reproducible, fetched once with signature check.
  - *Data volume*: persistent host-file-backed ext4 for guest-side installs. Host-installed `node_modules` contain Mach-O native addons that cannot run in a Linux guest — adopt performs a guest-side install instead.
- **Service re-exposure**: a vsock↔TCP proxy forwards adopted services' guest ports (e.g. gateway :18789) to host localhost, so existing local clients keep working unchanged.
- **Runtime** (`internal/vm/`): Code-Hex/vz/v3 over Apple Virtualization.framework. Requires CGO, a codesigned binary, and the `com.apple.security.virtualization` entitlement (release builds are signed; `docs/MACOS.md` covers self-signing for source builds).
- **Filesystem projection**: each granted host dir → its own virtiofs tag, mounted **read-write at `/mnt/host/<name>`** in-guest, never as rootfs (sidesteps the documented virtiofs uid/gid rootfs breakage). Guest agent uid pinned 1000; a mount-time normalization maps ownership. Timeline translates `/mnt/host/<name>/…` back to the real host path.
- **Control/data plane**: vsock (`net.Conn` via vz). The guest streams events to the host `rana`, and **the host writes the ledger** — so a guest that gets fully compromised can suppress its own future events but cannot rewrite host-persisted history (the trust property in `LIMITS.md §1.5`).
- **Boot budget**: cold ≤10s; on macOS ≥14, `SaveMachineStateToURL`/restore keeps a warm pool so `rana run` feels instant (gate G3).

**Limitations**: an agent inside the guest can't drive native macOS apps (AppleScript, iMessage); virtiofs delivers no inotify for host-side changes and has weaker lock semantics; project-specific toolchains beyond the runtime layer are user-provisioned. Stated plainly here and in `LIMITS.md §5`, not buried.

## 7. Feature tiers (Linux)

Probed at `ranad` start, surfaced by `rana doctor`:

| Tier | Kernel | Adds |
|---|---|---|
| Baseline | 5.15 | Full product: tracepoints, ringbuf, cgroup/connect4·6, fentry, sensitive-read map |
| Enhanced | ≥ 5.18 | kprobe-multi (cheaper fs attach) |
| Preferred | ≥ 6.6 | tcx flow accounting (tightens `io_uring` network coverage) |

cgroup v1-only hosts fail loudly with remediation. The product is complete at Baseline; higher tiers are efficiency and coverage, not features.
