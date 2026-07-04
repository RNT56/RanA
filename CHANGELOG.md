# Changelog

All notable changes to RanA. Format: [Keep a Changelog](https://keepachangelog.com/). Entries dated before the code was complete (`[Plan v1.1]`, `[Plan v1.2]`) record amendments to the original design document, which has since been retired; `CLAUDE.md` and the `docs/` set are now the governing references.

## [Unreleased] — 2026-07-04 (security hardening & leak closure)

Implementation hardening (no binding-decision changes) following an adversarial security self-assessment of RanA-as-installed-software.

### Redaction end-to-end hardening (`internal/redact`)

An exhaustive adversarial audit of the redaction trust core (type-enforcement, recall, ingress coverage, marker/salt/CRC, corpus) surfaced 14 verified findings; all are fixed, each with a permanent corpus row and/or regression test. Recall stays 100% and benign precision 100% on the now-648-row corpus (gate **G4**).

- **Entropy recall gaps closed.** Pure-hex tokens are now caught from 16 chars (64 bits) rather than 32 (a 24-hex token measured H≈3.5 bits/char and slipped the 4.0 bar); the token tokenizer now also splits on `.` `,` `;` `@` `|`, which both stops a dotted FQDN from being over-redacted whole (it is the qname a `net.dns`/`net.connect` event exists to record) and stops a secret diluted by a glued benign suffix from ducking the entropy bar.
- **Structural coverage widened.** Broader credential keywords (`passphrase`/`credential`/`passcode`/`client_secret`/… and short `pin`/`otp`/`pwd` with a non-alphanumeric lead); connection-string rule now catches empty-username (`redis://:pass@`), `+`/digit schemes (`mongodb+srv`, `oci8`), and semicolon (`Password=…;`) forms; Luhn-validated payment cards and long numeric secrets; and the **whole** PEM private-key block (`BEGIN`…`END`), closing the short-final-line key-material leak the header-only rule left.
- **Argv-split credentials.** `RedactArgv` now redacts the value element following a bare credential flag (`--password <value>`), which the per-element passes could not see.
- **Marker checksum: CRC-16 → 32-bit salted BLAKE3.** The old CRC was GF(2)-affine, leaking a linear equation on the salt per marker (salt recoverable from known-plaintext markers), and 16 bits collided at ~1/65536 (fabricated "reused secret" inferences). BLAKE3 is non-affine; 32 bits drops collisions to ~1/4e9. Marker width is now 8 hex.
- **Functional fix (masked by tests):** `hostFingerprint()` returned raw Go strings in the session.start `host` map, so the canonical encoder rejected it with `ErrRawString` and **every real session's anchoring event was silently dropped** — no test caught it because they all used empty/`Literal` maps. Values are now `redact.Literal`-wrapped, with a test on the production shape.
- **Option coupling fix.** `WithStricterEntropy` treats a 0 argument as "leave this dimension unchanged", so a profile tightening only one of `EntropyMinLen`/`EntropyThreshold` no longer collapses the length gate or fails service startup.
- **Docs honesty (P10):** `docs/REDACTION.md` §4 and `LIMITS.md` §4 corrected — the marker is a correlation *hint*, not a commitment (a salt-holder can confirm a guessed low-entropy value); the residual is stated plainly (context-free short values, the path-shaped allowlist blind spot). The fuzzer gained a real leak assertion (a sentinel secret must redact under any fuzz-chosen context), not just no-panic/idempotency.

### Security fixes
- **ranad peer-auth (HIGH).** ranad, as the client dialing svc's socket, verified only that its `SO_PEERCRED` call *succeeded* and discarded the uid — a hijacked/stale socket at that path could impersonate svc, receive the salt + event stream, and plant forged `heads.log` entries (defeating D27). ranad now requires the peer uid to equal the socket file's owner before the handshake.
- **exportverify overflow (MEDIUM).** A near-`uint64`-max uvarint length in a hostile `checkpoints.cbor` wrapped `int()` negative, bypassed the bounds check, and panicked — crashing the WASM/browser verifier. Now bounds-checked in `uint64` space, with adversarial tests at the overflow boundary.
- **install signature (MEDIUM).** `get-rana.sh` checked only a same-source SHA256; it now runs `cosign verify-blob` when available and warns loudly otherwise.
- **`verify --mirror` honesty (MEDIUM, P5/P10).** Reports `INCOMPLETE` (not a silent `OK`) when the heads mirror is absent, so "checked clean" can't be confused with "never ran."
- Uid-namespaced the temp fallbacks for the svc run-dir and the signing-key datadir; enforced a real CSP on the WASM viewer; added a standing test that exports never embed the private key or salt; adopt auto-detect now requires a corroborating signal (config dir exists) before acting on a spoofable process name.

### Leak closed
- **ranad↔svc session-end wiring.** The deferred item from [Plan v1.2] is now built: a `wire.SessionEnd` frame is broadcast by svc after sealing a session, and ranad's outbound loop evicts that session's Governor / segTracker / exe-provenance state (surfacing any final governor gap as a normal gap event). A long-lived ranad no longer accumulates per-session state for every session it ever observed. `LIMITS.md §8` and `docs/ARCHITECTURE.md §3` updated to match.
- Added `LIMITS.md §4a` documenting the honest limits of the Tier-2 shareable-artifact features.

## [Plan v1.2] — 2026-07-03 (post-implementation review)

A multi-dimension architecture/robustness/security review of the complete, all-green implementation surfaced fixes and one settled design decision.

### Added / Fixed
- **Verify gap-summary cross-check (gate G5).** Each segment header's `gap_summary` is now cross-checked against the tally of `gap` events decoded from that segment's own merkle-protected bytes. Closes a hole where a raw-sqlite attacker (no device key) could suppress a recorded gap on the *unattested tail* by recomputing a self-consistent `seg_hash` (signed segments were already protected). New gate case detects it.
- **`rana verify --mirror` default path.** Now defaults the heads-log to the root-owned `/var/lib/rana/heads.log`, never under `--data` — a same-uid attacker can rewrite `--data`, which would have defeated the D27 custody guarantee entirely.
- **Wire→ledger `AppendEncoded`.** The svc persists the wire's canonical bytes verbatim (hash the given bytes, don't re-encode — TRUST §7) rather than decode-then-re-encode, which lost the `Redacted` type and tripped the P3 guard on already-redacted data.
- **Robustness:** ranad DNSCache GC wired; a session cgroup-watch fd/goroutine leak fixed (ctx cancel now interrupts the blocking inotify read); digest worker switched to a size-capped streaming hash; `datasource.Alerts()` reads hashed bytes, not the unhashed `type` mirror column.
- **P5 fault surfacing:** `service.Config.OnFault` wires decode/persist failures to a logger; `rana run` uses it so a lost event is loud, not silent.

### Decided (v1.2 — the one integration choice the plan left open)
- **`rana run` hosts the per-user svc in-process** and binds the ranad socket at `<RANA_RUN_DIR>/ranad.sock` (default: the user runtime dir); svc listens, root `ranad` dials, SO_PEERCRED-gated to root (D10). Documented in `docs/ARCHITECTURE.md §3`.
- **Deferred, documented open items (at v1.2):** multi-user event routing (one root ranad → several users' svc sockets) and a ranad↔svc session-end wire signal to evict finished-session collector state. At v1.2, ranad's per-session Governor/segTracker/cgid state grew with the number of distinct sessions over the daemon's uptime (a slow, bounded, documented growth). **Update:** the session-end signal has since landed — see *[Unreleased] → Leak closed* above; that growth is now bounded. Multi-user routing remains deferred (`LIMITS.md §8`).

### Note on verification
Every pure-Go layer and the full wire→svc→ledger→verify→export→standalone-verifier path is race-tested green on darwin; the eBPF collector and the Linux daemon socket lifecycle are compile-verified for `GOOS=linux` (they require generated CO-RE objects + a Linux kernel + root, exercised in CI, not on the dev host).

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
- **Segment seal wording** unified: 4096 events or 60s after the segment's first event (the schema spec said "idle", TRUST said "wall" — they now agree).
- **Phase 3 exit criteria** now require a real agent running in-guest on the runtime layer, not merely identical event types.
- **Risk register:** added same-uid tampering and macOS runtime-gap rows.

### Rationale pointers
Each change traces to a principle: D27 → P4 (claim exactly what the chain delivers); path resolution → P1 (kernel truth — a claimed path is agent-influenceable); escape mechanics + DoH + hardlinks → P10 (documented honesty); UDP hooks → trust property 1 (completeness within scope); export CBOR → the TRUST spec's own "determinism is the whole game."
