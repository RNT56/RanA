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
| **`io_uring` socket ops** | On the 5.15 baseline, some `io_uring`-issued network operations bypass the `cgroup/connect4·6` hooks (`IORING_OP_CONNECT` does not enter the syscall path those hooks are attached to). | **Closed on TierEnhanced+ (kernel ≥ 5.18):** an `lsm/socket_connect` hook (`rana_socket_connect`, `bpf/src/rana_net.c`) fires for every completed connect regardless of call path — syscall or `io_uring` — and emits the identical `net.connect` record. On the 5.15 baseline (no stable BPF LSM attachment assumed), the gap remains as described. Coverage table below; `rana doctor` reports which tier your kernel gets. | Closed on TierEnhanced+ today; baseline-tier closure would need a kernel-version-conditional attach RanA does not yet perform. |
| **`LD_PRELOAD` / direct-syscall file ops** | A process that avoids the kernel paths we hook for *files* can write without an `fs.*` event. | **Network is still caught** at the cgroup socket layer (a different hook family it can't dodge from userspace); exec of the preloading process is recorded. | Broaden fs hook coverage (LSM hooks under evaluation). |
| **setuid transitions** | A setuid binary changes credentials mid-tree; ownership context shifts. | `proc.exec` with uid change is recorded and flagged. | Documented; enforcement-mode policy in Phase G. |
| **Hardlinks into the sensitive watchlist** | The watchlist matches resolved paths, which defeats symlinks; files present at session start are additionally pinned by `(dev,inode)`. A hardlink to a file that only matched a *prefix* rule (never individually pinned) could previously be read under a fresh, unwatched alias name without tripping `fs.sensitive_read`. | **Re-pinned at link time:** `fentry/security_path_link` (`rana_path_link`, `bpf/src/rana_fs.c`) checks the existing (pre-link) path against the sensitive-prefix rules on every hardlink creation during the session and, on a match, immediately pins the target's `(dev,inode)` into the same watchlist map used for session-start files — so a read under the brand-new alias is caught exactly like a read under the original name, from that point forward. Residual: a hardlink created and read as its **first** access in the same racing instant, before the re-pin's map write lands, is not itself a new gap here (`security_path_link` fires and completes before the link is usable) but is recorded for honesty. Files that are neither prefix-matched nor pinned at session start (a hardlink to a wholly unwatched file) are, correctly, still not tracked — that's expected behavior, not a gap. | Re-pin lands unconditionally at every supported tier (plain `fentry`, no tier gate needed). Symlink-style pre-session hardlink chains predating the watchlist's own construction are out of scope, unchanged from before. |
| **Encrypted DNS (DoH / DoT)** | Query names are invisible inside TLS — `net.dns` events do not exist for agents using encrypted resolvers. | `net.connect` to the resolver (:443/:853) and every subsequent IP-level `net.connect`; the `alert.new_domain` rule degrades to new-*IP*. | Documented; no interception will ever be added (P7-adjacent: no payload capture). |
| **Claimed vs. resolved file paths** | On kernels/paths where the resolved-path hook is unavailable and RanA falls back to syscall-argument paths, the recorded path is what the process *asked for* (TOCTOU-racy, agent-influenceable), not kernel ground truth. | Such events carry `path_source=claimed` in-schema, so the record itself tells you which kind of truth you're holding. `rana doctor` reports which tier your kernel gets. | Fallback tier shrinks as fentry coverage grows. |
| **Path resolution deeper than 48 components** | The in-kernel resolved-path walk (D7) is bounded to ≤48 dentry components for verifier-boundedness. A path nested deeper than that is truncated — but truncated from the *root end*, keeping the leaf-nearest 48 components (the segment sensitive-prefix matching and human review need most), not silently shown as a shorter, wrong-looking absolute path. | The event still carries `path_source=resolved` (it genuinely is a resolved walk, just a bounded-depth one) and the emitted path is the true nearest-to-file suffix. | Document only; 48 covers the overwhelming majority of real filesystem layouts. |
| **DNS question-name compression pointers** | `rana_dns.c`'s qname parser reads the wire-format question section literally and does not follow DNS name-compression pointers (`0xC0`-prefixed length bytes). A compressed question name (rare — DNS clients almost always encode the first question's name literally) is dropped rather than mis-parsed. | No `net.dns` event for that one query; the underlying `net.connect` to the resolver is still recorded. | Document only; compressed *questions* (as opposed to compressed *answers* in responses, which aren't walked at all — only literal A/AAAA rdata is read) are vanishingly rare in outbound client traffic. |

**`io_uring` network coverage by kernel:**

| Kernel | `connect` via `io_uring` | Notes |
|---|---|---|
| 5.15 (baseline) | Partial | Classic `connect()` fully covered; `IORING_OP_CONNECT` may bypass — no `lsm/socket_connect` attach assumed at this tier. |
| ≥ 5.18 (Enhanced) | **Closed** | `rana_socket_connect` (`lsm/socket_connect`) attaches and catches every completed connect, `io_uring`-issued or not, emitting the normal `net.connect` record. |
| ≥ 6.6 (Preferred) | **Closed** | Same `lsm/socket_connect` coverage as Enhanced, plus tcx flow accounting for tighter byte/flow attribution. |

`rana doctor` reports your machine's exact tier and which escapes apply.

## 4. Redaction residual risk

The redaction pipeline (see `docs/REDACTION.md`) achieves ≥99% recall on a permanent corpus of 600+ seeded secret shapes (gate **G4**). The residual is real:

- **Context-free short values.** A bare secret with no adjacent keyword and too little structure to detect — a lone 4–6 digit PIN/OTP, or a bare base64 token under ~24 characters — cannot be redacted without also redacting every benign small number and short identifier, which would gut the timeline's forensic value. *Labelled* short secrets are caught structurally (`pin=`/`otp=`/`passcode=` and the other credential keywords, `card`-shaped Luhn-valid numbers, `--password <value>` and other credential flags split across an argv boundary); pure hex tokens are caught from 16 characters (64 bits); the *bare, contextless* short value is the limit. A single-character credential flag (`-p <value>`) split across argv elements is too ambiguous to act on and is not covered.
- **Path-shaped allowlist (provenance-gated).** The entropy pass allowlists content-addressed path segments (a hash-length hex file under an `objects`/`commits` directory) so it does not shred the very paths a file event exists to record — but **only for kernel-`resolved` paths** (the kernel's dentry walk vouches the file exists there). On an agent-`claimed` path the allowlist is disabled, so a hex segment an attacker crafts to smuggle a secret *is* redacted. Two residuals remain, both narrow: (a) a malicious agent that *creates* a real file whose name hex-encodes a secret and then touches it (a `resolved` path) — a covert channel outside redaction's threat model, and one with far easier alternatives (`net.connect`, DNS); (b) a secret formatted as an exact RFC-4122 v4 UUID, whose ~3.4 bits/char is below the entropy bar and so cannot be redacted without also shredding the millions of benign UUIDs in agent I/O. Structural provider patterns (AWS/GCP/… keys) still run on every segment regardless.
- **Marker checksum is a correlation hint, not a secret.** The 32-bit salted BLAKE3 checksum in a marker (`docs/REDACTION.md` Stage 4) lets an analyst spot the same value reused within a ledger. It is not a commitment: someone who holds the per-ledger salt (the ledger owner always does; a same-uid attacker can read it) can confirm a *guessed* low-entropy value against a marker. The real secrecy guarantee is that raw bytes never leave `ranad` RAM, not that the marker is unguessable.
- **Novel credential formats** not yet in the structural pattern set. The entropy net catches most; misses are catalogued and drive additions. The corpus is a regression gate, so a miss found once is caught forever after.
  - **Example of the loop working:** Slack incoming-webhook URLs (`https://hooks.slack.com/services/<team>/<channel>/<token>`) were found adversarially to duck both the named patterns and the entropy bar (each `/`-segment individually too short). The miss was catalogued, a `slack-webhook` structural pattern added, and `internal/redact.TestSlackWebhookURLRedacted` is the permanent regression test — the documented catalogue→pattern→gate cycle, exercised for real.
- **Fixed-length structural patterns can lose their class label (not their recall) when a real key is glued, with no delimiter, to more word characters on the right.** The AWS-key and GCP-key patterns use a fixed-count quantifier (`{16}`, `{35}`) with a trailing word-boundary anchor; if a key is directly adjacent to more `[A-Za-z0-9]` text (e.g. embedded mid-token in a larger blob), the boundary can't match and the structural pattern doesn't fire at that position. The whole glued run still clears the Stage 3 entropy bar and is redacted — no raw secret bytes leak — but the marker is labeled `entropy` instead of `awskey`/`gcpkey`. A precision gap, not a confidentiality one. See `internal/redact.TestFixedLengthStructuralPatternLosesClassWhenGluedNoLeak`.
- **What can never leak:** environment values (never captured at all) and anything already redacted (raw bytes exist only transiently in `ranad` RAM, never on disk, never in the chain).

If your threat model cannot tolerate a ≤1% path-embedded-secret risk, do not point RanA's digest scopes at directories containing such paths.

## 4a. Tier-2 shareable-artifact limitations

These features produce or annotate exports (`rana export --pack`, `rana export --format incident`, `rana show --diff`, `rana doctor --report`, `rana adopt` auto-detect, exe-provenance, egress intelligence). All of them are additive enrichment (P1: `origin=enrichment`, never load-bearing) and none of them makes a network call or reads `environ` — but each has a real, honest limit:

- **Egress intelligence (`net_class`/`asn` on `alert.new_domain`) is a curated, hand-picked, ~10-entry anchor table compiled into the binary — not an IP-reputation or geolocation service, and it has no update mechanism.** It exists to narrate a timeline ("first contact: 8.8.8.8 (Google Public DNS)"), not to attribute ownership authoritatively. IP space is reassigned over time; a hardcoded prefix→label mapping can go stale and mislabel a block that has since changed hands. Absence of a label means nothing (most public addresses have no entry); presence of a label is a best-effort, build-time snapshot, not a live lookup. See `internal/alerts/rules.go` (`curatedASNPrefixes`).
- **Exe-provenance (`exe_known`/`exe_first_seen`/`exe_changed` on `proc.exec`) is a local, embedded path+basename allowlist, not a code-signing or hash-reputation check.** `ExeKnownAllowlisted` only means "this exec's path and basename match a conventional interpreter/shell location" — it is not a verdict of trustworthiness, and it does not itself detect a compromised system binary. `exe_first_seen`/`exe_changed` are only as strong as the digest the *caller* supplies (`internal/collector/provenance.go` trusts the pairing it's told, per P1 doc comment); if no digest is ever supplied, the enrichment is silently absent, and the base `proc.exec` event is still complete without it.
- **`rana adopt` auto-detect (`listRunningProcesses`) is a best-effort `/proc` scan, not a security boundary.** It reads only `comm`/`cmdline` (never `environ`, P3) and silently skips processes that exit or become unreadable mid-scan — appropriate for a one-shot convenience feature, not something to rely on for completeness the way the eBPF-sourced record is.
- **`rana show --diff` (`DigestDiff`) reports on-disk *availability* only, never content.** A `HaveNew=false` result is ambiguous by design (changed, deleted, moved, or simply unreadable all collapse to "does not match") — see `Note` for which. It also depends on `PathTranslator` correctness (guest→host path translation on macOS); a wrong translation reports a false mismatch, not a wrong file's content.
- **The incident report (`rana export --format incident`) is a narrative rendering of already-recorded, already-redacted events — its completeness is bounded by the same escapes as `LIMITS.md §3`.** It does not re-derive or infer anything the ledger doesn't already contain; a gap in the source ledger is a gap in the report.

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

## 8. Wiring status (honest current state)

RanA is built as decoupled layers, and not every seam between separate
processes is wired to its final form yet:

- **`rana run` (Linux) hosts the session service and the full record→ledger→
  verify→export path is exercised end to end** (the wire→svc→ledger→verify→
  standalone-verifier flow is race-tested). Actual kernel capture additionally
  requires `ranad` attached with generated eBPF objects (a Linux/root/CI
  concern, not runnable on the macOS dev host).
- **Single-user by design (v1).** One root `ranad` feeding *multiple* users'
  session services by cgid→uid routing is a documented open item, not built.
- **Long-lived-daemon session state — now bounded.** `ranad`'s per-session
  rate-limit, segment-tracking, and exe-provenance state is released when svc
  reports a session ended, via a `SessionEnd` frame on the ranad↔svc wire
  (svc broadcasts it after sealing; ranad's outbound loop evicts the state and
  surfaces any final governor gap). If ranad is disconnected when a session
  ends, the state is reclaimed on its next restart (a fresh ranad carries no
  accumulated state), so a dropped signal costs at most a bounded reclamation
  delay, never correctness.

These are wiring gaps between finished components, not missing guarantees: the
trust properties in §1 hold for every event that reaches the ledger.

---

*If any statement here is wrong, that is the highest-priority bug in the project.*
