# CONTRACTS — per-package interface contracts

This file is the **interface contract** for every package in RanA: what each
package is responsible for, the load-bearing types and functions it exposes, the
invariants it upholds, and how it is meant to be tested. It exists so the layers
can be built and verified independently (CLAUDE.md §3.2, "maximum-DAG
parallelism"): every package codes against the frozen **event schema** (plan
§4.3) and against the contract stated here for its neighbours — not against their
internals.

Source comments cite this file as `CONTRACTS §<package>` (e.g. `CONTRACTS
§internal/ledger`) or by quoting a specific clause. When code and this file
disagree, that is a bug in one of them; per `LIMITS.md`'s standing rule for the
trust surface, treat a wrong contract statement as the highest-priority defect.
This file describes contracts, not mechanism — the *why* and the cryptographic
detail live in `docs/TRUST.md`, `docs/ARCHITECTURE.md`, and `docs/REDACTION.md`,
which the sections below cross-reference.

## Ranking

Contracts here are subordinate to the ten principles (CLAUDE.md §1) and to
`RANA-plan-v1.md`. Where a contract clause and a principle appear to conflict,
the principle wins and the clause is the bug.

## Universal testing bar

Every package is held to these, over and above its package-specific test
contract:

- **Injectable clocks everywhere time matters.** No production code path calls
  the wall clock directly where a test would need to control it; time is taken
  from an injected `Clock`. Tests never `time.Sleep` to await a
  time-driven transition (the bar is: no real sleeps for scheduling; a fake
  clock drives timers). This clause is cited across the tree as "CONTRACTS
  testing bar: injectable clocks everywhere time matters."
- **Drive real code paths, not invasive mocks.** Fakes stand in only at true
  process/host boundaries (a `net.Pipe` for a socket peer, an in-memory
  `DataSource`, an injected fetch/dialer, a synthetic ring-buffer trace). The
  logic under test runs for real — a redaction test drives the real pipeline, a
  ledger test drives the real SQLite group-commit.
- **Hostile input never crashes a long-lived loop.** Parsers and frame readers
  return errors, never panic, on garbage/torn/oversize input; a bad frame or
  line fails itself and the serving loop keeps going.
- **`internal/redact` and `internal/ledger` are the trust core** (CLAUDE.md
  §3.1) and additionally held to the strictest bar: property/fuzz tests, a
  permanent regression corpus, and adversarial mutation suites.

---

## internal/schema

**Purpose.** Define RanA's frozen event envelope (v1) and the typed constructors
for the complete, closed event taxonomy (kernel-, svc-, and enrichment-origin),
with structural validation and redaction enforcement at the type level.

**Public surface.**

| Symbol | Purpose |
|---|---|
| `Event` | Canonical event envelope: v, type, session, seg, idx, ts_mono, ts_wall, pid, origin, state, data. |
| `EventType` | Discriminates the fixed non-marker types from the open `marker.*` family. |
| `Origin` | `kernel`, `svc`, or `enrichment` — load-bearing vs. advisory. |
| `NewSessionStart`, `NewProcExec`, `NewFsWriteOpen`, `NewFsSensitiveRead`, `NewNetConnect`, `NewMarker`, `NewGap`, … | One constructor per event type; each accepts already-`Redacted` payloads. |
| `Validate(Event) error` | Rejects v≠1, unknown type/origin/state, and structural invariants. |
| `NewSessionID(Clock) string` | ULID id: 48-bit ms timestamp + 80 bits `crypto/rand`. |
| `Clock` | Injectable time source for deterministic id/timestamp tests. |

**Invariants.**

1. Every constructor stamps `v=1`; `Validate` rejects any other version.
2. Session ids are 26-char Crockford-base32 ULIDs from an injectable clock plus
   `crypto/rand` — never derived from env or wall clock in a way tests can't fix.
3. All strings in `Data` are already `redact.Redacted` at constructor entry;
   schema validates shape but does not itself redact (redaction is upstream).
4. `marker.*` events are exclusively `origin=enrichment` (P1); non-marker events
   are `kernel` or `svc`. `Validate` enforces this.
5. The **gap-reason set is frozen** (`ringbuf_full`, `governor`,
   `daemon_restart`, …) and MUST NOT grow with ad-hoc values — cited elsewhere
   as "do NOT invent a new gap reason." New reasons are a schema change, not a
   string literal at a call site.
6. `net.connect` / `net.flow_close` carry a 16-byte v4-mapped daddr, validated
   structurally; proto ∈ {tcp, udp}.
7. The envelope's CBOR map-key order is fixed (plan §4.3) so canonical encoding
   is deterministic.

**Test contract.** Table-driven, one test per event type, each round-tripped
through `cborcanon.EncodeEvent` + `IsCanonical` to prove no raw string leaks into
`Data`; golden constants for type/origin/state; injectable `Clock` for
deterministic ULID tests.

---

## internal/wire

**Purpose.** The framed, length-prefixed CBOR protocol on the `ranad`↔`svc` unix
socket: it transports pre-encoded events, checkpoints, and lifecycle signals; it
never interprets event contents.

**Public surface.**

| Symbol | Purpose |
|---|---|
| `Frame` | Tag-dispatched union: `Hello`, `Ev`, `Head`, `SessionEnd`, `Bye`. |
| `Hello` | `V` (version), `Role` (ranad/svc), `Salt` (redaction salt, agreed out of band). |
| `Ev` | `Event []byte` — opaque canonical CBOR from `cborcanon.EncodeEvent`. |
| `Head` | A `HeadReport` (mirrors `chain.HeadReport`). |
| `SessionEnd` | `Session string` — tells ranad to evict that session's collector state. |
| `Bye` | Clean connection-close signal. |
| `WriteFrame` / `ReadFrame` | uvarint-length-prefixed CBOR codec over `io.Writer`/`io.Reader`. |
| `MaxFrameSize` (1 MiB), `Version` (1), `RoleRanad`, `RoleSVC` | Protocol limits/constants. |

**Invariants.**

1. Frame body ≤ **1 MiB**; oversize is rejected (`ErrFrameTooLarge`) *before*
   the body is allocated — a hostile peer cannot force an unbounded allocation.
2. Length prefix is an unsigned varint; the codec is pure over
   `io.Reader`/`io.Writer` — no socket syscalls, no blocking in the codec.
3. `Ev` bodies are opaque byte strings; wire never decodes or re-validates an
   event (the canonical bytes are transported and hashed as-is).
4. Version negotiation is strict: `V≠Version` is rejected, not truncated.
5. A torn frame (prefix or body cut at EOF) returns a distinct error from a
   clean EOF at a frame boundary.
6. `Salt` is transported over this socket, which is why the socket is
   root↔owner-uid gated at both ends (see cmd/ranad, internal/service).

**Test contract.** Pure round-trip over `bytes.Buffer` for all frame types;
`FuzzReadFrame` requires arbitrary input to error, never panic; peer-credential
extraction has its own linux/darwin tests separate from the codec.

---

## internal/chain

**Purpose.** The tamper-evident cryptographic chain: BLAKE3 leaf hashing, Merkle
segmentation, segment-header chaining, Ed25519 signed checkpoints, the device-key
lifecycle, and the append-only heads mirror. Its guarantee: any modification,
deletion, reordering, or re-signing of persisted events is **detectable**
(docs/TRUST.md; the exact boundary is LIMITS.md §6).

**Public surface.**

| Symbol | Purpose |
|---|---|
| `Leaf([]byte) [32]byte` | `BLAKE3(0x00 ‖ canonicalEvent)`; hashes bytes as-is. |
| `MerkleRoot([][32]byte) [32]byte` | Domain-separated binary tree (`0x01 ‖ l ‖ r`), odd-node duplicated. |
| `SegHeader`, `SegHash(SegHeader)` | Segment header + `BLAKE3(canonical CBOR header)`, returns hash and header bytes. |
| `Checkpoint`, `SignCheckpoint`, `VerifyCheckpoint`, `CheckpointHash` | Ed25519-signed, whole-ledger-chained checkpoints. |
| `KeyInfo`, `GenerateKey`, `LoadKey`, `Wrap`, `PubkeyID`, `ExportPubkeyPEM`, `ParsePubkeyPEM` | Device-key lifecycle (scrypt+ChaCha20Poly1305 wrap). |
| `HeadReport`, `AppendHead`, `ReadHeads` | O_APPEND single-line-JSON heads mirror (D27 custody). |

**Invariants.**

1. Leaf hashing is bytewise-deterministic; no re-encoding or validation of input
   (docs/TRUST.md §8: "hash the provided bytes; do NOT re-encode").
2. The Merkle tree is **domain-separated** by prefix (`0x00` leaf, `0x01` node)
   against second-preimage attacks; the odd-last node is duplicated.
3. Segment chaining: each header carries `prev_seg_hash`; genesis is 32 zero
   bytes; a deletion breaks the chain and is detected.
4. Checkpoint chaining is **whole-ledger** (`prev_checkpoint_hash` spans all
   sessions), so deleting an entire session wholesale breaks continuity (D12).
5. Canonical CBOR (RFC 8949 CDE, bytewise-sorted keys, definite length) is used
   for every hashed/signed structure; the shared encoder init-panics on
   misconfiguration.
6. Signature verification takes the **exact signed bytes**, never a struct
   re-derivation.
7. `AppendHead` is **O_APPEND single-line JSON, never truncates** — the property
   D27's custody guarantee depends on: reports written before a compromise
   survive even if the writer is later subverted. `ReadHeads` tolerates a torn
   last line (crash) but treats mid-stream malformation as fatal.
8. Device keys are stored `0o600`, either plain (magic `0x01` + seed) or wrapped
   (magic `0x02` + scrypt N=2^15,r=8,p=1 + ChaCha20Poly1305).

**Test contract.** Hand-computed Merkle golden vectors (1..5 leaves); the
CONTRACTS-required "chain of 3 segments" integration test plus its single-byte
tamper-flip counterpart (propagating seg_hash → next prev_seg_hash → checkpoint
chain_head); a single-bit-flip property test; sign/verify round-trips; heads
torn-last-line-tolerant / mid-stream-fatal corruption tests.

---

## internal/ledger

**Purpose.** The single-writer, tamper-evident SQLite ledger: group-commit
ingestion, signed segment sealing, whole-ledger checkpointing, streaming
verification, and portable export. Trust core.

**Public surface.**

| Symbol | Purpose |
|---|---|
| `NewWriter(Datadir, WriterOptions)` | One single-writer handle per process. |
| `Writer.Append(schema.Event)` | Queue a validated, redacted event for the next group commit. |
| `Writer.AppendEncoded(Event, []byte)` | Persist a pre-encoded kernel event — hash the bytes, do not re-encode. |
| `Writer.SealSession`, `Writer.Close`, `Writer.Err` | Force-seal/checkpoint; flush+stop; fatal-error check. |
| `Verify(Datadir, VerifyOptions) Result` | Stream-verify structure, merkle chains, signatures, gaps, mirror. |
| `Export(Datadir, session, outDir)` | Portable proof directory: CBOR artifacts + manifest (never the key/salt). |
| `Datadir` (`Ensure`, `LoadOrCreateSalt`) | On-disk layout: `ledger.db`, `device.key`, `salt`, `archives/`. |
| `Result` | `Code` (0 OK / 2 broken / 3 incomplete) + `Findings` + `IncompleteNotes` + `UnattestedTail`. |

**Invariants.**

1. **Single-writer discipline**: one writer goroutine serializes all mutations;
   concurrent readers use WAL + busy_timeout and never spuriously fail against
   that writer ("single writer goroutine").
2. **Group-commit** flushes at ≤512 events or every 10 ms, whichever first;
   the internal queue is bounded and **blocks — never drops** — when full, so no
   code path invents a new gap reason to explain a self-inflicted drop.
3. `event.bytes` columns hold the **full canonical event CBOR** (the hashed
   artifact); mutable index columns (e.g. a `type` mirror) are query
   conveniences and are **never** trusted by verify or hashing.
4. Merkle-per-segment + whole-ledger checkpoint chain: any single-byte edit,
   deletion, reorder, or re-sign surfaces as a precise `FindingKind`.
5. **Gap-summary cross-check**: each sealed segment's header `gap_summary` is
   re-tallied from the `gap` events in that segment's own merkle-protected
   bytes; a mismatch is `FindingGapDishonest` (closes unattested-tail
   suppression).
6. **D27 heads mirror**: checkpoints are reported synchronously to a root-owned
   heads log; `verify --mirror` cross-checks against it and returns
   `INCOMPLETE` (not silent OK) if the mirror is absent.
7. `AppendEncoded` rejects non-canonical CBOR; `Export` never emits the private
   key or salt; a missing verification pubkey yields `INCOMPLETE`, never a
   silent degrade.

**Test contract.** Writer flush-by-count/-timer/group tests; multi-session
checkpoint chaining; `AppendEncoded` round-trip + non-canonical rejection;
clean/empty pass, unattested-tail and missing-pubkey `INCOMPLETE`; the
**G1 benchmark** (1M events, ≥10k ev/s, zero loss, p99 group-commit <15 ms,
runnable on darwin); the external `test/chain-mutations` suite covering every
`FindingKind`.

---

## internal/redact

**Purpose.** The non-optional secrets-redaction pipeline (docs/REDACTION.md):
by construction, no raw captured string can reach a ledger leaf hash. Trust core.

**Public surface.**

| Symbol | Purpose |
|---|---|
| `NewPipeline(salt, …Option)` | Compile the pipeline with a per-ledger salt + built-in patterns. |
| `Pipeline.Redact` / `RedactArgv` / `RedactPath` | Redact a string / argv / path, returning `Redacted`. |
| `Redacted` | String subtype; the ledger writer accepts **only** this type. |
| `Redacted.Literal(string)` | Mark a compile-time constant safe without the pipeline. |
| `WithExtraPatterns`, `WithStricterEntropy` | Options that only **tighten** — never loosen — coverage. |

**Invariants.**

1. **No envp is ever read** anywhere; the pipeline operates only on already-
   captured strings.
2. **Redaction before hashing is enforced by the type system**: a `string`
   becomes `Redacted` only by passing through the pipeline or via
   `Redacted.Literal` on a constant; the writer/encoder accepts nothing else, so
   no raw string can reach a leaf by construction (CLAUDE.md §6 invariant 2).
3. **No flag disables redaction**; options can only tighten the entropy bar or
   add patterns.
4. Every replaced span becomes a typed marker `⟦R:<class>:<lenclass>:<crc>⟧`
   where the CRC is **salted** per-ledger; markers are idempotent (redacting a
   marker is a no-op) and a mutated marker is detectable.
5. The **class set is closed** (docs/REDACTION.md §4: awskey, gcpkey, openai,
   anthropic, ghtoken, slack, stripe, jwt, pem, bearer, connstring, entropy);
   new providers fold into an existing class, never a new one.
6. The pipeline is immutable post-construction and concurrency-safe;
   identical input yields byte-identical output (deterministic salted CRC).

**Test contract.** The permanent **G4 corpus** (`test/redaction-corpus`, ≥520
entries): recall ≥99% on must-redact rows, a benign false-positive ceiling, and
the load-bearing **zero-raw-secret-reaches-output** substring scan; plus
adversarial novel-shape tests, overlap-priority (structural beats entropy),
`-race` determinism under concurrent redaction, and fuzzing. Secrets are stored
`xb64`-obfuscated and decoded at load (a literal key would trip push-protection
and be self-defeating for this project).

---

## internal/collector

**Purpose.** Decode the fixed-layout eBPF ring-buffer records into Go values,
enrich them with session ids and redaction, join DNS answers to connects, and
govern event flow under load.

**Public surface.**

| Symbol | Purpose |
|---|---|
| `Enricher` | Resolves cgid→session, builds schema events, redacts argv/paths/qnames. |
| `EnrichExec/Fork/Exit/Connect/Sendmsg/DNS/FlowClose/UnixConnect/FsOp` | Per-record builders stamping monotonic Idx, calling the pipeline. |
| `EndSession(session)` | Evicts that session's Idx counter, exe-provenance seen-map, cgid bindings. |
| `BindCgid/UnbindCgid/SessionForCgid` | Bidirectional cgroup-id ↔ session-id map. |
| `DecodeRecord([]byte)` | Kind-dispatched decode; validates Version/Kind/Len; never panics on hostile input. |
| `FsOp*` opcodes (incl. `FsOpSensitiveRead`) | `fs.*` operation discriminator; sensitive-read is its own opcode. |
| `Governor` (`Admit`, `FlushGaps`, `EndSession`) | Per-session token bucket; frozen shed order; gap emission on shed/eviction. |
| `EventClass` | Never-shed vs. shed-order tiers (plan D14). |

**Invariants.**

1. **P1**: cgid comes from the kernel cgroup id, the session is kernel-vended,
   and every Idx is monotonically increasing per session (never restarted
   mid-session).
2. **P2**: the enricher only reads kernel records and joins the DNS cache — no
   blocking syscalls, no BPF write/override.
3. **P3**: every argv/path/qname passes `Pipeline.Redact*` before it reaches
   `schema.Event.Data` (which accepts only `Redacted`) — no raw bytes leak.
4. **P5**: the governor counts sheds per (session, class); `FlushGaps` returns
   one gap event per shed interval with exact counts and reason.
5. `FsOpSensitiveRead` emits `fs.sensitive_read` (never `fs.write_open`); its
   `Mode` carries the matched watchlist rule id.
6. **Exe-provenance (Tier-2)** adds Data fields only; no env read, no network; it
   requires a caller-supplied digest and maps to redacted rule labels.
7. The DNS join happens inside `EnrichConnect`/`EnrichSendmsg` before return,
   over a bounded recent-answers window.

**Test contract.** Hand-built synthetic records drive the real enricher against
fake cgid bindings under a deterministic clock; governor tests pin the never-shed
set, shed order, per-session bucket independence, and exact gap counts on a
scripted burst; provenance tests cover the session-keyed seen-map and eviction;
`DecodeRecord` is fuzzed (never panics) and its size/offset constants are
cross-checked against `internal/bpf/records.md`.

---

## internal/bpf

**Purpose.** Own the eBPF CO-RE programs, the `bpf2go`-generated bindings, and the
Linux-gated loader (attach, idempotent reattach, pin/unpin, `gap{daemon_restart}`
on restart). The tier-decision and pin-path logic are portable and unit-tested on
darwin; the generated-object references are build-tagged.

**Public surface.**

| Symbol | Purpose |
|---|---|
| `Loader`, `NewLoader` | Own attached-program lifetime + pinned maps under `/sys/fs/bpf/rana`; idempotent reattach. |
| `DetectKernelTier`, `Tier`, `Features` | Probe uname → capability tier (5.15 floor, 5.18 Enhanced, 6.6 Preferred). |
| `PinPath`, `SafePinPath` | Fixed pin paths; `SafePinPath` rejects traversal/NUL/whitespace. |
| `ReattachPlan`, `WantedPrograms` | Compute idempotent reattach (ToLoad/Skip/Stale) for a tier. |
| `DaemonRestartGap`, `GapDescriptor` | Portable `gap{daemon_restart}` shape the linux loader turns into an event. |
| `ParseKernelRelease`, `TierForKernel` | Parse uname release → tier (portable). |

**Invariants.**

1. **Build gating**: the pin/reattach plumbing is `//go:build linux`; the
   `bpf2go`-generated references are behind the `rana_bpf_generated` tag (set only
   after `go generate`); the tier/pin logic is portable (no tag), so `go build`
   and `go test` succeed on darwin with no clang and no generated objects.
2. **P1/P2**: attach points are kernel-sanctioned (tracepoint / fentry / cgroup /
   LSM) hooks that read kernel memory only — no `bpf_probe_write`, no
   `bpf_override_return`, no blocking helper. (CI greps the compiled program
   list to enforce this.)
3. **Idempotent reattach**: the same program set against the same pins is a
   no-op; stale pins are removed; a Baseline→Enhanced move loads only the new
   programs. Pin locations are fixed, never varied per invocation.
4. **P5**: a `gap{daemon_restart}` is produced on every loader construction and
   handed to ranad to stamp into the chain.
5. **Compile-check lives in CI** (`make gen`; `clang -target bpf`), never inside
   `go test`.

**Test contract.** Portable tests cover `TierForKernel`/`ParseKernelRelease`,
`ReattachPlan` idempotency, and stable pin-path construction; static-inspection
tests assert no override/blocking helper and stable program names; a cross-check
test pins `records.h` struct sizes to `records.md` (CI does the clang-backed
symbol cross-check).

---

## cmd/ranad

**Purpose.** The privileged Linux daemon: decode ring-buffer records, enrich with
redaction, govern flow, frame over the unix socket to svc, and mirror `Head`
frames into the root-owned `heads.log` (the one root-privileged write, D27). The
`Pump` is fully unit-testable on darwin with fakes.

**Public surface.**

| Symbol | Purpose |
|---|---|
| `Pump`, `PumpConfig` | Wire RecordSource → decode → enrich → govern → FrameSink; own inbound/outbound loops. |
| `Pump.Drain` | Pull every available record, process it, send frames; a bad record is skipped, not fatal. |
| `Pump.PumpInbound` | Drain `Head` frames from svc and append each to `heads.log` (the D27 mirror write). |
| `Pump.DrainEndedSessions` | On `wire.SessionEnd`, evict that session's governor/seg/enricher state; return any final gap. |
| `Pump.FlushGaps`, `Pump.ReconnectGap`, `Pump.HeadsLogPath` | Shed-interval gaps; reconnect gap builder; heads path. |
| `RecordSource`, `FrameSink`, `segTracker` | Abstracted source/sink (real socket vs. fake); per-session segment index. |

**Invariants.**

1. **P2**: the pump only reads already-captured records; it never blocks or
   modifies the syscall path — if ranad dies, workloads are unaffected.
2. **P3**: the enricher returns already-redacted events; the pump encodes via
   `cborcanon.EncodeEvent` before framing — no raw bytes reach the wire.
3. **P5 on every loss**: ring-buffer drops (governor drop counter), governor
   sheds (`FlushGaps` per interval), daemon restart (`ReconnectGap` on every
   reconnect), and session eviction (`DrainEndedSessions`' final gap) each
   produce a gap event.
4. `Seg` is stamped before encode and is canonical (part of the hash, never
   recomputed); the seal policy (4096 events or 60 s) is applied per session.
5. **NO listening TCP**: ranad dials outbound only to svc's unix socket, and
   authenticates it by matching `SO_PEERCRED` uid against the socket file's owner
   before the handshake (defense in depth against a hijacked path).
6. A malformed record or unknown-cgid is skipped, never fatal — the daemon keeps
   recording.

**Test contract.** `pump_test.go` drives the whole pump on darwin via a scripted
`fakeSource` and a `fakeSink` under a deterministic clock; record builders
construct wire bytes by hand; tests cover segment advance by count/age, clean
stop on no-record, fatal propagation on a genuine sink error, and the
`heads.log` append path.

---

## internal/alerts

**Purpose.** A deterministic rules engine that consumes persisted events
*post-commit* and synthesizes `alert.*` events plus best-effort desktop
notifications. Alerts are never load-bearing truth (P1).

**Public surface.**

| Symbol | Purpose |
|---|---|
| `Engine`, `NewEngine(Config, …Option)` | Post-persist rules engine over bounded per-session state. |
| `Engine.Observe(ev, seg)` | Post-persist callback; returns error only on `Sink` failure. |
| `Sink` | Persists synthesized `alert.*` events; its errors propagate (a real loss). |
| `Notifier`, `NopNotifier`, `FakeNotifier` | Best-effort desktop notification; failures never block. |
| `Config`, `Option` (`WithBurstThreshold`, `WithTrifectaWindow`) | Injected Clock+Sink (required), Notifier (optional), tunables. |

**Invariants.**

1. **Post-persist only**: `Observe` runs *after* the triggering event is durably
   persisted; the engine never re-reads the ledger and never blocks the persist
   path it observes.
2. **Sink errors propagate** from `Observe` (a dropped alert is a real loss the
   caller must know); **Notifier errors are best-effort** and never returned or
   allowed to block (P2 discipline).
3. **Fixed deterministic rules**: `new_domain` (first-contact qname/IP per
   session), `sensitive_read` (passthrough, no dedup/suppression), `burst` (rate
   over threshold in a sliding window, edge-triggered with re-arm), `trifecta`
   (sensitive-read + new-domain within a window → escalated
   `exfil_precursor=true`, never escalates the same pairing twice), and escape
   passthroughs.
4. Alerts consume events but do **not** own Idx allocation (the service stamps
   Idx on emit).

**Test contract.** A large integration suite drives every rule, the trifecta
correlation, the burst window, and error handling under a manually-advanced fake
clock with a recording sink; `FakeNotifier` round-trips and best-effort failure
isolation are tested per platform with an injectable runner.

---

## internal/profile

**Purpose.** Parse and validate TOML profile packs (agent recognition, digest
scopes, sensitive-path extensions, redaction tightening, marker config) and
enforce the **additive-only** invariant: a profile can only make RanA stricter or
richer, never blinder.

**Public surface.**

| Symbol | Purpose |
|---|---|
| `Load(name)`, `LoadFile(path)`, `Parse(src, source)` | Load/validate a shipped, custom, or inline profile. |
| `Profile` | Validated pack: Match, Adopt, Capture, Digest, SensitiveRead, Redaction, Markers, … |
| `Match(candidates, exe, argv)` | Auto-select a profile (exe_basename outranks argv_contains; first match wins). |
| `Glob`, `ExpandSessionCWD(All)` | `path.Match`-based globber with `**`; `$SESSION_CWD` expanded at session start. |
| `Available()` | Sorted list of shipped built-ins. |

**Invariants.**

1. **Additive-only, enforced at parse time** with named errors: a profile cannot
   remove a built-in, loosen redaction, disable the frozen always-on captures
   (exec / network_connect / sensitive-read), or loosen entropy thresholds.
2. **Glob**: `path.Match` per segment (stdlib, no new deps); `**` matches
   zero-or-more whole segments; compiled at validation and memoized so an
   adversarial `**/`-chain can't cause a matching blow-up.
3. **Capture defaults to on** (D7 baseline); absence is carried as `*bool` nil.
4. `$SESSION_CWD` is expanded at session start, not parse time.
5. The shipped `profiles/*.toml` are the canonical source; the embedded mirror is
   kept identical by a test that fails the build on drift.
6. **Markers**: `CarryFields` is an allowlist (nothing outside it ever reaches
   the ledger); a permanent P7 denylist (text/prompt/completion/message/content/
   summary) can never be allowlisted.

**Test contract.** `TestShippedPacks_ParseAndValidate` validates every shipped
pack; the additive-only invariants, glob semantics/memoization, `$SESSION_CWD`
expansion, auto-select precedence, and the embedded-mirror match each have
dedicated tests.

---

## internal/session

**Purpose.** The attribution primitive — one cgroup-v2 leaf per session — plus
portable session-id generation, systemd drop-in generation, and honest adoption
caveats. The `Driver` interface keeps the Linux-only mechanism behind a portable,
fakeable seam.

**Public surface.**

| Symbol | Purpose |
|---|---|
| `NewSessionID(Clock)` | 26-char Crockford-base32 ULID (wraps `schema.NewSessionID`). |
| `Driver` (`CreateScope`, `AddProcess`, `DestroyScope`, `WatchEmpty`), `Scope`, `FakeDriver` | Portable cgroup-leaf placement; in-memory fake safe on darwin. |
| `SliceName`, `ScopeName`, `ScopeUnitName`, `DropIn(unit, scope)` | Fixed `rana.slice`; pure systemd drop-in string builder (reversible). |
| `AdoptMode`, `AdoptCaveats(mode)` | Honest per-mode caveats written into `session.start` (P4). |

**Invariants.**

1. Session ids are ULID-shaped; `schema.NewSessionID` is canonical.
2. The `Driver` interface is platform-agnostic so the systemd/cgroupfs
   implementations are thin shims; `FakeDriver` is safe on all platforms.
3. `systemd_linux.go` whitelists `godbus/dbus/v5`; no other D-Bus dependency
   without a contract review.
4. `DropIn` is a pure string builder (no I/O), producing a reversible drop-in
   under `rana.slice`.
5. **Adoption caveats are honest** (P4): PID-mode records that pre-migration
   history, pre-existing fds, and pre-adoption activity are *not* recorded.

**Test contract.** ULID length/charset under injectable clocks; `FakeDriver` with
a created-scope audit trail; drop-in path/content, scope/slice naming, per-mode
caveats, and the `Driver` error semantics each tested — no real sleeps, no Linux
required.

## internal/service

**Purpose.** The user-owned process that assembles the ledger writer, the ranad
wire-frame server, the per-session marker socket, the content-digest worker, the
alert engine, and the localhost timeline HTTP host (docs/ARCHITECTURE.md §2).

**Public surface.**

| Symbol | Purpose |
|---|---|
| `Service`, `NewService(Config)` | Top-level assembly over `ledger.Writer`. |
| `Config` (incl. `OnFault func(error)`) | Required: LedgerDir, Profile, Session, LaunchToken; optional Clock, OnFault, RequireRanadUID. |
| `Service.RanadHandler` / `RanadServer` | Accept ranad-role connections; persist kernel events; broadcast checkpoints. |
| `Service.StartMarkerListener` / `MarkerListener` | Per-session unix socket → validated, redacted `marker.*` events. |
| `Service.StartDigestWorker` / `DigestWorker` | mtime-scan close-write debounce → `fs.settle` events. |
| `Service.EmitSessionStart` / `EmitSessionEnd` | Session lifecycle; `EmitSessionEnd` seals and `BroadcastSessionEnd`. |
| `Service.TimelineHandler` / `TimelineHost` | localhost bearer-gated timeline host (caller binds 127.0.0.1). |
| `GenerateLaunchToken`, `NewSessionMarkerSocket` | `crypto/rand` per-launch/per-session credentials. |

**Invariants.**

1. Markers always carry `origin=enrichment` and are redacted before the event is
   built (P7/P3); the marker token is a connection-level secret checked
   constant-time on **every** line, so an inherited fd without the token can
   inject nothing.
2. The digest worker debounces on **mtime-scan** (two consecutive unchanged
   scans = settled); paths are redacted before emission; it emits no
   delete-class event (not asked for by contract).
3. **P5 across all ingress**: kernel, marker, and digest append/observe faults
   all reach `Config.OnFault` — the kernel path via `RanadServer.OnDecodeError`,
   the marker/digest paths via `Service.reportFault` (the listener/worker still
   discard the returned error to keep serving, but the fault is surfaced, not
   lost).
4. The ranad socket is peer-uid gated (`RequireRanadUID`); a hostile/malformed
   frame fails itself and must **not** take down the whole ranad↔svc link.
5. The timeline host binds localhost only and requires the per-launch bearer
   token (constant-time) on every route; there is **no listening TCP** exposed
   beyond that.

**Test contract.** A fake ranad peer over `net.Pipe` drives real wire frames to a
verified ledger; a fake marker sender over a real unix socket exercises token +
redaction + hostile-line rejection; a fake filesystem drives the digest debounce;
the HTTP host is tested over a real loopback listener; `OnFault` is asserted to
receive marker/digest ingress faults. Fake clock throughout (no real sleeps).

---

## internal/ui

**Purpose.** The embedded, localhost-only timeline: the "event river" lanes
(process / filesystem / network), session picker, run-cluster causality view, and
live SSE tail (plan D19). Served by internal/service's timeline host.

**Public surface.**

| Symbol | Purpose |
|---|---|
| `Handler()` | localhost HTTP handler; per-launch bearer token on every route. |
| `DataSource` | Storage-agnostic: `Sessions`, `Events`, `Alerts`, `Stream`; real impl over the ledger. |
| `SessionSummary` | Compact per-session listing (id, profile, started/ended ns). |
| Routes | `/`, `/api/sessions`, `/api/events`, `/api/alerts`, `/api/stream` (SSE). |

**Invariants.**

1. **Constant-time bearer auth** on every request (header, or `token` query for
   SSE which can't set headers).
2. **No content capture, no third-party egress** (P7): CSP `default-src 'self'`,
   no cookies, no CORS; one same-origin bundle embedded via `go:embed` (built
   without Node at `go build` time); security headers (`nosniff`, `DENY`,
   `no-referrer`) on every response.
3. **The live tail is inert** (P2 extended to the UI): `DataSource.Stream` closes
   its channel when the context is done and MUST NOT back-pressure the capture
   pipeline — a slow reader can only hurt itself.

**Test contract.** An in-memory fake `DataSource` (no real ledger) exercises
token auth, CSP/security headers, JSON shape, and stream cleanup on context
cancellation.

---

## internal/vm (macOS)

**Purpose.** The macOS microVM lifecycle via Virtualization.framework: guest
boot/stop, virtiofs path projection, the vsock control/data plane, and
vsock↔TCP port-forwarding for adopted services (plan D15/D16). The only CGO in
the tree (vz).

**Public surface.**

| Symbol | Purpose |
|---|---|
| `GuestConfig` (`KernelCmdline`, `VirtiofsTags`, `Validate`) | Pure guest-config value type; deterministic builders. |
| `Mount`, `VirtiofsTag`, `DefaultGuestUID` (1000) | Host→guest projection; guest runs non-root. |
| `PathXlate` (`GuestToHost`, `HostToGuest`) | Longest-prefix, traversal-safe path translation. |
| `PortForward` (`Serve`, injected `Dial`) | Byte-transparent vsock↔TCP relay; no inspection (P2). |
| `BaseLayer` (`Verify`), `RuntimeLayerFetcher` (`Fetch`, `FetchSignature`) | Checksum-pinned base image; fetch-once-signature-checked runtime layer. |
| `VMConfig`, `Machine` (`SaveState`/`RestoreState`, arm64-only) | darwin+cgo boot/stop; warm save/restore on Apple Silicon only. |

**Invariants.**

1. Path translation **prevents `../` escapes**: `GuestToHost` rejects components
   that escape a tag's `HostRoot`; longest-prefix match prevents cross-mount
   traversal; `PathXlate` is immutable and concurrency-safe after construction.
2. **No real vsock in tests**: `PortForward` takes an injected dialer; tests use
   `net.Pipe`. Config builders are pure and golden-tested (sorted virtiofs tags,
   deterministic kernel cmdline).
3. The guest uid is non-zero (`Validate` enforces) — the guest agent never runs
   as root.
4. Save/restore is **arm64-only**; the amd64 file is a stub returning
   `ErrSaveRestoreUnsupported`.
5. The base layer is checksum-pinned (BLAKE3-256) and embedded; the runtime
   layer is fetched once and signature-checked before use — a bad signature
   fails closed.

**Test contract.** Golden path-translation round-trips (incl. `../`-escape and
duplicate-tag rejection); `GuestConfig.Validate`/cmdline/tag-order tests;
`net.Pipe` port-forward byte-relay; `t.TempDir` file-based image tests with an
injected fetch (no real network).

---

## cmd/rana

**Purpose.** The user-facing CLI and the in-process session-service host for
recording, inspecting, and verifying agent activity.

**Public surface — the frozen verb set (D20).** No new top-level verb is added;
new capability lands as a flag on an existing verb.

| Verb | Purpose |
|---|---|
| `run` | Execute a command in a recorded session under a profile. |
| `adopt` | Attach an already-running agent to a new recorded session. |
| `ps` | List recorded sessions (profile, start, state). |
| `timeline` | Open the localhost token-gated timeline UI (127.0.0.1 only). |
| `show` | Print session events; `--diff` reports on-disk availability (never content). |
| `tail` | Live-stream session events to stdout. |
| `verify` | Recompute the chain: exit `0` intact, `2` broken, `3` incomplete. |
| `export` | Write a proof pack (`--format proof`, default) or a Markdown `incident` report; `--pack` bundles. |
| `gc` | Compact sealed segments past the retention TTL into zstd archives. |
| `doctor` | Report capability tier + ledger health; `--report` prints the trust card. |
| `vm` | Manage the macOS Linux guest (macOS only; a no-op notice on Linux). |

**Invariants.**

1. The verb set is **frozen** (D20).
2. **`adopt` never reads environ** (P3): detection reads `/proc/<pid>/comm` and
   `/proc/<pid>/cmdline` (Linux) or `ps` (macOS) only, and auto-detect requires a
   corroborating signal (the profile's declared config dir exists) beyond a
   spoofable process name.
3. `show --diff` prints only a digest match/occurrence status, never file
   content.
4. `verify` exit codes map directly to the ledger verdict (docs/TRUST.md §6):
   `0`/`2`/`3`.
5. `doctor --report` reuses the exact building blocks of `doctor` + `verify`
   (`ledger.Verify` and the platform tier section) so the trust card cannot drift
   from what `verify` reports.
6. `defaultDataDir` reads only the CLI process's own config
   (`RANA_DATA_DIR`/`XDG_DATA_HOME`/`~/.local/share/rana`), never the recorded
   agent's environment.

**Test contract.** Verb logic is exercised through the internal package
boundaries (the full `ledger` record→verify round-trip, `report.IncidentReport`,
etc.); `detect.go` is unit-tested with an injectable process lister against
synthetic process lists.

---

## cmd/rana-verify-standalone, cmd/rana-verify-wasm, internal/exportverify

**Purpose.** The independent verifier of docs/TRUST.md §8: it reads a proof pack's
artifacts and re-derives every hash, Merkle root, segment-chain link, and Ed25519
signature from first principles. `internal/exportverify` is the shared pure-Go
core; the two `cmd/` binaries are a native CLI and a browser/WASM front-end over
it.

**Public surface.**

| Symbol | Purpose |
|---|---|
| `exportverify.VerifyExportDir/FS/Files` | Verify a proof pack from a directory, `fs.FS`, or in-memory byte map. |
| `exportverify.Result` | `Code` (0/2/3), `ReasonClass`, `Reason`, `UnattestedTail`, `ExternalPrevNotes`. |
| standalone `main` (`VerifyExportDir/Files`) | Native CLI; exit `0` OK / `2` broken / `3` incomplete. |
| wasm `globalThis.ranaVerifyExport(files)` | Synchronous JS entry point returning the verdict object. |

**Invariants.**

1. **Dependency wall**: the core imports only `internal/cborcanon`,
   `internal/chain`, and stdlib — **zero** sqlite, `internal/ledger`, or
   `internal/schema`. Verifying an export never requires trusting the rest of
   RanA.
2. **Second-implementation cross-check**: any disagreement with
   `ledger.Verify` on the same export is a spec bug to fix, not to paper over;
   the verifier deliberately shares no code path with it.
3. **Never panics on hostile bytes**: all uvarint parsing is
   integer-overflow-safe (uint64 lengths compared against the remaining buffer
   *before* any `int` conversion); every encoding error returns broken/incomplete.
4. **Hash the provided bytes, never re-encode** (docs/TRUST.md §8): leaf hashes
   come from the event's own CBOR bytes; segment grouping follows the
   header records' seal-time order, not the caller-supplied `seg` field.
5. Unattested-but-sealed segments are reported distinctly from both verified and
   broken.
6. The WASM build shares the identical core, makes **no** network call (D24), and
   captures nothing (P7) — it reads only the already-redacted artifacts the user
   drops on the page.

**Test contract.** The core builds a real export via `internal/ledger`
(test-only), corrupts each artifact class, and asserts the exact broken/incomplete
reason and exit code per docs/TRUST.md §8; a test pins the CLI's redeclared exit
constants to the core's values. The WASM path is covered through the shared core
plus the `assets/verifier` page.

---

## internal/report

**Purpose.** A pure-reader library that builds human-readable forensic reports
from already-recorded, already-redacted events. It never persists, never captures
model I/O, and never re-derives a kernel fact from anything but the recorded
stream.

**Public surface.**

| Symbol | Purpose |
|---|---|
| `IncidentReport(ctx, ds, sessionID)` | Markdown narrative: header, load-bearing timeline, run-cluster causality, LIMITS pointer. |
| `DigestDiff(tr PathTranslator, ev)` | Reconstruct before/after *availability* for an `fs.settle`, never content. |

**Invariants.**

1. **P7**: `IncidentReport` renders only frozen, documented event fields;
   marker events surface only fixed identifier/lifecycle fields (runId, agentId,
   channel, status), never the full Data map.
2. **P3**: every field read already went through redaction before encoding; the
   report reads it back, it does not re-derive.
3. `DigestDiff` never persists or transmits content — only a digest hex and a
   match/mismatch — and **refuses to read non-regular files** (symlink/device/
   FIFO) to avoid a blocking-read DoS.
4. The timeline merges `alert.*` from a separate `Alerts()` call (in case
   `Events()` paginated) and sorts by Idx.
5. It **points at** `LIMITS.md` but never restates it, so the two cannot drift
   into contradiction (P10/P4).

**Test contract.** Driven against a synthetic in-memory `DataSource`; `DigestDiff`
is tested with an injectable `PathTranslator` and verified to refuse special
files via an `Lstat` check before reading.

---

*End of contracts. A new package MUST arrive with its section here in the same PR
(CLAUDE.md §3.3 Definition of Done); a citation to a `CONTRACTS §<package>` that
has no section here is a documentation bug.*
