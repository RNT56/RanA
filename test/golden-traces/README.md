# Golden traces (eBPF fixture corpus)

This directory holds the **deterministic fixture corpus** for the eBPF programs
and the profile engine: *known input → known output*, checked byte-for-byte so a
change to a BPF program, the record decoders, or a shipped profile that alters
the recorded timeline is caught as a diff.

It backs the eBPF test contract in `CLAUDE.md §3.1` ("each program has a
deterministic fixture: known syscalls in → known events out") and the profile
test contract in `docs/PROFILES.md` ("a profile PR must include a golden-trace
test showing the profile applied to a recorded fixture produces the expected
digest scopes, watchlist, and lens").

## Two fixture kinds

1. **Program traces** — for `internal/bpf` / `internal/collector`. Each fixture
   is a pair:
   - `<name>.trace` — a recorded sequence of raw kernel records (the exact bytes
     a BPF program's ring buffer would emit for a known syscall sequence), and
   - `<name>.events.json` — the canonical `schema.Event` stream the collector
     must produce from that trace after redaction and enrichment.

   The harness feeds `<name>.trace` through the real
   `internal/collector` decode+enrich path (no kernel required — the trace *is*
   the ring-buffer output) and asserts the result equals `<name>.events.json`
   exactly, including `origin`, ordering, and any `gap` events. This is how the
   BPF→collector contract is regression-tested off a Linux host.

2. **Profile traces** — for `internal/profile`. Each fixture applies a shipped
   profile to a recorded session trace and pins the resulting digest scopes,
   watchlist, and alert lens, so an edit to a profile pack that widens or
   narrows what a session records shows up as a golden diff (profiles are
   additive-only; a golden change that *removes* coverage is a review red flag).

## Status

The **fixture format and harness contract are defined here**; the recorded
program-trace corpus is captured on Linux CI, where the real eBPF programs are
loaded against the LTS-kernel matrix (`make gen` produces the CO-RE objects) and
their ring-buffer output is snapshotted deterministically. The recorded traces
are **not generated on the macOS dev host** — it has no bpf ring buffers to
snapshot — which is the same Tier-1 boundary documented in `LIMITS.md §8` for
"actual kernel capture." Profile golden traces, which need no kernel, may be
added independently.

A fixture is only valid if it is **reproducible**: regenerating it from the same
kernel + BPF objects must produce identical bytes. A non-deterministic trace is
a corpus bug, not a fixture.
