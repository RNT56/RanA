# Profiles — Authoring Guide

Profiles are RanA's opinion layer: everything else is mechanism. A profile is a TOML pack that tells RanA how to *recognize* an agent, what to *digest*, which extra paths are *sensitive*, how to *enrich* causality, and how the timeline should *read*. Shipped packs: `generic`, `claude-code`, `codex`, `openclaw` (`profiles/`).

The hard rule before any syntax: **profiles can only make RanA stricter or richer, never blinder.** They may *add* sensitive paths, *add* redaction patterns, *tighten* entropy thresholds, and *scope* digests. They cannot remove built-ins, loosen redaction, or disable capture classes below the D7 baseline. A profile that tries is rejected at load with a named error.

---

## Sections

### `[profile]`
`name`, `description`, `version` (integer, bump on any behavior change).

### `[match]`
How `rana` recognizes the agent when no `--profile` is given: `exe_basename` (list), `argv_contains` (list), `auto` (bool — whether this profile may be selected automatically). Matching is a convenience, not attribution — attribution is always the cgroup.

### `[adopt]`
Optional. Present only in packs that `rana adopt <profile>` knows how to take over in place (currently just `openclaw`). It parameterizes that lifecycle; it does not affect what RanA captures. Fields:
- `config_dir` — the agent's on-disk config root, used to detect an existing install (openclaw: `~/.openclaw`).
- `gateway_port` (integer) — the local port the adopted daemon binds, used for a liveness probe and, on macOS, host↔guest port forwarding.
- `linux_supervisor` — the init system whose unit is rewritten to place the daemon under `rana.slice` (e.g. `systemd`).
- `macos_supervisor` — the supervisor for the guest-hosted daemon on macOS (e.g. `launchd`).
- `consent_default` — the default answer to the adopt-time consent prompt (e.g. `yes`); the user can always decline interactively.

Adopt is opt-in and interactive: a profile carrying `[adopt]` still only takes effect when the user explicitly runs `rana adopt`. Packs without an `[adopt]` table are adopted generically (no supervisor rewrite).

### `[capture]`
Booleans per event class (`exec`, `fork_exit`, `file_write`, `file_meta_ops`, `network_connect`, `network_flow`, `unix_sockets`). These exist for future *narrowing within policy*; in v1 all shipped profiles keep the full D7 set on, and `exec`/`network_connect`/sensitive-read cannot be disabled by any profile.

### `[digest]`
`scopes` (globs) and `exclude` (globs). Content digests (BLAKE3 on close-write) are computed **only** inside scopes — they cost I/O and touch file contents, so scope them where before/after evidence matters: the agent's workspace, the repo working tree. `$SESSION_CWD` expands to the directory the session started in.

### `[sensitive_read]`
`extra` — paths appended to the built-in in-kernel watchlist (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config/gcloud`, browser profile dirs, RanA's own data directory, …). Additive only. A read of any watched path is the highest-signal event RanA records.

### `[redaction]` (optional)
`extra_patterns` — additional regexes redacted in Stage 2; `entropy_min_len` / `entropy_threshold` — may only be set *stricter* than the defaults (`docs/REDACTION.md §3`). Looser values are a load error.

### `[markers]`
`enabled`, `socket`, `events`, `carry_fields`, `forbid_fields`. Markers are enrichment (`origin=enrichment`) and identifier-only — `carry_fields` is an allowlist, `forbid_fields` a belt-and-suspenders denylist, and no field not in `carry_fields` ever reaches the ledger regardless. Message text, prompts, completions, and summaries are forbidden permanently (P7).

### `[timeline]`
`lens` (`tree` | `causality`), `cluster_by` (marker field, e.g. `runId`), `fallback_lens` (used when markers are absent; `inferred` clustering is *labeled* inferred in the UI — a heuristic is never dressed up as ground truth).

### `[retention]`
`ttl_days` — sealed segments older than this are `rana gc`-eligible (compacted to zstd cold archives; chain continuity preserved via checkpoint stubs — `docs/TRUST.md §9`).

## Validation & testing

`rana doctor --profile <file>` validates a pack: TOML shape, glob syntax, additive-only invariants, threshold direction. A profile PR must include a golden-trace test (`test/golden-traces/`) showing the profile applied to a recorded fixture produces the expected digest scopes, watchlist, and lens.

## Design intent (read before authoring)

A profile answers "what does a *stranger* need to see to understand what this agent did?" — not "what can we collect?" If a value would be a sensible default for everyone, it belongs in `generic` (P6). If it narrows visibility, it doesn't belong anywhere.
