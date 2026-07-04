# Contributing to RanA

RanA is a security and forensics tool. Contributions are held to that bar: the person who trusts the record must be right to.

## Ground rules
- **License & sign-off:** Apache-2.0. Every commit needs a DCO `Signed-off-by` line (`git commit -s`). No CLA.
- **The execution contract is binding.** `CLAUDE.md` governs. If your change conflicts with a binding decision, open an issue proposing a versioned amendment first — don't work around it silently.
- **Scope walls are real.** See `CLAUDE.md §2`. Prompt/completion capture, TLS interception, telemetry, Windows, and v1 enforcement are out of scope by definition. PRs adding them are declined regardless of quality.

## The workflow
- **Strict TDD.** No production code without a failing test first (`CLAUDE.md §3.1`). PRs without tests are not reviewed.
- **The trust core** (`internal/redact`, `internal/ledger`) is held to the strictest bar. Changes there get an explicit threat note in the PR body: *what surface does this touch, and why is it still safe?*
- **Gates are CI-enforced.** G1/G4/G5/G7 are regression gates from Phase 1. A PR that regresses one fails the build. Don't disable a gate to make CI green — fix the regression or justify a threshold change via a versioned amendment.
- **Honesty is a feature.** If you discover a new attribution escape or blind spot, add it to `LIMITS.md` in the same PR that discovers it.

## Getting started
```sh
make gen && make build && make test     # see CLAUDE.md §5 for the full command set
make doctor                             # confirm your kernel's capability tier
```

## Reporting security issues
Do not open a public issue for vulnerabilities. See `docs/SECURITY.md` for private disclosure.

## A note on new verifiers
An independent implementation of the chain verifier (`docs/TRUST.md §8`) in another language is an especially welcome contribution. The spec, not RanA's code, is authoritative — a second implementation that agrees strengthens the whole guarantee.
