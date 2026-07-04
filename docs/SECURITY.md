# Security Policy

RanA is a security and forensics tool; a vulnerability in it is worth more to an attacker than one in most software. We treat reports accordingly.

## Reporting a vulnerability

**Do not open a public issue.** Report privately via GitHub Security Advisories on the RanA repository ("Report a vulnerability"). If that is unavailable, use the security contact published on rana.dev.

Include: affected version/commit, platform + kernel, reproduction steps, and your assessment of impact. Proof-of-concept exploits are welcome; live exploitation of third parties is not.

**Our commitments:** acknowledgment within 72 hours; a triage verdict within 7 days; a coordinated disclosure timeline agreed with the reporter (default 90 days, faster for anything touching the trust core); credit in the release notes unless you prefer otherwise. No bounty program at this stage — we are honest about that rather than vague.

## What counts as security-relevant here

Beyond the usual (RCE, privilege escalation via `ranad`, the UI):

- **Any way to make the ledger lie** — an event that can be suppressed *without* a `gap`, a mutation `rana verify` misses, a chain-mutation-suite bypass.
- **Any way for a secret to persist** — a string shape that survives redaction into a leaf hash is a critical vulnerability, not a bug (`P3`, gate G4).
- **Any way for observe mode to affect the workload** — a hook that can block, delay meaningfully, or alter a recorded process violates `P2` and is treated as critical.
- **Coverage claims that are false** — an undocumented attribution escape is a vulnerability in `LIMITS.md` (`P10`); report it the same way.

## Hardening posture (summary)

- `ranad` runs with minimal capabilities, no listening TCP sockets, one SO_PEERCRED-gated unix socket, and a hardened systemd unit. See `docs/THREAT-MODEL.md §4`.
- The ledger, signing key, and UI live at user privilege; the root daemon never touches them — except the root-owned checkpoint-head mirror, which exists precisely to bound same-uid tampering (`LIMITS.md §6.1`).
- Releases are reproducible-built, cosign-signed, ship an SBOM, and contain no postinstall scripts. Verify the signature before installing a root daemon — including this one. `install/get-rana.sh` (the `curl | sh` one-liner) does this for you when `cosign` is on `PATH`: it downloads each asset's `.sig`/`.pem` alongside the checksum and runs `cosign verify-blob` against the release workflow's GitHub Actions OIDC identity, on top of (not instead of) the SHA256 checksum check. The checksum alone only proves the download wasn't corrupted in transit — since `SHA256SUMS` and the binaries are served from the same host, it does *not* by itself prove the release wasn't tampered with at the source; the cosign step is what proves provenance. If `cosign` isn't installed, the script prints a loud warning and falls back to checksum-only verification — it never silently downgrades. Set `RANA_REQUIRE_COSIGN=1` to make the installer fail closed (abort) instead of warning when cosign is missing or verification fails.
- No telemetry, no phone-home, no auto-update. RanA makes no network call on its own behalf at all today. The plan (D24) reserves an explicit, opt-in `rana doctor --check-update` as the only acceptable future exception to "no update check by default"; it is not implemented yet — until it lands, there is no update-check code path of any kind, not even a documented flag to opt into.
