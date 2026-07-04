# Redaction — Normative Specification

Redaction is the single most important safety property in RanA and the one most easily gotten wrong. An append-only, tamper-evident ledger makes everything it captures **permanent** — you cannot scrub a leaked token later without breaking the chain you're selling. Therefore secrets must never be captured in the first place.

This spec is **normative**. It cannot be disabled (`P3`). The pipeline runs at **every writer ingress**: in `ranad` between decode and the socket send (kernel events — raw secret bytes exist only transiently in `ranad` RAM, never on disk, never over the socket), **and** in the session service over every string that reaches the writer from any other source — marker fields, session metadata (adopt argv, host fingerprint strings), and digest-worker paths. Markers never transit `ranad`, so a ranad-only pipeline would be a hole; it is the same library in both processes.

**Ordering guarantee (the crux):** redaction completes *before* an event is handed to the writer, therefore *before* it is encoded and hashed. The writer, by construction, accepts only an already-redacted type — a raw string cannot reach a leaf even by programmer error, from either process.

---

## Stage 1 — Environment exclusion (absolute)

- eBPF programs never read `envp`.
- `ranad` never reads `/proc/<pid>/environ`.
- No code path captures environment *values*. (Variable *names* may appear in a future opt-in; values never.)

This is enforced by a grep-able CI check (`CLAUDE.md §6.1`) and by the simple fact that no function in the codebase takes the environment as input.

Redaction stages 2–4 run on everything else that is a string: `argv`, file paths, DNS qnames, URLs inside markers, and any string field of any event.

## Stage 2 — Structural pattern set

Ordered, applied first (cheap, high-precision). The built-in set is **additive-only**: profiles may *add* patterns, never *remove* built-ins.

**Cloud / provider keys**
- AWS access key: `(AKIA|ASIA)[0-9A-Z]{16}`
- AWS secret (contextual): 40-char base64 following `aws_secret`/`SecretAccessKey`
- GCP API key: `AIza[0-9A-Za-z\-_]{35}`
- Azure: storage/connection-string secret shapes
- OpenAI / Anthropic: `sk-[A-Za-z0-9]{20,}`, `sk-ant-[A-Za-z0-9\-]{20,}`
- GitHub: `gh[posru]_[A-Za-z0-9]{36,}`
- Slack: `xox[baprs]-[A-Za-z0-9-]{10,}`; incoming-webhook URLs `hooks.slack.com/services/<team>/<channel>/<token>` (the triple is the secret span — added after an adversarial pass showed its `/`-segments individually duck the entropy bar)
- Stripe: `[sr]k_live_[A-Za-z0-9]{24,}`
- Google OAuth: `ya29\.[0-9A-Za-z\-_]+`

**Tokens & structured secrets**
- JWT: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`
- PEM private-key headers: `-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`
- Bearer headers: `(?i)authorization:\s*bearer\s+\S+`

**Generic inline credentials**
- `(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*\S+`
- Connection strings with inline creds: `[a-z]+://[^:/\s]+:[^@/\s]+@` (redact the `user:pass@` span)
- `.env`-style `KEY=<high-entropy value>` (value handed to Stage 3)

**Credential-file path bodies**
- Keep the *fact* that `~/.ssh/id_ed25519` was touched; redact any token-shaped basename within a path.

## Stage 3 — Entropy pass

Catches secrets the pattern set doesn't name.

- A token (whitespace/`=`/`:`-delimited) of **length ≥ 20** with **Shannon entropy ≥ 4.0 bits/char** and not a dictionary word → redact.
- Base64-looking or hex-looking blobs of **length ≥ 32** → redact.
- **Paths are not exempt** — they are evaluated *per segment*: each path component is a candidate token against the same thresholds, so `/tmp/upload/<base64-token>` is caught while `/usr/lib/x86_64-linux-gnu` is not (ordinary components fail the entropy/length bar, and known-benign shapes — git object hashes in `.git/objects/ab/cdef…`, content-addressed store paths — are allowlisted by *context*, not by being paths). This is what makes Stage 2's "redact token-shaped basenames" rule a special case of a general one rather than a contradiction of an exemption.
- Thresholds are tunable **stricter** per profile (lower length, higher entropy) — never looser.

Entropy is computed over the candidate token or path segment only, so ordinary prose and normal paths are not flagged.

## Stage 4 — Typed replacement

A redacted span is replaced with a structured marker that preserves *type* and *shape* for analysis while leaking nothing:

```
⟦R:<class>:<lenclass>:<checksum>⟧
```

- `class` ∈ `{ awskey, gcpkey, openaikey, anthropickey, ghtoken, slacktoken, stripekey, jwt, pem, bearer, connstring, entropy }`
- `lenclass` ∈ `{ s, m, l, xl }` (bucketed length — never the exact length, which can itself be identifying)
- `checksum` = the low **32 bits** of `BLAKE3( value ‖ per-ledger-random-salt )`, rendered as 8 hex characters

**Why the salted checksum:**
- Two identical secrets *within one ledger* produce the same `checksum`, so an analyst can see "the same token was used in these three places" — a useful correlation hint. At 32 bits, two *different* values collide into the same marker only ~1 in 4 billion times, so the hint is reliable rather than birthday-prone (a 16-bit checksum collided at ~1/65536 — frequent enough in a busy ledger to fabricate a "reused credential" inference).
- The checksum is a **truncated cryptographic hash keyed by a per-ledger random salt**, so it is useless across ledgers (different salt) and exposes **no algebraic structure**. This is a deliberate choice over a CRC: a CRC is GF(2)-affine, so each marker would leak one linear equation over the salt bits and the salt could be recovered by Gaussian elimination from enough known-plaintext markers. A BLAKE3 truncation is not linearly invertible.

**What a marker does and does not protect (honest scope):**
- The salt lives with the ledger and is **never exported** (`docs/TRUST.md §7`). A recipient of a shared export who does **not** have the salt cannot correlate a marker back to a candidate value, and cannot correlate the same *unknown* value across two exports made with different salts.
- A marker does **not** hide that the same value appears twice *within one export* — identical value → identical marker, by design (that is the correlation feature).
- A marker is **not** a commitment scheme. Against someone who holds the salt (the exporter always retains it, and a same-uid attacker can read it), a marker is a 32-bit oracle: a guessed low-entropy value can be confirmed by recomputing the checksum. The real secrecy guarantee is that **the raw value never leaves `ranad` RAM** — not that the marker is unguessable. (`LIMITS.md`.)

## The corpus method (gate G4)

`test/redaction-corpus/` is a permanent regression gate, not a one-time test.

- **≥ 500 seeded secret shapes**: real-format synthetic keys for every provider above, JWTs, PEM blocks, connection strings, `.env` dumps, and adversarial cases (secrets split across argv boundaries, secrets in unusual encodings, near-miss high-entropy non-secrets that must **not** be redacted to bound false positives).
- **Recall gate: ≥ 99%** of seeded secrets must be redacted with the built-in set. Every miss is (a) a build failure until triaged and (b) catalogued, so a shape that slips once is caught by an added pattern forever after.
- **Precision floor**: the corpus includes benign high-entropy strings (git SHAs, UUIDs, base64 image fragments in paths) that must survive un-redacted beyond a small budget, so the entropy pass doesn't shred normal data into uselessness.
- **The load-bearing assertion**: any test in the entire suite in which a *raw* seeded secret reaches a leaf hash is an immediate build failure — this is what makes "secrets never persist" a mechanical fact rather than a hope.

## Residual risk (stated, not hidden)

The residual is real and enumerated in `LIMITS.md §4`. In short:

- **Context-free short values.** A bare secret with no adjacent keyword and too little structure to detect — a lone 4–6 digit PIN/OTP (`483920`), or a bare base64 token under ~24 chars — cannot be redacted without also redacting every benign number and short identifier, which would gut the timeline. *Labelled* short secrets (`pin=…`, `otp=…`, `card …`, `--password …`) are caught structurally; the bare, contextless case is the limit.
- **Path-shaped allowlist, provenance-gated.** The entropy pass allowlists content-addressed path segments (`…/objects/<hash>`) so it doesn't shred the paths a file event exists to record — but only when the path is kernel-`resolved` (`path_source=resolved`, D7). On an agent-`claimed` path the allowlist is off, so a crafted `…/objects/<hex-secret>` is redacted. Residual: a malicious agent that *creates* a real file named after a hex-encoded secret (a covert channel, out of scope), and a secret formatted as an exact v4 UUID (below the entropy bar — unredactable without shredding all UUIDs). Structural provider patterns run on every segment regardless.
- **Novel formats** before their structural pattern is added — the entropy net catches most; misses are catalogued and become permanent corpus rows.

What can **never** leak: environment values (never captured), and already-redacted spans (raw bytes never leave `ranad` RAM). If a threat model can't tolerate the path-embedded residual, don't point digest scopes at directories containing such paths.
