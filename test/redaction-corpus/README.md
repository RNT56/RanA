# Redaction corpus (gate G4)

`corpus.jsonl` is the permanent regression corpus for `internal/redact` — ≥500
seeded secret shapes plus benign near-misses. It enforces gate **G4** (recall
≥99%, benign-precision floor, and the load-bearing *zero raw secret reaches a
leaf* property). See `docs/REDACTION.md` "The corpus method".

## Why secrets are stored obfuscated

A secrets-redaction tool must test against **format-valid** synthetic
credentials. But committing literal, format-valid keys to a public repo trips
platform secret-scanning push-protection (rightly) and is self-defeating for
*this* project specifically.

So every secret-bearing field is stored obfuscated and decoded deterministically
at test load — no RNG, fully reproducible:

- Each row is `{"enc":"xb64", "input":"…", "secrets":[…], "spans":[…], "must_redact":bool, "kind":…}`.
- `enc:"xb64"` means `input` and each `secrets` entry are
  `base64( cyclicXOR(plaintext, key="rana-corpus-xor-key") )`.
- The XOR (not plain base64) is deliberate: scanners base64-decode, so base64
  alone would still expose the key. XOR-then-base64 yields only noise to a
  decoder. It is **not** a security boundary — just scanner/hygiene avoidance.
- The loader (`internal/redact/corpus_test.go`, `decodeCorpusField`) and the
  inline test helper (`xs` in `secrets_test.go`) reverse it.

## Adding entries

Never paste a literal format-valid secret into this file or any `_test.go`.
Encode it first (base64 of cyclic-XOR with the key above) and store it as
`xb64`, or use the `xs("…")` helper inline in Go tests. Benign near-misses that
are genuinely not credentials (git SHAs, UUIDs) may stay plaintext with
`must_redact:false`.

A miss found once must become a permanent entry here (`docs/REDACTION.md`): the
catalogue → pattern → gate loop is how coverage only ever grows.
