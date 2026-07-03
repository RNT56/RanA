# Trust — Chain Specification & Independent Verification

This is the normative specification of RanA's tamper-evidence. It defines exactly how events become a verifiable chain, what `rana verify` checks, and how a **third party with no RanA installed** can verify an exported session. If the implementation and this document disagree, that is a bug in one of them; file it.

The guarantee, precisely: **any modification, deletion, reordering, or re-signing of persisted events is detectable.** Not prevented — detected. See `LIMITS.md §6` for the root-adversary boundary.

---

## 1. Canonical event encoding

Every event is encoded to a **deterministic byte string** before hashing. Determinism is the whole game — two encoders MUST produce identical bytes for the same event.

- Format: **CBOR** (RFC 8949) in **canonical form**: map keys sorted bytewise, shortest-form integer encoding, no indefinite-length items, no floating point (timestamps are integer nanoseconds).
- Fields are fixed per event type (see `docs/ARCHITECTURE.md §5` and plan §4.3). Strings are **already redacted** (`docs/REDACTION.md`) at encode time — the encoder never sees a raw secret.
- Timestamps: each event carries `(ts_mono, ts_wall)` as integer nanoseconds, both captured in-kernel.

Encoding is stable across RanA versions: a v1.3 verifier can verify a v1.0 ledger. New event types add new keys; they never change the encoding of existing types.

## 2. Leaf hash

```
leaf = BLAKE3( canonical_cbor(event) )       # 32 bytes
```

BLAKE3 chosen for speed (keeps `verify` O(events) and fast at millions of events — gate G1's cousin) and a clean tree mode.

## 3. Segments and the Merkle root

Events are grouped into **segments**. A segment seals when it reaches **4096 events** or **60 seconds after its first event**, whichever first (also on `session.end`).

- Compute a binary Merkle tree over the segment's ordered leaf hashes:
  ```
  merkle_root = merkle( [leaf_0, leaf_1, ..., leaf_n-1] )
  ```
  - Duplicate the last node when a level has odd length (standard).
  - Domain-separate leaf vs. internal nodes to prevent second-preimage tricks:
    ```
    node = BLAKE3( 0x01 || left || right )     # internal
    leaf = BLAKE3( 0x00 || canonical_cbor(event) )   # (the 0x00 prefix is part of §2)
    ```

## 4. Chaining segments

Each segment has a **header** that binds it to its predecessor:

```
seg_header = {
  session_id,
  seg_index,
  first_rowid, last_rowid,
  event_count,
  merkle_root,
  prev_seg_hash,          # BLAKE3 of the previous segment's header (genesis: 32 zero bytes)
  gap_summary,            # counts by reason: ringbuf_full / governor / daemon_restart
  sealed_at_wall
}
seg_hash = BLAKE3( canonical_cbor(seg_header) )
```

`prev_seg_hash` makes the segments a hash chain: altering any sealed segment breaks every segment after it.

## 5. Signed checkpoints

Every **64 segments**, every **5 minutes** while sealed-but-unsigned segments are pending, and at `session.end`, RanA writes an Ed25519 checkpoint:

```
checkpoint = {
  session_id,
  seg_range: [first, last],
  chain_head: seg_hash(last),
  prev_checkpoint_hash,     # BLAKE3 of the previous checkpoint in the WHOLE LEDGER
                            # (across sessions; genesis: 32 zero bytes)
  signed_at_wall,
  pubkey_id
}
signature = Ed25519_sign( device_private_key, canonical_cbor(checkpoint) )
```

- The **device key** is generated at first run, stored `0600`, optionally passphrase-wrapped. The private key never leaves the machine and is never in an export.
- `prev_checkpoint_hash` makes the checkpoints one **ledger-wide chain**: segments chain *within* a session; checkpoints chain *across* sessions. Deleting an entire session wholesale therefore breaks the checkpoint chain and is detected — a per-session-only design would not see it.
- The **unattested tail**: segments sealed after the last checkpoint are hash-linked but not yet signed. `verify` reports them as *unattested* — a normal, expected state for recent data (bounded to ≤5 minutes by the checkpoint timer), distinct from both "verified" and "broken."
- **Head mirror (same-uid custody, plan D27):** at each checkpoint, the session service reports `(session_id, seg_range, chain_head)` to `ranad`, which appends it to a **root-owned, append-only** `/var/lib/rana/heads.log`. The user-owned key can be stolen by an attacker with the user's uid; heads mirrored *before* the compromise are pinned beyond that attacker's reach. `rana verify --mirror` cross-checks. See `LIMITS.md §6.1`.
- Checkpoints bind the chain to an identity and bound the rewrite window: to forge history, an attacker must re-sign every checkpoint from the tampered point forward (requires the private key) **and** match every mirrored head (requires root).

## 6. What `rana verify` checks

`rana verify [--session S]` streams the ledger and confirms, in order:

1. **Leaf recomputation** — re-encode each event, recompute its leaf, compare. Catches any field edit.
2. **Merkle recomputation** — rebuild each segment's tree, compare `merkle_root`. Catches insertions/deletions/reorders within a segment.
3. **Chain linkage** — recompute each `seg_hash`, confirm `prev_seg_hash` matches. Catches segment-level tampering.
4. **Signatures & checkpoint chain** — verify every checkpoint signature against the recorded pubkey, and confirm `prev_checkpoint_hash` continuity across the whole ledger. Catches re-signing without the key *and* wholesale session deletion.
5. **Gap honesty** — confirm every claimed `gap` is internally consistent and that row continuity matches segment bounds.
6. **Mirror cross-check** (`--mirror`, when run on the recording machine) — every entry in the root-owned `heads.log` must match the ledger's checkpoint at that position. Catches a rewrite-and-re-sign by an attacker who obtained the user-owned key (`LIMITS.md §6.1`).

Segments sealed after the last checkpoint are reported as an **unattested tail** (recent, expected, ≤5 min of data) — verified for hash-linkage, not yet identity-bound.

**Exit codes distinguish two very different outcomes:**

| Code | Meaning |
|---|---|
| `0` | Chain intact. History is complete-within-scope or has **honest, recorded gaps**. |
| `2` | **Broken chain** — a leaf/root/link/signature mismatch. Someone altered persisted history. |
| `3` | Chain intact but **verification incomplete** (e.g. a referenced cold archive is missing). Neither trust nor alarm — fetch the archive. |

A gap-bearing history returning `0` is the point: RanA never pretends a gap didn't happen, and an honest gap is not a tamper.

## 7. Export format (portable proof)

`rana export --session S out/` writes a directory a third party can verify with **no RanA installed**:

```
out/
├── events.cbor         # AUTHORITATIVE: length-prefixed canonical-CBOR events (redacted), in order
├── events.jsonl        # human-readable convenience, derived from events.cbor — never hashed
├── segments.cbor       # every seg_header, canonical CBOR (+ segments.jsonl convenience)
├── checkpoints.cbor    # every checkpoint + signature (+ checkpoints.jsonl convenience)
├── pubkey.pem          # the device public key (NOT the private key, NOT the ledger salt)
└── manifest.json       # format version, hash/sig algorithms, session fingerprint
```

**Why CBOR is the verification artifact and JSON is not:** timestamps are int64 nanoseconds (~1.8 × 10¹⁸), beyond JSON's 2⁵³ integer precision. A verifier that re-encoded JSON into CBOR would compute different bytes and report false tampering. So the canonical bytes themselves are exported, the verifier hashes them directly, and the JSONL exists purely for human eyes. (The bytes can't be forged to disagree with the JSONL *and* still verify — they are pinned by the Merkle roots and signatures; treat the JSONL as a rendering, the CBOR as the record.)

The **redaction salt is never exported** (`docs/REDACTION.md`) — redaction markers in an export cannot be correlated back to secrets even by the exporter's future self.

## 8. Independent verifier specification

Anyone can implement this in ~a page in any language. RanA ships a reference `rana-verify-standalone` (single static binary, ~a few hundred lines) but the spec is the contract:

```
INPUT:  an export directory (§7)
OUTPUT: OK | BROKEN(reason) | INCOMPLETE(reason)

1. Parse manifest.json; confirm format_version and algorithm identifiers are recognized
   (hash = BLAKE3, sig = Ed25519, encoding = canonical-CBOR-RFC8949).

2. For each length-prefixed record in events.cbor:
     ASSERT the bytes are well-formed canonical CBOR (RFC 8949 §4.2)   else BROKEN(encoding)
     leaf = BLAKE3(0x00 || record_bytes)          # hash the provided bytes; do NOT re-encode
     accumulate leaves grouped by the event's seg index.

3. For each seg_header record in segments.cbor:
     recompute merkle_root over that segment's accumulated leaves (§3, with 0x01 internal prefix)
     ASSERT recomputed merkle_root == seg_header.merkle_root         else BROKEN(merkle, seg)
     seg_hash = BLAKE3(seg_header record_bytes)
     ASSERT seg_header.prev_seg_hash == seg_hash(previous)           else BROKEN(chain, seg)
       (genesis prev_seg_hash == 32 zero bytes)

4. For each checkpoint record in checkpoints.cbor:
     ASSERT Ed25519_verify(pubkey.pem, checkpoint_without_sig bytes, signature)
                                                                     else BROKEN(signature, ckpt)
     ASSERT checkpoint.chain_head == seg_hash(checkpoint.seg_range.last)
                                                                     else BROKEN(head_mismatch, ckpt)
     ASSERT checkpoint.prev_checkpoint_hash chains from the previous
     exported checkpoint (single-session exports: the first checkpoint's
     prev refers to a checkpoint outside the export — record it as an
     EXTERNAL-PREV note, verifiable against the source ledger)          else BROKEN(ckpt_chain)

5. If any seg referenced by a checkpoint range is absent from segments.cbor → INCOMPLETE.
   Events after the last checkpoint → report as UNATTESTED TAIL (not BROKEN).

6. All assertions pass → OK.
```

**Design consequences worth stating:**
- Verification needs only the public key and the exported data. The exporter cannot forge a passing export they didn't legitimately record, because forging requires the private key (step 4).
- Verification reveals **effects, not secrets**: the export is already redacted, and the salt is withheld, so handing an export to an auditor leaks the *shape* of what the agent did, never credentials.
- A verifier in a different language is a valid, encouraged contribution — the spec, not RanA's code, is authoritative.

## 9. Retention and archives

`rana gc` compacts sealed segments to zstd cold archives. Chain continuity is preserved by leaving **checkpoint stubs** that reference archived segment roots, so `verify` over live data returns `0`, and `verify` that needs an archived range returns `3` (INCOMPLETE) with the archive path — never a false `2`.
