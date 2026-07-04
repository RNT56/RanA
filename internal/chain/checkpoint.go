package chain

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"lukechampine.com/blake3"
)

// Checkpoint is an Ed25519-signed attestation over a range of a session's
// sealed segments (docs/TRUST.md §5). Checkpoints chain across the WHOLE
// ledger (not just within a session) via PrevCheckpointHash — deleting an
// entire session wholesale therefore breaks the checkpoint chain and is
// detected (the whole-ledger checkpoint chain).
type Checkpoint struct {
	SessionID          string
	SegFirst, SegLast  uint64
	ChainHead          [32]byte // seg_hash of the last segment in range
	PrevCheckpointHash [32]byte // BLAKE3 of the previous checkpoint body in the WHOLE LEDGER; genesis: 32 zero bytes
	SignedAtWall       uint64   // ns
	PubkeyID           string   // chain.KeyInfo.PubkeyID of the signing key
}

// checkpointWire is the canonical CBOR encoding of a Checkpoint's signed
// body, field names exactly as docs/TRUST.md §5 (snake_case; seg_range is
// encoded as a two-element array [first, last]).
type checkpointWire struct {
	SessionID          string    `cbor:"session_id"`
	SegRange           [2]uint64 `cbor:"seg_range"`
	ChainHead          []byte    `cbor:"chain_head"`
	PrevCheckpointHash []byte    `cbor:"prev_checkpoint_hash"`
	SignedAtWall       uint64    `cbor:"signed_at_wall"`
	PubkeyID           string    `cbor:"pubkey_id"`
}

// ErrInvalidSignature is returned by VerifyCheckpoint when the signature
// does not verify against the given public key and body.
var ErrInvalidSignature = errors.New("chain: checkpoint signature does not verify")

// checkpointBodyCBOR encodes the canonical, to-be-signed body bytes for c.
func checkpointBodyCBOR(c Checkpoint) ([]byte, error) {
	wire := checkpointWire{
		SessionID:          c.SessionID,
		SegRange:           [2]uint64{c.SegFirst, c.SegLast},
		ChainHead:          c.ChainHead[:],
		PrevCheckpointHash: c.PrevCheckpointHash[:],
		SignedAtWall:       c.SignedAtWall,
		PubkeyID:           c.PubkeyID,
	}
	return canonEncMode.Marshal(wire)
}

// SignCheckpoint canonically encodes c's signed body and signs it with
// priv:
//
//	signature = Ed25519_sign(device_private_key, canonical_cbor(checkpoint))
//
// (docs/TRUST.md §5). It returns the exact bytes that were signed
// (bodyCBOR) alongside the signature — both are persisted (internal/ledger)
// and exported (docs/TRUST.md §7) so a verifier can recompute
// CheckpointHash and re-verify the signature without reconstructing struct
// encoding itself.
func SignCheckpoint(priv ed25519.PrivateKey, c Checkpoint) (bodyCBOR, sig []byte, err error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("chain: invalid ed25519 private key size %d", len(priv))
	}

	bodyCBOR, err = checkpointBodyCBOR(c)
	if err != nil {
		return nil, nil, err
	}

	sig = ed25519.Sign(priv, bodyCBOR)
	return bodyCBOR, sig, nil
}

// VerifyCheckpoint verifies sig over bodyCBOR against pub. bodyCBOR is
// taken as-is (the exact bytes originally signed / stored / exported) — it
// is not re-derived from a Checkpoint struct, matching docs/TRUST.md §8
// step 4's "hash/verify the provided bytes" discipline.
func VerifyCheckpoint(pub ed25519.PublicKey, bodyCBOR, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("chain: invalid ed25519 public key size %d", len(pub))
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: bad signature length %d", ErrInvalidSignature, len(sig))
	}
	if !ed25519.Verify(pub, bodyCBOR, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// CheckpointHash computes BLAKE3(bodyCBOR) — the primitive
// PrevCheckpointHash chaining is built from (docs/TRUST.md §5): the next
// checkpoint's PrevCheckpointHash is this checkpoint's CheckpointHash.
func CheckpointHash(bodyCBOR []byte) [32]byte {
	return blake3.Sum256(bodyCBOR)
}
