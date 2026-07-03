package chain

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"lukechampine.com/blake3"
)

func genTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

func sampleCheckpoint() Checkpoint {
	var head [32]byte
	for i := range head {
		head[i] = byte(i + 1)
	}
	return Checkpoint{
		SessionID:          "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		SegFirst:           0,
		SegLast:            63,
		ChainHead:          head,
		PrevCheckpointHash: [32]byte{}, // genesis
		SignedAtWall:       1700000000000000000,
		PubkeyID:           "deadbeefcafebabe",
	}
}

// TestSignCheckpoint_VerifyRoundTrip: a checkpoint signed with a key
// verifies successfully against that key's public half.
func TestSignCheckpoint_VerifyRoundTrip(t *testing.T) {
	pub, priv := genTestKey(t)
	c := sampleCheckpoint()

	bodyCBOR, sig, err := SignCheckpoint(priv, c)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}

	if err := VerifyCheckpoint(pub, bodyCBOR, sig); err != nil {
		t.Fatalf("VerifyCheckpoint on valid signature: %v", err)
	}
}

// TestVerifyCheckpoint_WrongKeyFails confirms verification fails against a
// different key's public half — re-signing without the original key is
// exactly what docs/TRUST.md §6 step 4 must catch.
func TestVerifyCheckpoint_WrongKeyFails(t *testing.T) {
	_, priv := genTestKey(t)
	otherPub, _ := genTestKey(t)
	c := sampleCheckpoint()

	bodyCBOR, sig, err := SignCheckpoint(priv, c)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}

	if err := VerifyCheckpoint(otherPub, bodyCBOR, sig); err == nil {
		t.Fatalf("VerifyCheckpoint succeeded against the wrong public key")
	}
}

// TestVerifyCheckpoint_TamperedBodyFails: flipping a single bit in the
// signed body must invalidate the signature.
func TestVerifyCheckpoint_TamperedBodyFails(t *testing.T) {
	pub, priv := genTestKey(t)
	c := sampleCheckpoint()

	bodyCBOR, sig, err := SignCheckpoint(priv, c)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}

	tampered := make([]byte, len(bodyCBOR))
	copy(tampered, bodyCBOR)
	tampered[0] ^= 1

	if err := VerifyCheckpoint(pub, tampered, sig); err == nil {
		t.Fatalf("VerifyCheckpoint succeeded on tampered body")
	}
}

// TestVerifyCheckpoint_TamperedSigFails: flipping a single bit in the
// signature must fail verification.
func TestVerifyCheckpoint_TamperedSigFails(t *testing.T) {
	pub, priv := genTestKey(t)
	c := sampleCheckpoint()

	bodyCBOR, sig, err := SignCheckpoint(priv, c)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}

	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 1

	if err := VerifyCheckpoint(pub, bodyCBOR, tampered); err == nil {
		t.Fatalf("VerifyCheckpoint succeeded on tampered signature")
	}
}

// TestCheckpointHash_MatchesBlake3OfBody confirms CheckpointHash is exactly
// BLAKE3(bodyCBOR) — the primitive prev_checkpoint_hash chaining is built
// from (docs/TRUST.md §5).
func TestCheckpointHash_MatchesBlake3OfBody(t *testing.T) {
	_, priv := genTestKey(t)
	c := sampleCheckpoint()

	bodyCBOR, _, err := SignCheckpoint(priv, c)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}

	want := blake3.Sum256(bodyCBOR)
	got := CheckpointHash(bodyCBOR)
	if got != want {
		t.Fatalf("CheckpointHash = %x, want %x", got, want)
	}
}

// TestSignCheckpoint_BodyExcludesSignature: bodyCBOR must not itself embed
// the signature (the signature is computed OVER bodyCBOR — it cannot also
// be a field inside it, or signing would be circular/ambiguous).
func TestSignCheckpoint_BodyExcludesSignature(t *testing.T) {
	_, priv := genTestKey(t)
	c := sampleCheckpoint()

	bodyCBOR, sig, err := SignCheckpoint(priv, c)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}

	if bytes.Contains(bodyCBOR, sig) {
		t.Fatalf("bodyCBOR appears to embed the signature bytes")
	}
}

// TestSignCheckpoint_FieldNames confirms the checkpoint body encodes with
// the documented field names (docs/TRUST.md §5): session_id, seg_range
// (first/last), chain_head, prev_checkpoint_hash, signed_at_wall,
// pubkey_id.
func TestSignCheckpoint_FieldNames(t *testing.T) {
	_, priv := genTestKey(t)
	c := sampleCheckpoint()

	bodyCBOR, _, err := SignCheckpoint(priv, c)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}

	var decoded map[string]any
	if err := canonDecMode.Unmarshal(bodyCBOR, &decoded); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	for _, k := range []string{"session_id", "chain_head", "prev_checkpoint_hash", "signed_at_wall", "pubkey_id"} {
		if _, ok := decoded[k]; !ok {
			t.Errorf("missing field %q in checkpoint body; got %v", k, keysOf(decoded))
		}
	}
}

// TestSignCheckpoint_Deterministic: signing the same checkpoint twice with
// the same key produces the same body bytes (ed25519 signatures over a
// message are deterministic per RFC 8032, so signatures match too).
func TestSignCheckpoint_Deterministic(t *testing.T) {
	_, priv := genTestKey(t)
	c := sampleCheckpoint()

	body1, sig1, err := SignCheckpoint(priv, c)
	if err != nil {
		t.Fatalf("sign 1: %v", err)
	}
	body2, sig2, err := SignCheckpoint(priv, c)
	if err != nil {
		t.Fatalf("sign 2: %v", err)
	}

	if !bytes.Equal(body1, body2) {
		t.Fatalf("bodyCBOR not deterministic")
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatalf("signature not deterministic")
	}
}

// TestSignCheckpoint_FieldChangeChangesBody: changing any field of the
// Checkpoint changes the signed body bytes.
func TestSignCheckpoint_FieldChangeChangesBody(t *testing.T) {
	_, priv := genTestKey(t)
	base := sampleCheckpoint()
	baseBody, _, err := SignCheckpoint(priv, base)
	if err != nil {
		t.Fatalf("SignCheckpoint base: %v", err)
	}

	mutations := []func(*Checkpoint){
		func(c *Checkpoint) { c.SessionID = "different" },
		func(c *Checkpoint) { c.SegFirst++ },
		func(c *Checkpoint) { c.SegLast++ },
		func(c *Checkpoint) { c.ChainHead[0] ^= 1 },
		func(c *Checkpoint) { c.PrevCheckpointHash[0] ^= 1 },
		func(c *Checkpoint) { c.SignedAtWall++ },
		func(c *Checkpoint) { c.PubkeyID = "different-id" },
	}

	for i, mutate := range mutations {
		mutated := base
		mutate(&mutated)
		mutatedBody, _, err := SignCheckpoint(priv, mutated)
		if err != nil {
			t.Fatalf("mutation %d: SignCheckpoint: %v", i, err)
		}
		if bytes.Equal(mutatedBody, baseBody) {
			t.Errorf("mutation %d did not change checkpoint body", i)
		}
	}
}

// TestVerifyCheckpoint_MalformedBody confirms malformed CBOR body bytes
// error out (rather than panicking) during verification.
func TestVerifyCheckpoint_MalformedBody(t *testing.T) {
	pub, _ := genTestKey(t)
	garbage := []byte{0xff, 0xff, 0xff}
	sig := make([]byte, ed25519.SignatureSize)

	if err := VerifyCheckpoint(pub, garbage, sig); err == nil {
		t.Fatalf("expected error verifying malformed body/sig combination")
	}
}
