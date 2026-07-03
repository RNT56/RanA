package chain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
	"lukechampine.com/blake3"
)

// deviceKeyFilename is the fixed filename for the device signing key
// within a RanA data directory (CONTRACTS §internal/ledger: root/device.key).
const deviceKeyFilename = "device.key"

// keyFileMagic distinguishes the two on-disk key file formats. It is the
// first byte of device.key.
const (
	keyFileMagicPlain   = 0x01 // raw 32-byte ed25519 seed follows
	keyFileMagicWrapped = 0x02 // scrypt+chacha20poly1305-wrapped seed follows
)

// scrypt parameters. N=1<<15 costs roughly tens of milliseconds on
// laptop-class hardware while remaining a meaningful brute-force cost —
// generous enough for a one-time key-unlock operation (not a hot path).
const (
	scryptN      = 1 << 15
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = chacha20poly1305.KeySize
	scryptSaltSz = 16
)

// KeyInfo describes a loaded or freshly generated ed25519 device key.
type KeyInfo struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	PubkeyID   string // hex(BLAKE3(PublicKey)[:8])
}

// PubkeyID derives the short, stable identifier for a public key:
// hex(BLAKE3(pub)[:8]) — 16 lowercase hex characters. Checkpoints carry
// this (docs/TRUST.md §5 pubkey_id) so a verifier can associate a
// checkpoint with the pubkey.pem shipped alongside an export without
// embedding the full 32-byte key in every checkpoint body.
func PubkeyID(pub ed25519.PublicKey) string {
	sum := blake3.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// ErrKeyExists is returned by GenerateKey when a device key file already
// exists in dir — RanA never silently overwrites an existing signing key,
// since doing so would sever the chain of custody for every checkpoint
// already signed with it.
var ErrKeyExists = errors.New("chain: device key already exists")

// GenerateKey creates a fresh ed25519 device key and writes it to
// dir/device.key with mode 0600, unwrapped (docs/TRUST.md §5: "generated at
// first run, stored 0600, optionally passphrase-wrapped"). The private key
// never leaves the machine. Refuses to overwrite an existing key
// (ErrKeyExists). To passphrase-wrap the key (optional — CONTRACTS
// §internal/chain), call Wrap after GenerateKey.
func GenerateKey(dir string) (KeyInfo, error) {
	path := filepath.Join(dir, deviceKeyFilename)
	if _, err := os.Stat(path); err == nil {
		return KeyInfo{}, fmt.Errorf("%w: %s", ErrKeyExists, path)
	} else if !os.IsNotExist(err) {
		return KeyInfo{}, fmt.Errorf("chain: stat %s: %w", path, err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyInfo{}, fmt.Errorf("chain: generating ed25519 key: %w", err)
	}

	fileBytes, err := encodeKeyFile(priv, "")
	if err != nil {
		return KeyInfo{}, err
	}

	if err := writeFile0600Exclusive(path, fileBytes); err != nil {
		return KeyInfo{}, err
	}

	return KeyInfo{PublicKey: pub, PrivateKey: priv, PubkeyID: PubkeyID(pub)}, nil
}

// Wrap re-encodes the device key at dir/device.key under scrypt-derived
// chacha20poly1305 encryption keyed by passphrase (docs/TRUST.md §5's
// optional passphrase wrap). It reads the existing (unwrapped) key, wraps
// it, and atomically replaces the on-disk file — the plaintext seed never
// lingers on disk. passphrase must be non-empty. After Wrap, LoadKey
// requires the same passphrase.
func Wrap(dir, passphrase string) error {
	if passphrase == "" {
		return errors.New("chain: Wrap requires a non-empty passphrase")
	}

	path := filepath.Join(dir, deviceKeyFilename)
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("chain: reading %s: %w", path, err)
	}

	priv, err := decodeKeyFile(raw, "")
	if err != nil {
		return fmt.Errorf("chain: Wrap: key is not currently unwrapped or is unreadable: %w", err)
	}
	defer zero(priv)

	fileBytes, err := encodeKeyFile(priv, passphrase)
	if err != nil {
		return err
	}

	return writeFile0600(path, fileBytes)
}

// LoadKey reads and decodes dir/device.key. passphrase must match what
// GenerateKey was called with (empty string for an unwrapped key); a wrong
// or missing passphrase against a wrapped key fails decryption.
func LoadKey(dir, passphrase string) (KeyInfo, error) {
	path := filepath.Join(dir, deviceKeyFilename)
	raw, err := os.ReadFile(path)
	if err != nil {
		return KeyInfo{}, fmt.Errorf("chain: reading %s: %w", path, err)
	}

	priv, err := decodeKeyFile(raw, passphrase)
	if err != nil {
		return KeyInfo{}, err
	}

	pub := priv.Public().(ed25519.PublicKey)
	return KeyInfo{PublicKey: pub, PrivateKey: priv, PubkeyID: PubkeyID(pub)}, nil
}

// encodeKeyFile builds the on-disk device.key byte layout:
//
//	plain:   0x01 || seed(32)
//	wrapped: 0x02 || salt(16) || nonce(12) || ciphertext(seed(32)+tag(16))
func encodeKeyFile(priv ed25519.PrivateKey, passphrase string) ([]byte, error) {
	seed := priv.Seed()

	if passphrase == "" {
		out := make([]byte, 0, 1+len(seed))
		out = append(out, keyFileMagicPlain)
		out = append(out, seed...)
		return out, nil
	}

	salt := make([]byte, scryptSaltSz)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("chain: generating key-wrap salt: %w", err)
	}

	wrapKey, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, fmt.Errorf("chain: deriving key-wrap key: %w", err)
	}
	defer zero(wrapKey)

	aead, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("chain: constructing AEAD: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("chain: generating nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, seed, nil)

	out := make([]byte, 0, 1+len(salt)+len(nonce)+len(ciphertext))
	out = append(out, keyFileMagicWrapped)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// decodeKeyFile reverses encodeKeyFile.
func decodeKeyFile(raw []byte, passphrase string) (ed25519.PrivateKey, error) {
	if len(raw) < 1 {
		return nil, errors.New("chain: device key file is empty")
	}

	switch raw[0] {
	case keyFileMagicPlain:
		if passphrase != "" {
			return nil, errors.New("chain: passphrase supplied but device key is not passphrase-wrapped")
		}
		seed := raw[1:]
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("chain: malformed device key file: seed length %d, want %d", len(seed), ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(seed), nil

	case keyFileMagicWrapped:
		if passphrase == "" {
			return nil, errors.New("chain: device key is passphrase-wrapped but no passphrase supplied")
		}
		body := raw[1:]
		if len(body) < scryptSaltSz+chacha20poly1305.NonceSize {
			return nil, errors.New("chain: malformed wrapped device key file (too short)")
		}
		salt := body[:scryptSaltSz]
		nonce := body[scryptSaltSz : scryptSaltSz+chacha20poly1305.NonceSize]
		ciphertext := body[scryptSaltSz+chacha20poly1305.NonceSize:]

		wrapKey, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
		if err != nil {
			return nil, fmt.Errorf("chain: deriving key-wrap key: %w", err)
		}
		defer zero(wrapKey)

		aead, err := chacha20poly1305.New(wrapKey)
		if err != nil {
			return nil, fmt.Errorf("chain: constructing AEAD: %w", err)
		}

		seed, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, errors.New("chain: failed to unwrap device key (wrong passphrase?)")
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("chain: malformed device key file: unwrapped seed length %d, want %d", len(seed), ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(seed), nil

	default:
		return nil, fmt.Errorf("chain: unrecognized device key file format (magic byte 0x%02x)", raw[0])
	}
}

// zero best-effort clears sensitive key material from memory once no
// longer needed. This is defense in depth, not a guarantee against a
// determined attacker with process memory access (P4).
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// writeFile0600 writes data to path atomically-enough for a single-writer
// key file: create with 0600 from the start (never briefly world/group
// readable), then rename into place.
func writeFile0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".device.key.tmp-*")
	if err != nil {
		return fmt.Errorf("chain: creating temp key file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once renamed

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chain: chmod temp key file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("chain: writing temp key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("chain: closing temp key file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("chain: renaming key file into place: %w", err)
	}
	return nil
}

// writeFile0600Exclusive is like writeFile0600 but the final placement is
// exclusive: it fails (and leaves any pre-existing file at path untouched)
// if path already exists, instead of silently replacing it.
//
// GenerateKey's own os.Stat "does it already exist" check has an inherent
// TOCTOU race window: two GenerateKey calls (e.g. `rana` and `ranad` both
// racing to bootstrap the device key on a machine's very first run) can
// both observe "no key yet" before either has written, and plain
// os.Rename(tmp, path) unconditionally replaces whatever is at path on
// POSIX — the second writer would silently clobber the first key,
// severing custody of anything already signed with it, with no error and
// no trace. os.Link (hard link) fails with EEXIST if path already exists,
// so only the first writer to reach this point wins; the loser's temp file
// is removed and ErrKeyExists is returned exactly as if its earlier Stat
// had lost the race — the documented "never silently overwrite an existing
// signing key" guarantee holds even under concurrent GenerateKey calls, not
// just sequential ones.
func writeFile0600Exclusive(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".device.key.tmp-*")
	if err != nil {
		return fmt.Errorf("chain: creating temp key file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the link succeeds and tmp is removed below

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chain: chmod temp key file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("chain: writing temp key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("chain: closing temp key file: %w", err)
	}

	if err := os.Link(tmpPath, path); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%w: %s", ErrKeyExists, path)
		}
		return fmt.Errorf("chain: linking key file into place: %w", err)
	}
	return nil
}

// pemPubkeyType is the PEM block type used for the exported device public
// key (docs/TRUST.md §7: pubkey.pem, "the device public key (NOT the
// private key)").
const pemPubkeyType = "RANA ED25519 PUBLIC KEY"

// ExportPubkeyPEM encodes pub as a PEM block suitable for
// docs/TRUST.md §7's pubkey.pem export artifact. It never touches private
// key material.
func ExportPubkeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("chain: invalid ed25519 public key size %d", len(pub))
	}
	block := &pem.Block{
		Type:  pemPubkeyType,
		Bytes: append([]byte(nil), pub...),
	}
	return pem.EncodeToMemory(block), nil
}

// ParsePubkeyPEM reverses ExportPubkeyPEM.
func ParsePubkeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("chain: no PEM block found")
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("chain: PEM block has wrong length %d for an ed25519 public key", len(block.Bytes))
	}
	return ed25519.PublicKey(block.Bytes), nil
}
