// Command rana-verify-standalone is the independent, portable reference
// implementation of docs/TRUST.md §8: given nothing but an export directory
// (docs/TRUST.md §7 — events.cbor/segments.cbor/checkpoints.cbor/
// pubkey.pem/manifest.json), it re-derives every hash, Merkle root,
// segment-chain link, and Ed25519 signature from first principles and
// reports whether the exported history is intact.
//
// It deliberately imports NO sqlite, NO internal/ledger, and NO
// internal/schema — only internal/cborcanon, internal/chain, and the Go
// standard library — so that verifying an export never requires trusting
// (or even building) the rest of RanA. This is a second, independent
// implementation of the trust guarantee described in docs/TRUST.md; any
// disagreement with internal/ledger.Verify on the same data is a spec bug
// (CONTRACTS §cmd/rana-verify-standalone), not something to paper over
// here.
//
// Usage:
//
//	rana-verify-standalone <export-dir>
//
// Exit codes (docs/TRUST.md §6, exactly):
//
//	0  OK          chain intact (honest gaps and an unattested tail are
//	               still exit 0 — see docs/TRUST.md §6).
//	2  BROKEN      a leaf/root/link/signature mismatch: tamper detected.
//	3  INCOMPLETE  chain intact but verification could not be completed
//	               (e.g. a missing artifact) — never a false BROKEN.
package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/chain"
)

// Exit codes, exactly per docs/TRUST.md §6 / internal/ledger.CodeOK et al.
// Redeclared here (not imported) because this binary imports no
// internal/ledger — see the package doc comment.
const (
	CodeOK         = 0
	CodeBroken     = 2
	CodeIncomplete = 3
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: rana-verify-standalone <export-dir>")
		os.Exit(CodeIncomplete)
	}
	os.Exit(Run(os.Args[1], os.Stdout))
}

// Run verifies the export directory at dir, writes a human-readable report
// to out, and returns the process exit code (docs/TRUST.md §6).
func Run(dir string, out io.Writer) int {
	res, err := Verify(dir)
	if err != nil {
		fmt.Fprintf(out, "INCOMPLETE: %v\n", err)
		return CodeIncomplete
	}

	switch res.Code {
	case CodeOK:
		fmt.Fprintln(out, "OK")
	case CodeBroken:
		fmt.Fprintf(out, "BROKEN(%s): %s\n", res.ReasonClass, res.Reason)
	case CodeIncomplete:
		fmt.Fprintf(out, "INCOMPLETE: %s\n", res.Reason)
	}
	for _, u := range res.UnattestedTail {
		fmt.Fprintf(out, "UNATTESTED-TAIL: session=%s seg=%d (sealed, hash-linked, not yet checkpoint-signed)\n", u.Session, u.Seg)
	}
	for _, n := range res.ExternalPrevNotes {
		fmt.Fprintf(out, "EXTERNAL-PREV: checkpoint %d's prev_checkpoint_hash refers to a checkpoint outside this export (expected for a single-session export whose ledger has earlier sessions) — verify it against the source ledger\n", n)
	}
	return res.Code
}

// Result is the outcome of Verify: an exit Code, the first BROKEN/
// INCOMPLETE reason encountered (if any), and the informational notes
// docs/TRUST.md §8 step 5/6 calls out as neither pass nor fail.
type Result struct {
	Code              int
	ReasonClass       string // set only when Code == CodeBroken: "encoding" | "merkle" | "chain" | "signature" | "head_mismatch" | "ckpt_chain" | "manifest"
	Reason            string
	UnattestedTail    []UnattestedSegment
	ExternalPrevNotes []int // indices into the checkpoint sequence
}

// UnattestedSegment is a sealed segment with hash linkage verified but no
// covering checkpoint signature yet (docs/TRUST.md §5/§6): a normal,
// expected state for recent data, reported distinctly from both "verified"
// and "broken".
type UnattestedSegment struct {
	Session string
	Seg     uint64
}

// eventEnvelope mirrors internal/cborcanon's event envelope field-for-field
// so this verifier can read back the `session` field needed to group leaves
// per session (see accumulateLeaves — segment membership within a session
// is NOT reconstructed from the event's own `seg` field; see that
// function's doc comment for why). It deliberately does NOT import
// internal/schema — decoding into a small local struct with matching
// `cbor` tags is sufficient and keeps this binary's dependency surface
// exactly cborcanon+chain+stdlib, per CONTRACTS §cmd/rana-verify-standalone.
type eventEnvelope struct {
	V       uint8          `cbor:"v"`
	Type    string         `cbor:"type"`
	Session string         `cbor:"session"`
	Seg     uint64         `cbor:"seg"`
	Idx     uint64         `cbor:"idx"`
	TsMono  uint64         `cbor:"ts_mono"`
	TsWall  uint64         `cbor:"ts_wall"`
	Pid     uint32         `cbor:"pid"`
	Origin  string         `cbor:"origin"`
	State   string         `cbor:"state"`
	Data    map[string]any `cbor:"data"`
}

// segHeaderRecord mirrors internal/chain's segHeaderWire field-for-field
// (docs/TRUST.md §4): session_id, seg_index, first_rowid, last_rowid,
// event_count, merkle_root, prev_seg_hash, gap_summary, sealed_at_wall.
// Redeclared locally (rather than imported — chain's wire struct is
// unexported) so this verifier decodes the exact same canonical field set
// independently.
type segHeaderRecord struct {
	SessionID    string            `cbor:"session_id"`
	SegIndex     uint64            `cbor:"seg_index"`
	FirstRowID   int64             `cbor:"first_rowid"`
	LastRowID    int64             `cbor:"last_rowid"`
	EventCount   uint64            `cbor:"event_count"`
	MerkleRoot   []byte            `cbor:"merkle_root"`
	PrevSegHash  []byte            `cbor:"prev_seg_hash"`
	GapSummary   map[string]uint64 `cbor:"gap_summary"`
	SealedAtWall uint64            `cbor:"sealed_at_wall"`
}

// checkpointBodyRecord mirrors internal/chain's checkpointWire
// field-for-field (docs/TRUST.md §5): session_id, seg_range, chain_head,
// prev_checkpoint_hash, signed_at_wall, pubkey_id.
type checkpointBodyRecord struct {
	SessionID          string    `cbor:"session_id"`
	SegRange           [2]uint64 `cbor:"seg_range"`
	ChainHead          []byte    `cbor:"chain_head"`
	PrevCheckpointHash []byte    `cbor:"prev_checkpoint_hash"`
	SignedAtWall       uint64    `cbor:"signed_at_wall"`
	PubkeyID           string    `cbor:"pubkey_id"`
}

// manifest is the subset of manifest.json (docs/TRUST.md §7) this verifier
// checks (docs/TRUST.md §8 step 1).
type manifest struct {
	FormatVersion int    `json:"format_version"`
	Hash          string `json:"hash"`
	Sig           string `json:"sig"`
	Encoding      string `json:"encoding"`
	Session       string `json:"session"`
}

// brokenErr is a sentinel error type carrying the reason-class taxonomy
// docs/TRUST.md §8 lists per step (encoding / merkle / chain / signature /
// head_mismatch / ckpt_chain / manifest), so Verify can report BROKEN with
// a precise, machine-matchable class alongside a human reason.
type brokenErr struct {
	class  string
	detail string
}

func (e *brokenErr) Error() string { return e.detail }

func broken(class, format string, args ...any) error {
	return &brokenErr{class: class, detail: fmt.Sprintf(format, args...)}
}

// Verify implements docs/TRUST.md §8's algorithm exactly against the export
// directory at dir. A returned Go error means verification could not even
// be attempted (missing directory, unreadable file, malformed JSON at the
// manifest-parsing stage) — callers map that to INCOMPLETE. Once files are
// readable, all further outcomes are reported via Result (BROKEN vs
// INCOMPLETE vs OK) rather than an error, matching the exit-code triad.
func Verify(dir string) (Result, error) {
	if _, err := os.Stat(dir); err != nil {
		return Result{}, fmt.Errorf("export directory: %w", err)
	}

	// Step 1: manifest.
	m, err := readManifest(filepath.Join(dir, "manifest.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return Result{Code: CodeIncomplete, Reason: "manifest.json is missing"}, nil
		}
		return Result{Code: CodeIncomplete, Reason: fmt.Sprintf("manifest.json: %v", err)}, nil
	}
	if bad := checkManifestAlgorithms(m); bad != nil {
		return Result{Code: CodeBroken, ReasonClass: bad.(*brokenErr).class, Reason: bad.Error()}, nil
	}

	// Step 2: events.cbor -> per-session ordered leaf sequences, in file
	// order (docs/TRUST.md §8 step 2).
	eventsPath := filepath.Join(dir, "events.cbor")
	eventsRaw, err := os.ReadFile(eventsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Result{Code: CodeIncomplete, Reason: "events.cbor is missing"}, nil
		}
		return Result{Code: CodeIncomplete, Reason: fmt.Sprintf("events.cbor: %v", err)}, nil
	}
	leavesBySession, evErr := accumulateLeaves(eventsRaw)
	if evErr != nil {
		be := evErr.(*brokenErr)
		return Result{Code: CodeBroken, ReasonClass: be.class, Reason: be.Error()}, nil
	}

	// Step 3: segments.cbor -> recompute merkle_root and the seg_hash chain.
	segsPath := filepath.Join(dir, "segments.cbor")
	segsRaw, err := os.ReadFile(segsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Result{Code: CodeIncomplete, Reason: "segments.cbor is missing"}, nil
		}
		return Result{Code: CodeIncomplete, Reason: fmt.Sprintf("segments.cbor: %v", err)}, nil
	}
	segs, segHashesBySeg, segErr := verifySegments(segsRaw, leavesBySession)
	if segErr != nil {
		be := segErr.(*brokenErr)
		return Result{Code: CodeBroken, ReasonClass: be.class, Reason: be.Error()}, nil
	}

	// Step 4: checkpoints.cbor -> Ed25519 signatures + chain_head match +
	// prev_checkpoint_hash continuity within the export.
	ckptsPath := filepath.Join(dir, "checkpoints.cbor")
	ckptsRaw, err := os.ReadFile(ckptsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Result{Code: CodeIncomplete, Reason: "checkpoints.cbor is missing"}, nil
		}
		return Result{Code: CodeIncomplete, Reason: fmt.Sprintf("checkpoints.cbor: %v", err)}, nil
	}

	var pub ed25519.PublicKey
	pubPath := filepath.Join(dir, "pubkey.pem")
	pubBytes, err := os.ReadFile(pubPath)
	pubMissing := err != nil
	if err == nil {
		pub, err = chain.ParsePubkeyPEM(pubBytes)
		if err != nil {
			return Result{Code: CodeIncomplete, Reason: fmt.Sprintf("pubkey.pem: %v", err)}, nil
		}
	} else if !os.IsNotExist(err) {
		return Result{Code: CodeIncomplete, Reason: fmt.Sprintf("pubkey.pem: %v", err)}, nil
	}

	ckpts, extPrev, ckErr := parseCheckpoints(ckptsRaw)
	if ckErr != nil {
		be := ckErr.(*brokenErr)
		return Result{Code: CodeBroken, ReasonClass: be.class, Reason: be.Error()}, nil
	}

	if len(ckpts) > 0 && pubMissing {
		return Result{Code: CodeIncomplete, Reason: "checkpoints.cbor has checkpoints but pubkey.pem is missing; signatures were NOT checked"}, nil
	}

	lastCheckpointedSeg := map[string]int64{} // session_id -> highest seg_last covered by any checkpoint
	for i, ck := range ckpts {
		if err := chain.VerifyCheckpoint(pub, ck.body, ck.sig); err != nil {
			return Result{Code: CodeBroken, ReasonClass: "signature", Reason: fmt.Sprintf("checkpoint %d: %v", i, err)}, nil
		}

		lastSegHash, ok := segHashesBySeg[segKey(ck.wire.SessionID, ck.wire.SegRange[1])]
		if !ok {
			return Result{Code: CodeIncomplete, Reason: fmt.Sprintf("checkpoint %d references seg %d (session %s), which is absent from segments.cbor", i, ck.wire.SegRange[1], ck.wire.SessionID)}, nil
		}
		var wantHead [32]byte
		copy(wantHead[:], ck.wire.ChainHead)
		if lastSegHash != wantHead {
			return Result{Code: CodeBroken, ReasonClass: "head_mismatch", Reason: fmt.Sprintf("checkpoint %d chain_head does not match recomputed seg_hash of seg %d", i, ck.wire.SegRange[1])}, nil
		}

		if s := ck.wire.SegRange[1]; int64(s) > lastCheckpointedSeg[ck.wire.SessionID] {
			lastCheckpointedSeg[ck.wire.SessionID] = int64(s)
		}
	}

	// prev_checkpoint_hash continuity WITHIN the export (docs/TRUST.md §8
	// step 4): the first checkpoint's prev may legitimately point outside
	// the export (single-session export of a ledger with earlier sessions)
	// — that is an EXTERNAL-PREV note, not a break. Every SUBSEQUENT
	// checkpoint in the export must chain from the one before it.
	for i := 1; i < len(ckpts); i++ {
		want := chain.CheckpointHash(ckpts[i-1].body)
		var got [32]byte
		copy(got[:], ckpts[i].wire.PrevCheckpointHash)
		if got != want {
			return Result{Code: CodeBroken, ReasonClass: "ckpt_chain", Reason: fmt.Sprintf("checkpoint %d's prev_checkpoint_hash does not chain from checkpoint %d within this export", i, i-1)}, nil
		}
	}

	// Step 5: unattested tail — segments not covered by any checkpoint in
	// this export.
	var unattested []UnattestedSegment
	for _, sh := range segs {
		if int64(sh.SegIndex) > lastCheckpointedSeg[sh.SessionID] {
			unattested = append(unattested, UnattestedSegment{Session: sh.SessionID, Seg: sh.SegIndex})
		}
	}

	return Result{Code: CodeOK, UnattestedTail: unattested, ExternalPrevNotes: extPrev}, nil
}

func readManifest(path string) (manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return manifest{}, err
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return manifest{}, err
	}
	return m, nil
}

// checkManifestAlgorithms implements docs/TRUST.md §8 step 1: confirm
// format_version and algorithm identifiers are recognized before any
// hashing is attempted.
func checkManifestAlgorithms(m manifest) error {
	if m.FormatVersion != 1 {
		return broken("manifest", "unrecognized format_version %d (want 1)", m.FormatVersion)
	}
	if m.Hash != "blake3" {
		return broken("manifest", "unrecognized hash algorithm %q (want blake3)", m.Hash)
	}
	if m.Sig != "ed25519" {
		return broken("manifest", "unrecognized signature algorithm %q (want ed25519)", m.Sig)
	}
	if m.Encoding != "cbor-rfc8949-cde" {
		return broken("manifest", "unrecognized encoding %q (want cbor-rfc8949-cde)", m.Encoding)
	}
	return nil
}

// readUvarintPrefixedRecords splits buf into its uvarint-length-prefixed
// records (docs/TRUST.md §7), returning each record's raw bytes in file
// order. class names the artifact for error messages.
func readUvarintPrefixedRecords(buf []byte, class string) ([][]byte, error) {
	var recs [][]byte
	off := 0
	for off < len(buf) {
		n, sz := binary.Uvarint(buf[off:])
		if sz <= 0 {
			return nil, broken("encoding", "%s: malformed uvarint length prefix at offset %d", class, off)
		}
		off += sz
		if off+int(n) > len(buf) {
			return nil, broken("encoding", "%s: record length %d overruns buffer at offset %d", class, n, off)
		}
		recs = append(recs, buf[off:off+int(n)])
		off += int(n)
	}
	return recs, nil
}

// accumulateLeaves implements docs/TRUST.md §8 step 2: for each
// length-prefixed record in events.cbor, confirm it is well-formed
// canonical CBOR, compute its leaf hash by hashing the PROVIDED bytes
// directly (never re-encoding — docs/TRUST.md §8 step 2's explicit "hash
// the provided bytes; do NOT re-encode", and TRUST.md §7's int64-ns
// rationale for why the CBOR bytes themselves, not a re-derived encoding,
// are authoritative), and accumulates leaves in file order, grouped ONLY by
// session.
//
// Grouping is deliberately NOT keyed by the event envelope's own `seg`
// field: internal/ledger's Writer assigns segment membership at seal time
// by contiguous SQLite rowid range (docs/TRUST.md §4's first_rowid/
// last_rowid), and does not rewrite each event's already-persisted `seg`
// envelope field to match — an event's `seg` is caller/collector-supplied
// metadata, not the authoritative segment assignment (mirroring
// internal/ledger.Verify's own readSegmentEvents, which selects by rowid
// range, never by the `type`/other mirror columns). The authoritative
// grouping a standalone verifier can reconstruct from the export alone is
// therefore: segments.cbor's records, in file order, each claiming exactly
// EventCount leaves consumed in order from that session's events.cbor
// stream (docs/TRUST.md §7: events.cbor is written "in order"; segments.cbor
// likewise "every seg_header ... in order"). A short read (fewer leaves
// left than EventCount claims) is itself reported as broken/incomplete by
// verifySegments's merkle-root mismatch or explicit count check.
func accumulateLeaves(buf []byte) (map[string][][32]byte, error) {
	recs, err := readUvarintPrefixedRecords(buf, "events.cbor")
	if err != nil {
		return nil, err
	}

	leaves := map[string][][32]byte{}
	for i, rec := range recs {
		ok, err := cborcanon.IsCanonical(rec)
		if err != nil || !ok {
			return nil, broken("encoding", "events.cbor record %d is not well-formed canonical CBOR", i)
		}
		var env eventEnvelope
		if err := cborcanon.Decode(rec, &env); err != nil {
			return nil, broken("encoding", "events.cbor record %d: decoding envelope: %v", i, err)
		}
		leaf := chain.Leaf(rec)
		leaves[env.Session] = append(leaves[env.Session], leaf)
	}
	return leaves, nil
}

// verifySegments implements docs/TRUST.md §8 step 3: for each seg_header
// record (visited in file order), consume the next EventCount leaves from
// that session's ordered leaf sequence (see accumulateLeaves), recompute
// merkle_root over exactly those leaves and confirm it matches, then
// recompute seg_hash = BLAKE3(record bytes) (the exact given bytes, per the
// same "hash provided bytes" discipline as leaf hashing) and confirm
// prev_seg_hash chains from the previous segment's recomputed hash within
// its session (genesis: 32 zero bytes).
//
// chain.CheckpointHash is reused here purely as the generic BLAKE3(bytes)
// primitive it already is (see internal/chain/checkpoint.go: "CheckpointHash
// computes BLAKE3(bodyCBOR)") — segment headers and checkpoint bodies both
// need exactly that primitive applied to already-canonical bytes, so this
// avoids a redundant local BLAKE3 dependency while keeping this file's
// import set to cborcanon+chain+stdlib.
func verifySegments(buf []byte, leavesBySession map[string][][32]byte) ([]segHeaderRecord, map[string][32]byte, error) {
	recs, err := readUvarintPrefixedRecords(buf, "segments.cbor")
	if err != nil {
		return nil, nil, err
	}

	segHashes := map[string][32]byte{}
	prevHashBySession := map[string][32]byte{} // zero value == genesis
	cursorBySession := map[string]int{}        // next unconsumed leaf index, per session
	var headers []segHeaderRecord

	for i, rec := range recs {
		var sh segHeaderRecord
		if err := cborcanon.Decode(rec, &sh); err != nil {
			return nil, nil, broken("encoding", "segments.cbor record %d: decoding seg_header: %v", i, err)
		}
		headers = append(headers, sh)

		all := leavesBySession[sh.SessionID]
		start := cursorBySession[sh.SessionID]
		end := start + int(sh.EventCount)
		if end > len(all) {
			return nil, nil, broken("merkle", "segments.cbor record %d (session %s seg %d): claims %d events but only %d remain in events.cbor for this session", i, sh.SessionID, sh.SegIndex, sh.EventCount, len(all)-start)
		}
		leaves := all[start:end]
		cursorBySession[sh.SessionID] = end

		root := chain.MerkleRoot(leaves)
		var wantRoot [32]byte
		copy(wantRoot[:], sh.MerkleRoot)
		if root != wantRoot {
			return nil, nil, broken("merkle", "segments.cbor record %d (session %s seg %d): recomputed merkle_root does not match stored merkle_root", i, sh.SessionID, sh.SegIndex)
		}

		segHash := chain.CheckpointHash(rec) // BLAKE3(record bytes) — see doc comment above.

		var wantPrev [32]byte
		copy(wantPrev[:], sh.PrevSegHash)
		gotPrev := prevHashBySession[sh.SessionID]
		if wantPrev != gotPrev {
			return nil, nil, broken("chain", "segments.cbor record %d (session %s seg %d): prev_seg_hash does not chain from the previous segment", i, sh.SessionID, sh.SegIndex)
		}

		prevHashBySession[sh.SessionID] = segHash
		segHashes[segKey(sh.SessionID, sh.SegIndex)] = segHash
	}

	return headers, segHashes, nil
}

// parsedCheckpoint pairs a decoded checkpoint body with its raw body/sig
// bytes (needed as-is for Ed25519 verification and for CheckpointHash
// chaining, matching docs/TRUST.md §8 step 4's "hash/verify the provided
// bytes" discipline).
type parsedCheckpoint struct {
	body []byte
	sig  []byte
	wire checkpointBodyRecord
}

// parseCheckpoints implements the parsing half of docs/TRUST.md §8 step 4:
// each outer record in checkpoints.cbor is itself
// [uvarint-len body][uvarint-len sig] (docs/ledger.Export's
// encodeCheckpointExportRecord), decoded here independently.
func parseCheckpoints(buf []byte) ([]parsedCheckpoint, []int, error) {
	outer, err := readUvarintPrefixedRecords(buf, "checkpoints.cbor")
	if err != nil {
		return nil, nil, err
	}

	var out []parsedCheckpoint
	for i, rec := range outer {
		body, sig, err := splitCheckpointRecord(rec)
		if err != nil {
			return nil, nil, broken("encoding", "checkpoints.cbor record %d: %v", i, err)
		}
		var wire checkpointBodyRecord
		if err := cborcanon.Decode(body, &wire); err != nil {
			return nil, nil, broken("encoding", "checkpoints.cbor record %d: decoding checkpoint body: %v", i, err)
		}
		out = append(out, parsedCheckpoint{body: body, sig: sig, wire: wire})
	}

	// External-prev note: the first checkpoint's prev_checkpoint_hash may
	// legitimately refer to a checkpoint outside this (possibly
	// single-session) export (docs/TRUST.md §8 step 4). We can only note
	// this — verifying it requires the source ledger, which is explicitly
	// out of scope for a standalone export verifier.
	var extPrev []int
	if len(out) > 0 {
		extPrev = append(extPrev, 0)
	}

	return out, extPrev, nil
}

// splitCheckpointRecord reverses ledger.encodeCheckpointExportRecord:
// [uvarint bodyLen][body][uvarint sigLen][sig].
func splitCheckpointRecord(rec []byte) (body, sig []byte, err error) {
	bodyLen, sz := binary.Uvarint(rec)
	if sz <= 0 {
		return nil, nil, errors.New("malformed body length uvarint")
	}
	off := sz
	if off+int(bodyLen) > len(rec) {
		return nil, nil, errors.New("body length overruns record")
	}
	body = rec[off : off+int(bodyLen)]
	off += int(bodyLen)

	sigLen, sz2 := binary.Uvarint(rec[off:])
	if sz2 <= 0 {
		return nil, nil, errors.New("malformed sig length uvarint")
	}
	off += sz2
	if off+int(sigLen) > len(rec) {
		return nil, nil, errors.New("sig length overruns record")
	}
	sig = rec[off : off+int(sigLen)]
	return body, sig, nil
}

// segKey builds the map key grouping leaves/hashes by (session, seg) —
// segments are chained within a session (docs/TRUST.md §4), so identical
// seg indices in different sessions must never collide.
func segKey(session string, seg uint64) string {
	return fmt.Sprintf("%s#%d", session, seg)
}
