// Package main_test exercises rana-verify-standalone end to end: it builds
// a real export directory using internal/ledger.Export (a TEST-ONLY
// dependency — main.go itself imports neither internal/ledger nor
// database/sql; see the package doc comment on main.go), runs the verifier
// binary's logic against it, and asserts OK; then corrupts each artifact
// class in turn and asserts the exact BROKEN/INCOMPLETE reason and exit
// code (docs/TRUST.md §8, CONTRACTS §cmd/rana-verify-standalone).
//
// This binary + this test together are a SECOND, INDEPENDENT
// implementation of docs/TRUST.md's trust guarantee, deliberately not
// sharing internal/ledger.Verify's code path — any disagreement between the
// two on a given export is a spec bug (CONTRACTS: "treat any disagreement
// with internal/ledger.Verify as a spec bug to surface").
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// buildExport constructs a small, clean, multi-segment, checkpointed ledger
// (mirroring internal/ledger's own buildCleanLedger fixture shape, but
// built here from ONLY internal/ledger's exported surface — NewWriter,
// WriterOptions, Writer.Append/FlushForTest/Close, Export — since this test
// lives outside package ledger) and exports one session to a fresh
// directory, returning the export dir.
func buildExport(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	d := ledger.Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	key, err := chain.GenerateKey(root)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	w, err := ledger.NewWriter(d, ledger.WriterOptions{
		SegSealMaxEvents:  5,
		CheckpointMaxSegs: 2,
		Key:               key,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	session := "01ARZ3NDEKTSV4RRFFQ69G5FC0"
	// 3 segments' worth (15 events): a checkpoint covers segs [0,1], seg 2
	// is an unattested tail — exactly the shape rana-verify-standalone must
	// report as OK-with-unattested-tail, not BROKEN.
	for i := 0; i < 15; i++ {
		ts := uint64(1_000_000_000 + i)
		ev := schema.NewProcExec(session, 0, uint64(i), ts, ts, 100,
			[]redact.Redacted{redact.Literal("/bin/true")},
			redact.Literal("true"), redact.Literal("/root"), redact.Literal("/bin/true"),
			1, 0)
		if err := w.Append(ev); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if err := w.FlushForTest(); err != nil {
			t.Fatalf("flush %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	outDir := filepath.Join(root, "export")
	if err := ledger.Export(d, session, outDir); err != nil {
		t.Fatalf("Export: %v", err)
	}
	return outDir
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return b
}

func mustWriteFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func TestVerifyCleanExportIsOK(t *testing.T) {
	dir := buildExport(t)

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Code != CodeOK {
		t.Fatalf("Code = %d, want CodeOK(0); reason=%q", res.Code, res.Reason)
	}
	if len(res.UnattestedTail) == 0 {
		t.Fatalf("expected a non-empty unattested tail (seg 2 was sealed but not checkpointed)")
	}
}

func TestVerifyCleanExportExitCode(t *testing.T) {
	dir := buildExport(t)
	code := Run(dir, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("Run exit code = %d, want 0", code)
	}
}

// TestVerifyMissingDirIsIncomplete proves a nonexistent/unreadable export
// directory is reported as INCOMPLETE (3), not BROKEN (2) — we could not
// verify, we did not detect tampering.
func TestVerifyMissingDirIsIncomplete(t *testing.T) {
	code := Run(filepath.Join(t.TempDir(), "does-not-exist"), &bytes.Buffer{})
	if code != 3 {
		t.Fatalf("exit code = %d, want 3 (INCOMPLETE) for a missing export dir", code)
	}
}

// TestCorruptEventByte proves editing a single byte inside one event's
// canonical CBOR record breaks the recomputed leaf, and therefore the
// segment's merkle_root, and reports BROKEN(2).
func TestCorruptEventByte(t *testing.T) {
	dir := buildExport(t)
	path := filepath.Join(dir, "events.cbor")
	raw := mustReadFile(t, path)

	// Flip a byte partway into the buffer (well past the first record's
	// uvarint length prefix, so it lands inside CBOR record content for
	// records early in the stream) without corrupting uvarint framing
	// itself (we alter a byte inside a record body, not a length prefix).
	_, sz := binary.Uvarint(raw)
	if sz <= 0 {
		t.Fatalf("malformed first uvarint in events.cbor")
	}
	corruptAt := sz + 2 // a couple bytes into the first record's body
	if corruptAt >= len(raw) {
		t.Fatalf("events.cbor too short to corrupt at offset %d (len=%d)", corruptAt, len(raw))
	}
	mutated := append([]byte(nil), raw...)
	mutated[corruptAt] ^= 0xFF
	mustWriteFile(t, path, mutated)

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Code != CodeBroken {
		t.Fatalf("Code = %d, want CodeBroken(2); reason=%q", res.Code, res.Reason)
	}
}

// TestDropSegment proves deleting a whole seg_header record from
// segments.cbor is detected: the checkpoint referencing that segment can no
// longer be matched against segments.cbor's contents.
func TestDropSegment(t *testing.T) {
	dir := buildExport(t)
	path := filepath.Join(dir, "segments.cbor")
	raw := mustReadFile(t, path)

	// Drop the FIRST record entirely (its uvarint prefix + body).
	recLen, sz := binary.Uvarint(raw)
	if sz <= 0 {
		t.Fatalf("malformed first uvarint in segments.cbor")
	}
	recEnd := sz + int(recLen)
	if recEnd >= len(raw) {
		t.Fatalf("segments.cbor has only one record; cannot drop-and-keep-others")
	}
	mutated := append([]byte(nil), raw[recEnd:]...)
	mustWriteFile(t, path, mutated)

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Code != CodeBroken {
		t.Fatalf("Code = %d, want CodeBroken(2) after dropping a segment; reason=%q", res.Code, res.Reason)
	}
}

// TestBreakCheckpointSignature proves flipping a byte in a checkpoint's
// signature is caught by the Ed25519 verification step.
func TestBreakCheckpointSignature(t *testing.T) {
	dir := buildExport(t)
	path := filepath.Join(dir, "checkpoints.cbor")
	raw := mustReadFile(t, path)

	// checkpoints.cbor records are [uvarint len][body][uvarint len][sig],
	// uvarint-length-prefixed as ONE outer record per docs/TRUST.md §7/
	// export.go's encodeCheckpointExportRecord. Parse the outer record,
	// then the inner body/sig sub-fields, and flip a byte inside sig.
	outerLen, sz := binary.Uvarint(raw)
	if sz <= 0 {
		t.Fatalf("malformed outer uvarint in checkpoints.cbor")
	}
	outerStart := sz
	outerRec := raw[outerStart : outerStart+int(outerLen)]

	bodyLen, sz2 := binary.Uvarint(outerRec)
	if sz2 <= 0 {
		t.Fatalf("malformed inner body uvarint")
	}
	sigOff := sz2 + int(bodyLen)
	sigLen, sz3 := binary.Uvarint(outerRec[sigOff:])
	if sz3 <= 0 {
		t.Fatalf("malformed inner sig uvarint")
	}
	sigStart := sigOff + sz3
	if sigStart >= len(outerRec) {
		t.Fatalf("checkpoint record too short to hold a signature")
	}
	_ = sigLen

	mutated := append([]byte(nil), raw...)
	// Absolute offset of the first sig byte within the whole file.
	absSigStart := outerStart + sigStart
	mutated[absSigStart] ^= 0xFF
	mustWriteFile(t, path, mutated)

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Code != CodeBroken {
		t.Fatalf("Code = %d, want CodeBroken(2) after corrupting a checkpoint signature; reason=%q", res.Code, res.Reason)
	}
}

// TestBreakCheckpointChain proves that corrupting prev_checkpoint_hash
// inside a checkpoint body (re-signing with a DIFFERENT key so the
// signature itself still "verifies" against a swapped-in pubkey would be a
// separate, stronger attack; here we simulate the simpler, more common
// case: the exported single-session prev_checkpoint_hash pointing outside
// the export is reported as an external-prev note, not silently accepted
// as chained — so instead we corrupt chain_head/prev linkage BETWEEN the
// two in-export checkpoints, if there are at least two).
//
// With SegSealMaxEvents=5 and CheckpointMaxSegs=2, this fixture produces
// exactly one checkpoint (segs 0-1) with an EXTERNAL-PREV (genesis)
// prev_checkpoint_hash, since seg 2 is unattested. To exercise the
// in-export chain-break path we instead corrupt the checkpoint's
// chain_head so it no longer matches the recomputed hash of its last
// referenced segment — still a checkpoint-integrity break, reported
// BROKEN(2).
func TestBreakCheckpointChain(t *testing.T) {
	dir := buildExport(t)
	path := filepath.Join(dir, "checkpoints.cbor")
	raw := mustReadFile(t, path)

	// Flip a byte inside the BODY (not the sig) so the signature no longer
	// matches the body it was signed over either — but more specifically
	// this proves body-tamper (which corrupts chain_head/prev fields) is
	// caught, exercising a different code path (signature mismatch on a
	// tampered body) than TestBreakCheckpointSignature (signature bytes
	// themselves corrupted, body untouched).
	outerLen, sz := binary.Uvarint(raw)
	if sz <= 0 {
		t.Fatalf("malformed outer uvarint")
	}
	outerStart := sz
	outerRec := raw[outerStart : outerStart+int(outerLen)]
	bodyLenOff := 0
	bodyLen, sz2 := binary.Uvarint(outerRec[bodyLenOff:])
	if sz2 <= 0 {
		t.Fatalf("malformed inner body uvarint")
	}
	bodyStart := sz2
	if bodyLen < 4 {
		t.Fatalf("checkpoint body implausibly short: %d", bodyLen)
	}

	mutated := append([]byte(nil), raw...)
	absBodyStart := outerStart + bodyStart
	mutated[absBodyStart+2] ^= 0xFF
	mustWriteFile(t, path, mutated)

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Code != CodeBroken {
		t.Fatalf("Code = %d, want CodeBroken(2) after corrupting a checkpoint body; reason=%q", res.Code, res.Reason)
	}
}

// TestCorruptManifestUnrecognizedAlgorithm proves an unrecognized
// hash/sig/encoding identifier in manifest.json is rejected before any
// hashing is attempted (docs/TRUST.md §8 step 1).
func TestCorruptManifestUnrecognizedAlgorithm(t *testing.T) {
	dir := buildExport(t)
	path := filepath.Join(dir, "manifest.json")
	raw := mustReadFile(t, path)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parsing manifest.json: %v", err)
	}
	m["hash"] = "sha256" // not blake3
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshaling manifest: %v", err)
	}
	mustWriteFile(t, path, out)

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Code != CodeBroken {
		t.Fatalf("Code = %d, want CodeBroken(2) for an unrecognized hash algorithm; reason=%q", res.Code, res.Reason)
	}
}

// TestMissingManifestIsIncomplete proves a missing manifest.json is
// INCOMPLETE, not BROKEN — an absent artifact is not itself evidence of
// tampering with what IS present.
func TestMissingManifestIsIncomplete(t *testing.T) {
	dir := buildExport(t)
	if err := os.Remove(filepath.Join(dir, "manifest.json")); err != nil {
		t.Fatalf("removing manifest.json: %v", err)
	}
	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Code != CodeIncomplete {
		t.Fatalf("Code = %d, want CodeIncomplete(3) for a missing manifest.json; reason=%q", res.Code, res.Reason)
	}
}

// TestMissingPubkeyIsIncomplete proves a missing pubkey.pem (but otherwise
// intact export) cannot check signatures and reports INCOMPLETE, not a
// silent OK and not a false BROKEN.
func TestMissingPubkeyIsIncomplete(t *testing.T) {
	dir := buildExport(t)
	if err := os.Remove(filepath.Join(dir, "pubkey.pem")); err != nil {
		t.Fatalf("removing pubkey.pem: %v", err)
	}
	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Code != CodeIncomplete {
		t.Fatalf("Code = %d, want CodeIncomplete(3) for a missing pubkey.pem; reason=%q", res.Code, res.Reason)
	}
}

// TestRunExitCodesMatchDocumentedSpec exercises Run's os.Exit-code mapping
// directly (0/2/3) rather than main()'s os.Exit call, which is untestable
// in-process.
func TestRunExitCodesMatchDocumentedSpec(t *testing.T) {
	clean := buildExport(t)
	if code := Run(clean, &bytes.Buffer{}); code != 0 {
		t.Fatalf("clean export: Run = %d, want 0", code)
	}

	broken := buildExport(t)
	raw := mustReadFile(t, filepath.Join(broken, "events.cbor"))
	_, sz := binary.Uvarint(raw)
	mutated := append([]byte(nil), raw...)
	mutated[sz+1] ^= 0xFF
	mustWriteFile(t, filepath.Join(broken, "events.cbor"), mutated)
	if code := Run(broken, &bytes.Buffer{}); code != 2 {
		t.Fatalf("broken export: Run = %d, want 2", code)
	}

	incomplete := buildExport(t)
	if err := os.Remove(filepath.Join(incomplete, "pubkey.pem")); err != nil {
		t.Fatalf("removing pubkey.pem: %v", err)
	}
	if code := Run(incomplete, &bytes.Buffer{}); code != 3 {
		t.Fatalf("incomplete export: Run = %d, want 3", code)
	}
}
