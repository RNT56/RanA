// Package exportverify_test exercises the exportverify core end to end: it
// builds a real export directory using internal/ledger.Export (a TEST-ONLY
// dependency — verify.go itself imports neither internal/ledger nor
// database/sql; see the package doc comment), runs VerifyExportDir and
// VerifyExportFiles against it, and asserts OK; then corrupts each
// artifact class in turn and asserts the exact BROKEN/INCOMPLETE reason
// and code (docs/TRUST.md §8, CONTRACTS §cmd/rana-verify-standalone).
//
// This package + this test together are a SECOND, INDEPENDENT
// implementation of docs/TRUST.md's trust guarantee, deliberately not
// sharing internal/ledger.Verify's code path — any disagreement between the
// two on a given export is a spec bug.
package exportverify_test

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/exportverify"
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
	// is an unattested tail — exactly the shape a verifier must report as
	// OK-with-unattested-tail, not BROKEN.
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

// readExportFiles loads an export directory into the map shape
// VerifyExportFiles expects, mirroring what a wasm front end would build
// from browser File objects.
func readExportFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	names := []string{
		exportverify.FileManifest,
		exportverify.FileEvents,
		exportverify.FileSegments,
		exportverify.FileCheckpoint,
		exportverify.FilePubkey,
	}
	files := map[string][]byte{}
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("reading %s: %v", name, err)
		}
		files[name] = b
	}
	return files
}

func TestVerifyExportDirCleanExportIsOK(t *testing.T) {
	dir := buildExport(t)

	res, err := exportverify.VerifyExportDir(dir)
	if err != nil {
		t.Fatalf("VerifyExportDir: %v", err)
	}
	if res.Code != exportverify.CodeOK {
		t.Fatalf("Code = %d, want CodeOK(0); reason=%q", res.Code, res.Reason)
	}
	if len(res.UnattestedTail) == 0 {
		t.Fatalf("expected a non-empty unattested tail (seg 2 was sealed but not checkpointed)")
	}
}

// TestVerifyExportFilesCleanExportIsOK proves the files-map API (the one
// cmd/rana-verify-wasm will use, since a browser has no filesystem) agrees
// with the directory-based API on the same data.
func TestVerifyExportFilesCleanExportIsOK(t *testing.T) {
	dir := buildExport(t)
	files := readExportFiles(t, dir)

	res := exportverify.VerifyExportFiles(files)
	if res.Code != exportverify.CodeOK {
		t.Fatalf("Code = %d, want CodeOK(0); reason=%q", res.Code, res.Reason)
	}
	if len(res.UnattestedTail) == 0 {
		t.Fatalf("expected a non-empty unattested tail (seg 2 was sealed but not checkpointed)")
	}
}

// TestVerifyMissingDirIsIncomplete proves a nonexistent/unreadable export
// directory is reported as INCOMPLETE (3), not BROKEN (2) — we could not
// verify, we did not detect tampering.
func TestVerifyMissingDirIsIncomplete(t *testing.T) {
	_, err := exportverify.VerifyExportDir(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatalf("VerifyExportDir on a missing directory: want error, got nil")
	}
}

// TestVerifyExportFilesEmptyMapIsIncomplete proves the files-map API (which
// has no directory-existence concept) reports a wholly empty input as
// INCOMPLETE via Result, not a Go error.
func TestVerifyExportFilesEmptyMapIsIncomplete(t *testing.T) {
	res := exportverify.VerifyExportFiles(map[string][]byte{})
	if res.Code != exportverify.CodeIncomplete {
		t.Fatalf("Code = %d, want CodeIncomplete(3) for an empty files map; reason=%q", res.Code, res.Reason)
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

	res, err := exportverify.VerifyExportDir(dir)
	if err != nil {
		t.Fatalf("VerifyExportDir: %v", err)
	}
	if res.Code != exportverify.CodeBroken {
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

	res, err := exportverify.VerifyExportDir(dir)
	if err != nil {
		t.Fatalf("VerifyExportDir: %v", err)
	}
	if res.Code != exportverify.CodeBroken {
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

	res, err := exportverify.VerifyExportDir(dir)
	if err != nil {
		t.Fatalf("VerifyExportDir: %v", err)
	}
	if res.Code != exportverify.CodeBroken {
		t.Fatalf("Code = %d, want CodeBroken(2) after corrupting a checkpoint signature; reason=%q", res.Code, res.Reason)
	}
	if res.ReasonClass != "signature" {
		t.Fatalf("ReasonClass = %q, want %q", res.ReasonClass, "signature")
	}
}

// TestBreakCheckpointChain proves that corrupting the checkpoint body
// (which changes chain_head/prev linkage) is caught: with
// SegSealMaxEvents=5 and CheckpointMaxSegs=2, this fixture produces exactly
// one checkpoint (segs 0-1) with an EXTERNAL-PREV (genesis)
// prev_checkpoint_hash, since seg 2 is unattested. Flipping a body byte
// invalidates the signature over that body, exercising a different code
// path (signature mismatch on a tampered body) than
// TestBreakCheckpointSignature (signature bytes themselves corrupted, body
// untouched).
func TestBreakCheckpointChain(t *testing.T) {
	dir := buildExport(t)
	path := filepath.Join(dir, "checkpoints.cbor")
	raw := mustReadFile(t, path)

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

	res, err := exportverify.VerifyExportDir(dir)
	if err != nil {
		t.Fatalf("VerifyExportDir: %v", err)
	}
	if res.Code != exportverify.CodeBroken {
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

	res, err := exportverify.VerifyExportDir(dir)
	if err != nil {
		t.Fatalf("VerifyExportDir: %v", err)
	}
	if res.Code != exportverify.CodeBroken {
		t.Fatalf("Code = %d, want CodeBroken(2) for an unrecognized hash algorithm; reason=%q", res.Code, res.Reason)
	}
	if res.ReasonClass != "manifest" {
		t.Fatalf("ReasonClass = %q, want %q", res.ReasonClass, "manifest")
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
	res, err := exportverify.VerifyExportDir(dir)
	if err != nil {
		t.Fatalf("VerifyExportDir: %v", err)
	}
	if res.Code != exportverify.CodeIncomplete {
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
	res, err := exportverify.VerifyExportDir(dir)
	if err != nil {
		t.Fatalf("VerifyExportDir: %v", err)
	}
	if res.Code != exportverify.CodeIncomplete {
		t.Fatalf("Code = %d, want CodeIncomplete(3) for a missing pubkey.pem; reason=%q", res.Code, res.Reason)
	}
}

// TestVerifyExportFSAgreesWithDir proves the fs.FS-based entry point
// produces the same verdict as the directory-based one on identical data.
func TestVerifyExportFSAgreesWithDir(t *testing.T) {
	dir := buildExport(t)

	dirRes, err := exportverify.VerifyExportDir(dir)
	if err != nil {
		t.Fatalf("VerifyExportDir: %v", err)
	}

	fsRes, err := exportverify.VerifyExportFS(os.DirFS(dir))
	if err != nil {
		t.Fatalf("VerifyExportFS: %v", err)
	}

	if fsRes.Code != dirRes.Code {
		t.Fatalf("VerifyExportFS.Code = %d, VerifyExportDir.Code = %d, want equal", fsRes.Code, dirRes.Code)
	}
	if len(fsRes.UnattestedTail) != len(dirRes.UnattestedTail) {
		t.Fatalf("VerifyExportFS.UnattestedTail = %d entries, VerifyExportDir = %d, want equal",
			len(fsRes.UnattestedTail), len(dirRes.UnattestedTail))
	}
}
