// Command rana-verify-standalone is the independent, portable reference
// implementation of docs/TRUST.md §8: given nothing but an export directory
// (docs/TRUST.md §7 — events.cbor/segments.cbor/checkpoints.cbor/
// pubkey.pem/manifest.json), it re-derives every hash, Merkle root,
// segment-chain link, and Ed25519 signature from first principles and
// reports whether the exported history is intact.
//
// The verification algorithm itself lives in internal/exportverify, which
// imports NO sqlite, NO internal/ledger, and NO internal/schema — only
// internal/cborcanon, internal/chain, and the Go standard library — so
// that verifying an export never requires trusting (or even building) the
// rest of RanA. This binary is a thin CLI shell around that package; see
// internal/exportverify's package doc comment for the full rationale. Any
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
	"fmt"
	"io"
	"os"

	"github.com/RNT56/RanA/internal/exportverify"
)

// Exit codes, exactly per docs/TRUST.md §6 / internal/ledger.CodeOK et al.
// Redeclared here (rather than referencing exportverify.CodeOK et al.
// directly at every call site) purely for call-site brevity; values are
// kept identical to internal/exportverify's by the TestExitCodesMatch test.
const (
	CodeOK         = exportverify.CodeOK
	CodeBroken     = exportverify.CodeBroken
	CodeIncomplete = exportverify.CodeIncomplete
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

// Result is a local alias of exportverify.Result, kept as a named type in
// this package so existing callers/tests referencing main.Result continue
// to compile unchanged.
type Result = exportverify.Result

// UnattestedSegment is a local alias of exportverify.UnattestedSegment; see
// Result's doc comment.
type UnattestedSegment = exportverify.UnattestedSegment

// Verify delegates to internal/exportverify.VerifyExportDir. Kept as a
// package-level function (rather than inlining the call at Run's call
// site) so existing tests that call main.Verify(dir) directly continue to
// compile unchanged.
func Verify(dir string) (Result, error) {
	return exportverify.VerifyExportDir(dir)
}
