package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/report"
	"github.com/RNT56/RanA/internal/service"
)

// defaultHeadsLogPath is where ranad's root-owned, append-only checkpoint
// mirror actually lives (cmd/ranad/main_linux.go's defaultDataDir, D27,
// docs/TRUST.md §5, LIMITS.md §6.1). It is deliberately NOT derived from the
// user's --data directory: the whole point of the mirror is to sit outside
// the uid a same-user attacker controls, so defaulting --heads-log to
// <data>/heads.log would silently check the ledger against a copy that
// attacker can also rewrite.
const defaultHeadsLogPath = "/var/lib/rana/heads.log"

// findingLine renders a verify Finding as one human-readable line.
func findingLine(f ledger.Finding) string {
	s := string(f.Kind)
	if f.Session != "" {
		s += " session=" + f.Session
	}
	if f.Seg != 0 {
		s += fmt.Sprintf(" seg=%d", f.Seg)
	}
	if f.Detail != "" {
		s += ": " + f.Detail
	}
	return s
}

// cmdVerify recomputes the whole chain and maps the ledger's verdict directly
// onto the process exit code: 0 intact (possibly with honest gaps or an
// unattested tail), 2 broken (tamper detected), 3 incomplete (e.g. an
// archived segment is missing). This mapping is the CLI's contract with
// docs/TRUST.md §6 and must never be softened.
func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", defaultDataDir(), "RanA data directory")
	session := fs.String("session", "", "verify only this session id (default: all)")
	mirror := fs.Bool("mirror", false, "cross-check against the root-owned heads.log (plan D27)")
	headsLog := fs.String("heads-log", "", "path to the root-owned heads.log (default: "+defaultHeadsLogPath+"; NOT under --data, which a same-uid attacker can rewrite — plan D27, docs/TRUST.md §5)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	dir := ledger.Dir(*dataDir)
	opts := ledger.VerifyOptions{Session: *session, Mirror: *mirror}
	if *mirror {
		opts.HeadsLogPath = *headsLog
		if opts.HeadsLogPath == "" {
			// The mirror's whole purpose (D27) is to live outside the uid a
			// same-user attacker controls, so the default must NOT be
			// derived from --data (the user-owned datadir) — it must be the
			// root-owned system path ranad actually writes to
			// (cmd/ranad/main_linux.go defaultDataDir, docs/TRUST.md §5,
			// LIMITS.md §6.1). Defaulting to <data>/heads.log would silently
			// cross-check against a file the attacker can also rewrite,
			// defeating the property --mirror exists to provide.
			opts.HeadsLogPath = defaultHeadsLogPath
		}
	}

	res, err := ledger.Verify(dir, opts)
	if err != nil {
		fmt.Fprintf(stderr, "rana verify: %v\n", err)
		return exitUsage
	}

	switch res.Code {
	case ledger.CodeOK:
		fmt.Fprintln(stdout, "OK — chain intact.")
		if len(res.UnattestedTail) > 0 {
			fmt.Fprintf(stdout, "  (%d segment(s) in an unattested tail: sealed since the last checkpoint, not yet signed)\n", len(res.UnattestedTail))
		}
	case ledger.CodeBroken:
		fmt.Fprintln(stdout, "BROKEN — tamper detected:")
		for _, f := range res.Findings {
			fmt.Fprintf(stdout, "  - %s\n", findingLine(f))
		}
	case ledger.CodeIncomplete:
		fmt.Fprintln(stdout, "INCOMPLETE — chain intact but not fully checkable:")
		for _, f := range res.IncompleteNotes {
			fmt.Fprintf(stdout, "  - %s\n", findingLine(f))
		}
	}
	return res.Code
}

// cmdExport writes a portable, independently-verifiable proof pack, or (with
// --format incident) a human-readable incident narrative built from the same
// recorded events. These are two different renderings of one session's
// truth, not two verbs — hence flags on the frozen `export` verb rather than
// a new one (plan D20).
func cmdExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", defaultDataDir(), "RanA data directory")
	session := fs.String("session", "", "session id to export (required)")
	out := fs.String("out", "", "output directory (proof pack) or output file (--format incident; default stdout)")
	format := fs.String("format", "proof", "output shape: proof (default, docs/TRUST.md export) | incident (Markdown narrative, internal/report.IncidentReport)")
	pack := fs.Bool("pack", false, "bundle the export plus the offline verifier viewer into a single <session>.ranaproof archive (proof format only)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	// Positional fallback: `rana export <session> <out>`.
	if *session == "" && fs.NArg() >= 1 {
		*session = fs.Arg(0)
	}
	if *out == "" && fs.NArg() >= 2 {
		*out = fs.Arg(1)
	}
	if *session == "" {
		fmt.Fprintln(stderr, "rana export: --session (or positional <session>) is required")
		return exitUsage
	}

	switch *format {
	case "proof":
		return cmdExportProof(*dataDir, *session, *out, *pack, stdout, stderr)
	case "incident":
		if *pack {
			fmt.Fprintln(stderr, "rana export: --pack applies only to --format proof")
			return exitUsage
		}
		return cmdExportIncident(*dataDir, *session, *out, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "rana export: unknown --format %q (want: proof|incident)\n", *format)
		return exitUsage
	}
}

// cmdExportProof implements the original `rana export` behavior: writing
// docs/TRUST.md §7's export directory, optionally (--pack) bundled into a
// single self-contained <session>.ranaproof archive alongside the offline
// verifier viewer (pack.go).
func cmdExportProof(dataDir, session, out string, pack bool, stdout, stderr io.Writer) int {
	if out == "" {
		fmt.Fprintln(stderr, "rana export: --out (or positional <out>) is required for --format proof")
		return exitUsage
	}

	exportDir := out
	if pack {
		// Export to a scratch directory first, then bundle it — --pack's
		// --out names the .ranaproof file/archive, not a loose directory of
		// export files.
		tmp, err := os.MkdirTemp("", "rana-export-*")
		if err != nil {
			fmt.Fprintf(stderr, "rana export: preparing pack: %v\n", err)
			return exitUsage
		}
		defer os.RemoveAll(tmp)
		exportDir = tmp
	}

	if err := ledger.Export(ledger.Dir(dataDir), session, exportDir); err != nil {
		fmt.Fprintf(stderr, "rana export: %v\n", err)
		return exitUsage
	}

	if !pack {
		fmt.Fprintf(stdout, "Exported session %s to %s\n", session, out)
		fmt.Fprintln(stdout, "Verify it anywhere with: rana-verify-standalone "+out)
		return exitOK
	}

	packPath := out
	if err := writeProofPack(exportDir, packPath, session); err != nil {
		fmt.Fprintf(stderr, "rana export: %v\n", err)
		return exitUsage
	}
	fmt.Fprintf(stdout, "Wrote proof pack for session %s to %s\n", session, packPath)
	fmt.Fprintln(stdout, "Open it anywhere: extract, then open viewer/index.html in a browser")
	fmt.Fprintln(stdout, "  (or run rana-verify-standalone on the exports/ directory inside it).")
	return exitOK
}

// cmdExportIncident renders internal/report.IncidentReport for session to
// stdout, or to a file when out is non-empty.
func cmdExportIncident(dataDir, session, out string, stdout, stderr io.Writer) int {
	ds, err := service.NewLedgerDataSource(ledger.Dir(dataDir))
	if err != nil {
		fmt.Fprintf(stderr, "rana export: %v\n", err)
		return exitUsage
	}
	defer ds.Close()

	text, err := report.IncidentReport(context.Background(), reportDataSource{inner: ds}, session)
	if err != nil {
		fmt.Fprintf(stderr, "rana export: %v\n", err)
		return exitUsage
	}

	if out == "" {
		fmt.Fprint(stdout, text)
		return exitOK
	}
	if err := os.WriteFile(out, []byte(text), 0o644); err != nil {
		fmt.Fprintf(stderr, "rana export: writing %s: %v\n", out, err)
		return exitUsage
	}
	fmt.Fprintf(stdout, "Wrote incident report for session %s to %s\n", session, out)
	return exitOK
}

// cmdGC compacts sealed segments older than the retention TTL into zstd cold
// archives, preserving chain continuity via checkpoint stubs.
func cmdGC(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gc", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", defaultDataDir(), "RanA data directory")
	ttlDays := fs.Int("ttl-days", 30, "archive sealed segments older than this many days")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *ttlDays < 0 {
		fmt.Fprintln(stderr, "rana gc: --ttl-days must not be negative")
		return exitUsage
	}

	n, err := ledger.GC(ledger.Dir(*dataDir), time.Duration(*ttlDays)*24*time.Hour)
	if err != nil {
		fmt.Fprintf(stderr, "rana gc: %v\n", err)
		return exitUsage
	}
	fmt.Fprintf(stdout, "Archived %d sealed segment(s).\n", n)
	return exitOK
}
