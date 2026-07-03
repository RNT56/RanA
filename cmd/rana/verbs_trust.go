package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/RNT56/RanA/internal/ledger"
)

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
	headsLog := fs.String("heads-log", "", "path to heads.log (default: <data>/heads.log)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	dir := ledger.Dir(*dataDir)
	opts := ledger.VerifyOptions{Session: *session, Mirror: *mirror}
	if *mirror {
		opts.HeadsLogPath = *headsLog
		if opts.HeadsLogPath == "" {
			opts.HeadsLogPath = filepath.Join(*dataDir, "heads.log")
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

// cmdExport writes a portable, independently-verifiable proof pack.
func cmdExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", defaultDataDir(), "RanA data directory")
	session := fs.String("session", "", "session id to export (required)")
	out := fs.String("out", "", "output directory (required)")
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
	if *session == "" || *out == "" {
		fmt.Fprintln(stderr, "rana export: --session and --out (or positional <session> <out>) are required")
		return exitUsage
	}

	if err := ledger.Export(ledger.Dir(*dataDir), *session, *out); err != nil {
		fmt.Fprintf(stderr, "rana export: %v\n", err)
		return exitUsage
	}
	fmt.Fprintf(stdout, "Exported session %s to %s\n", *session, *out)
	fmt.Fprintln(stdout, "Verify it anywhere with: rana-verify-standalone "+*out)
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
