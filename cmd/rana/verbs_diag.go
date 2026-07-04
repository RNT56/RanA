package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/service"
)

// cmdTimeline opens the localhost timeline UI: it binds a 127.0.0.1 listener
// on a random port, mounts the token-gated UI over a ledger-backed data
// source, prints the token-bearing URL, and serves until interrupted.
func cmdTimeline(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("timeline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", defaultDataDir(), "RanA data directory")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	ds, err := service.NewLedgerDataSource(ledger.Dir(*dataDir))
	if err != nil {
		fmt.Fprintf(stderr, "rana timeline: %v\n", err)
		return exitUsage
	}
	token, err := service.GenerateLaunchToken()
	if err != nil {
		fmt.Fprintf(stderr, "rana timeline: %v\n", err)
		return exitUsage
	}
	host, err := service.NewTimelineHost(service.TimelineHostConfig{Token: token, DataSource: ds})
	if err != nil {
		fmt.Fprintf(stderr, "rana timeline: %v\n", err)
		return exitUsage
	}

	// Bind 127.0.0.1 only (never 0.0.0.0) — the timeline is single-user,
	// localhost, token-gated by construction (plan D19, §3.4).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(stderr, "rana timeline: %v\n", err)
		return exitUsage
	}
	url := fmt.Sprintf("http://%s/?token=%s", ln.Addr().String(), token)
	fmt.Fprintf(stdout, "Timeline UI: %s\n", url)
	fmt.Fprintln(stdout, "(127.0.0.1 only, token-gated; Ctrl-C to stop)")

	srv := &http.Server{Handler: host.Handler(), ReadHeaderTimeout: 5 * time.Second}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(stderr, "rana timeline: %v\n", err)
		return exitUsage
	}
	return exitOK
}

// cmdTail live-tails a session's events to stdout.
func cmdTail(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tail", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", defaultDataDir(), "RanA data directory")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "rana tail: a session id is required:  rana tail <session-id>")
		return exitUsage
	}
	sessionID := fs.Arg(0)

	ds, err := service.NewLedgerDataSource(ledger.Dir(*dataDir))
	if err != nil {
		fmt.Fprintf(stderr, "rana tail: %v\n", err)
		return exitUsage
	}
	ch, err := ds.Stream(context.Background(), sessionID)
	if err != nil {
		fmt.Fprintf(stderr, "rana tail: %v\n", err)
		return exitUsage
	}
	for ev := range ch {
		printEvent(stdout, ev)
	}
	return exitOK
}

// cmdDoctor reports RanA's health: the common (portable) checks here, plus a
// platform-specific section (kernel/BTF/cgroup tier on Linux; macOS/vz/guest
// on macOS) provided by doctorPlatform. With --report, it instead (in
// addition — see cmdDoctorReport) prints a plain-text, copy-pasteable trust
// card suitable for pasting into an issue or handing to a colleague.
func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", defaultDataDir(), "RanA data directory")
	report := fs.Bool("report", false, "print a shareable, plain-text trust card instead of the interactive health check")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	if *report {
		return cmdDoctorReport(*dataDir, stdout)
	}

	fmt.Fprintln(stdout, versionString())
	fmt.Fprintln(stdout, "")

	// Platform section (build-tagged).
	doctorPlatform(stdout)

	// Common section: data directory + ledger quick-check.
	fmt.Fprintln(stdout, "Data:")
	fmt.Fprintf(stdout, "  data dir:   %s\n", *dataDir)
	dir := ledger.Dir(*dataDir)
	if _, err := os.Stat(dir.DBPath); err != nil {
		fmt.Fprintf(stdout, "  ledger:     none yet (%s)\n", dir.DBPath)
		return exitOK
	}
	if _, err := os.Stat(dir.KeyPath); err == nil {
		fmt.Fprintln(stdout, "  device key: present (0600)")
	} else {
		fmt.Fprintln(stdout, "  device key: MISSING — checkpoints cannot be signed")
	}
	res, err := ledger.Verify(dir, ledger.VerifyOptions{})
	if err != nil {
		fmt.Fprintf(stdout, "  ledger:     present, verify error: %v\n", err)
		return exitOK
	}
	switch res.Code {
	case ledger.CodeOK:
		fmt.Fprintln(stdout, "  ledger:     present, chain intact (rana verify: OK)")
	case ledger.CodeBroken:
		fmt.Fprintln(stdout, "  ledger:     present, CHAIN BROKEN — run `rana verify` (tamper detected)")
	case ledger.CodeIncomplete:
		fmt.Fprintln(stdout, "  ledger:     present, verify incomplete (archived data may be missing)")
	}
	return exitOK
}

// cmdDoctorReport renders the "trust card": a plain-text, copy-pasteable
// summary a stranger can hand to someone else to answer "can I trust this
// recording?" without running anything themselves. It deliberately reuses
// the exact same building blocks as plain `doctor` and `verify` — the
// platform capability-tier section (doctorPlatform) and the ledger's own
// quick-check (ledger.Verify) — rather than inventing a second notion of
// "healthy" that could drift from what those commands actually report
// (P10: documented honesty; P4: claim exactly what the chain delivers).
func cmdDoctorReport(dataDir string, stdout io.Writer) int {
	fmt.Fprintln(stdout, "=== RanA Trust Card ===")
	fmt.Fprintln(stdout, versionString())
	fmt.Fprintln(stdout, "")

	fmt.Fprintln(stdout, "Capability tier:")
	doctorPlatform(stdout)

	fmt.Fprintln(stdout, "Redaction:")
	fmt.Fprintf(stdout, "  corpus:     >=%d seeded secret shapes (test/redaction-corpus/corpus.jsonl)\n", redactionCorpusSize)
	fmt.Fprintln(stdout, "  guarantee:  every captured string is redacted before it is hashed (P3);")
	fmt.Fprintln(stdout, "              no code path reads envp/environ; no flag disables redaction.")
	fmt.Fprintln(stdout, "  regression gate: G4 — >=99% recall on the corpus, zero raw secret leaks")
	fmt.Fprintln(stdout, "")

	fmt.Fprintln(stdout, "Ledger integrity (quick-check):")
	fmt.Fprintf(stdout, "  data dir:   %s\n", dataDir)
	dir := ledger.Dir(dataDir)
	if _, err := os.Stat(dir.DBPath); err != nil {
		fmt.Fprintf(stdout, "  ledger:     none yet (%s)\n", dir.DBPath)
	} else {
		res, err := ledger.Verify(dir, ledger.VerifyOptions{})
		switch {
		case err != nil:
			fmt.Fprintf(stdout, "  ledger:     present, verify error: %v\n", err)
		case res.Code == ledger.CodeOK:
			fmt.Fprintln(stdout, "  ledger:     chain intact (rana verify: OK)")
			if len(res.UnattestedTail) > 0 {
				fmt.Fprintf(stdout, "              (%d segment(s) sealed but not yet checkpoint-signed)\n", len(res.UnattestedTail))
			}
		case res.Code == ledger.CodeBroken:
			fmt.Fprintln(stdout, "  ledger:     BROKEN — tamper detected (rana verify for details)")
		case res.Code == ledger.CodeIncomplete:
			fmt.Fprintln(stdout, "  ledger:     INCOMPLETE — intact but not fully checkable (archived data may be missing)")
		}
	}
	fmt.Fprintln(stdout, "")

	fmt.Fprintln(stdout, "What this does and does not prove:")
	fmt.Fprintln(stdout, "  This card summarizes RanA's own self-checks. It is not a substitute for")
	fmt.Fprintln(stdout, "  reading LIMITS.md, which enumerates exactly what RanA guarantees, what it")
	fmt.Fprintln(stdout, "  explicitly does not, and every known attribution escape. See LIMITS.md")
	fmt.Fprintln(stdout, "  before relying on this recording for anything that matters.")
	return exitOK
}

// redactionCorpusSize is the seeded-secret-shape count backing G4
// (CLAUDE.md §4: "test/redaction-corpus/ (500+ seeded secret shapes) is a
// permanent regression gate"). It is a constant, not a runtime read of
// test/redaction-corpus/corpus.jsonl, because that corpus lives outside
// any binary's embedded assets and a shipped `rana` binary has no
// filesystem-relative access to the source tree it was built from; the
// count is cross-checked against the real corpus by
// internal/redact.TestCorpusMinimumSize, so this constant cannot silently
// drift stale without a test failing.
const redactionCorpusSize = 520
