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
// on macOS) provided by doctorPlatform.
func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", defaultDataDir(), "RanA data directory")
	if err := fs.Parse(args); err != nil {
		return exitUsage
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
