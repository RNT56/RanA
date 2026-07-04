package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/report"
	"github.com/RNT56/RanA/internal/schema"
	"github.com/RNT56/RanA/internal/service"
)

// cmdPs lists recorded sessions, newest first.
func cmdPs(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ps", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", defaultDataDir(), "RanA data directory")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	ds, err := service.NewLedgerDataSource(ledger.Dir(*dataDir))
	if err != nil {
		fmt.Fprintf(stderr, "rana ps: %v\n", err)
		return exitUsage
	}
	sessions, err := ds.Sessions(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "rana ps: %v\n", err)
		return exitUsage
	}
	if len(sessions) == 0 {
		fmt.Fprintln(stdout, "No recorded sessions yet.")
		return exitOK
	}
	fmt.Fprintf(stdout, "%-26s  %-14s  %-20s  %s\n", "SESSION", "PROFILE", "STARTED", "STATE")
	for _, s := range sessions {
		state := "active"
		if s.EndedNs != 0 {
			state = "ended"
		}
		fmt.Fprintf(stdout, "%-26s  %-14s  %-20s  %s\n",
			s.ID, s.Profile, formatWall(s.StartedNs), state)
	}
	return exitOK
}

// cmdShow prints a session's events in order. With --diff, it additionally
// runs internal/report.DigestDiff against every fs.settle event and prints
// whether the recorded revision is still available on local disk — never
// file content (report.DigestDiff's own guarantee).
func cmdShow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", defaultDataDir(), "RanA data directory")
	limit := fs.Int("limit", 0, "max events to print (0 = all)")
	diff := fs.Bool("diff", false, "for each fs.settle event, report on-disk digest availability (never content)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "rana show: a session id is required:  rana show <session-id>")
		return exitUsage
	}
	sessionID := fs.Arg(0)

	ds, err := service.NewLedgerDataSource(ledger.Dir(*dataDir))
	if err != nil {
		fmt.Fprintf(stderr, "rana show: %v\n", err)
		return exitUsage
	}
	defer ds.Close()
	events, err := ds.Events(context.Background(), sessionID, 0, *limit)
	if err != nil {
		fmt.Fprintf(stderr, "rana show: %v\n", err)
		return exitUsage
	}
	if len(events) == 0 {
		fmt.Fprintf(stdout, "No events for session %s.\n", sessionID)
		return exitOK
	}
	for _, ev := range events {
		printEvent(stdout, ev)
		if *diff && ev.Type == schema.EventTypeFsSettle {
			printDigestDiff(stdout, ev)
		}
	}
	return exitOK
}

// printDigestDiff renders one fs.settle event's report.DigestDiff outcome
// as an indented follow-up line under the event it belongs to. It never
// prints file content — only the availability Note, and the recorded
// digests as hex, matching report.DigestDiffResult's own guarantee.
func printDigestDiff(w io.Writer, ev schema.Event) {
	res, err := report.DigestDiff(identityPathTranslator{}, ev)
	if err != nil {
		fmt.Fprintf(w, "    diff: %v\n", err)
		return
	}
	fmt.Fprintf(w, "    diff: %s\n", res.Note)
	fmt.Fprintf(w, "      path:       %s\n", res.Path)
	fmt.Fprintf(w, "      new_digest: %s\n", res.NewDigest)
	if res.PrevDigest != "" {
		fmt.Fprintf(w, "      prev_digest: %s\n", res.PrevDigest)
	}
}

// printEvent renders one event as a compact line. It prints only already-
// redacted, effect-level fields (never model I/O — there is none in the
// ledger to print).
func printEvent(w io.Writer, ev schema.Event) {
	fmt.Fprintf(w, "%s  %-20s  pid=%-6d  %s\n",
		formatWall(ev.TsWall), ev.Type, ev.Pid, summarizeData(ev))
}

// summarizeData renders the most useful one-liner per event type from its
// (already-redacted) Data map, without dumping the whole map.
func summarizeData(ev schema.Event) string {
	switch ev.Type {
	case schema.EventTypeProcExec:
		return fmt.Sprintf("%v %v", ev.Data["exe_path"], ev.Data["argv"])
	case schema.EventTypeNetConnect:
		return fmt.Sprintf("%v:%v", ev.Data["daddr"], ev.Data["dport"])
	case schema.EventTypeNetDNS:
		return fmt.Sprintf("%v", ev.Data["qname"])
	case schema.EventTypeFsSensitiveRead:
		return fmt.Sprintf("SENSITIVE %v (rule %v)", ev.Data["path"], ev.Data["rule"])
	case schema.EventTypeGap:
		return fmt.Sprintf("gap reason=%v counts=%v", ev.Data["reason"], ev.Data["counts"])
	default:
		if p, ok := ev.Data["path"]; ok {
			return fmt.Sprintf("%v", p)
		}
		return ""
	}
}

// formatWall renders a CLOCK_REALTIME-ns timestamp as a local time string.
func formatWall(ns uint64) string {
	if ns == 0 {
		return "-"
	}
	return time.Unix(0, int64(ns)).Format("2006-01-02 15:04:05")
}
