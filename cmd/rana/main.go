// Command rana is the user-facing RanA CLI and session-service host.
//
// The verb set is frozen at plan D20: run, adopt, ps, timeline, show, tail,
// verify, export, gc, doctor, vm (vm is macOS-only; on Linux it prints a
// not-applicable notice). Each verb is deliberately thin — it parses flags
// and calls into the internal packages, which hold all the real logic.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// exit codes. verify deliberately reuses the ledger's 0/2/3 codes
// (docs/TRUST.md §6); everything else uses 0 for success and 1 for a usage
// or runtime error, keeping 2/3 unambiguous as tamper/incomplete signals.
const (
	exitOK    = 0
	exitUsage = 1
)

// dispatch runs one CLI invocation and returns its process exit code. It is
// the single testable entry point: main is just os.Exit(dispatch(...)).
func dispatch(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return exitUsage
	}

	verb, rest := args[0], args[1:]
	switch verb {
	case "run":
		return cmdRun(rest, stdout, stderr)
	case "adopt":
		return cmdAdopt(rest, stdout, stderr)
	case "ps":
		return cmdPs(rest, stdout, stderr)
	case "timeline":
		return cmdTimeline(rest, stdout, stderr)
	case "show":
		return cmdShow(rest, stdout, stderr)
	case "tail":
		return cmdTail(rest, stdout, stderr)
	case "verify":
		return cmdVerify(rest, stdout, stderr)
	case "export":
		return cmdExport(rest, stdout, stderr)
	case "gc":
		return cmdGC(rest, stdout, stderr)
	case "doctor":
		return cmdDoctor(rest, stdout, stderr)
	case "vm":
		return cmdVM(rest, stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return exitOK
	case "version", "--version":
		fmt.Fprintln(stdout, versionString())
		return exitOK
	default:
		fmt.Fprintf(stderr, "rana: unknown command %q\n\n", verb)
		printUsage(stderr)
		return exitUsage
	}
}

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdout, os.Stderr))
}

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

func versionString() string { return "rana " + version }

func printUsage(w io.Writer) {
	fmt.Fprint(w, `rana — the flight recorder for AI agents (chain of custody)

Usage: rana <command> [flags]

Recording
  run       Record a single agent run:  rana run --profile <p> -- <cmd> [args]
  adopt     Adopt a long-running agent (e.g. openclaw) into a recorded session
  ps        List recorded sessions

Inspection
  timeline  Open the localhost timeline UI (token-gated, 127.0.0.1)
  show      Print a session's events:  rana show <session-id>
  tail      Live-tail a session's events

Trust
  verify    Recompute and verify the chain (exit 0=intact, 2=broken, 3=incomplete)
  export    Write a portable, independently-verifiable proof pack
  gc        Compact sealed segments older than the retention TTL

Diagnostics
  doctor    Report this machine's capability tier and RanA's health
  vm        Manage the macOS Linux guest (macOS only)

Global
  help      Show this help
  version   Print the version

Read LIMITS.md before you rely on RanA for anything that matters.
`)
}

// defaultDataDir resolves RanA's per-user data directory (ledger, device key,
// salt, heads mirror). It never reads the recorded agent's environment — this
// is the CLI's own process configuration, distinct from the P3 prohibition on
// capturing an agent's envp/environ into the ledger.
func defaultDataDir() string {
	if d := os.Getenv("RANA_DATA_DIR"); d != "" {
		return d
	}
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "rana")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "rana")
	}
	return filepath.Join(home, ".local", "share", "rana")
}
