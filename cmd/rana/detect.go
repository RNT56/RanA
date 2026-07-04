package main

import (
	"sort"

	"github.com/RNT56/RanA/internal/profile"
)

// runningProcess is the minimal per-process shape rana adopt's auto-detect
// needs to match against a profile pack: the resolved/best-effort
// executable identity and argv. It NEVER carries environment data (P3 — no
// path reads envp/environ, enforced structurally by this type simply
// having no field for it).
type runningProcess struct {
	Pid     int
	ExePath string
	Argv    []string
}

// processLister enumerates candidate processes for auto-detection.
// Implemented per-platform (detect_linux.go via /proc/<pid>/{comm,cmdline},
// detect_darwin.go via `ps -axo pid=,comm=,args=`) and stubbed out in tests
// via a package-var override, so detectAdoptCandidates is fully unit
// testable without touching a real process table.
type processLister func() ([]runningProcess, error)

// detectedCandidate is one auto-detected adoption candidate: the matched
// profile plus the process that matched it.
type detectedCandidate struct {
	Profile *profile.Profile
	Proc    runningProcess
}

// adoptableProfileNames lists the profiles rana adopt's auto-detect scans
// for (task scope: "openclaw/claude-code/codex"). Auto-detect deliberately
// does not scan every shipped pack (e.g. generic-ci, aider, cursor) — it
// targets the long-running, adoptable-in-place agents [adopt] is meant
// for; a profile with no [adopt] section can still be matched and
// reported (so the user learns "this is what's running"), but cannot
// itself be adopted (see cmdAdopt's existing prof.Adopt == nil check,
// unchanged by auto-detect).
var adoptableProfileNames = []string{"openclaw", "claude-code", "codex"}

// detectAdoptCandidates scans running processes (via list) and returns
// every distinct profile that internal/profile.Match selects for at least
// one running process, one detectedCandidate per matched profile (first
// matching process wins, for a stable, deterministic result). Processes
// that match no profile are silently skipped — this is a convenience scan,
// not an inventory of every process on the host (docs/PROFILES.md
// [match]: "matching is a convenience, not attribution").
func detectAdoptCandidates(list processLister) ([]detectedCandidate, error) {
	procs, err := list()
	if err != nil {
		return nil, err
	}

	var candidates []*profile.Profile
	for _, name := range adoptableProfileNames {
		p, err := profile.Load(name)
		if err != nil {
			continue // a shipped pack failing to load is a build problem, not a scan-time error
		}
		candidates = append(candidates, p)
	}

	seen := make(map[string]bool, len(candidates))
	var out []detectedCandidate
	for _, proc := range procs {
		m := profile.Match(candidates, proc.ExePath, proc.Argv)
		if m == nil || seen[m.Name] {
			continue
		}
		seen[m.Name] = true
		out = append(out, detectedCandidate{Profile: m, Proc: proc})
	}

	// Deterministic order regardless of process-table enumeration order.
	sort.Slice(out, func(i, j int) bool { return out[i].Profile.Name < out[j].Profile.Name })
	return out, nil
}
