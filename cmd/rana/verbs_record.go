package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/RNT56/RanA/internal/profile"
)

// loadProfileOrGeneric loads the named profile, or the generic default when
// name is empty. It is shared by run and adopt.
func loadProfileOrGeneric(name string) (*profile.Profile, error) {
	if name == "" {
		name = "generic"
	}
	return profile.Load(name)
}

// cmdRun records a single agent run. The heavy lifting — creating the cgroup
// session scope and exec'ing the child inside it (Linux), or routing through
// the guest VM (macOS) — is platform-specific and lives in runPlatform.
func cmdRun(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profileName := fs.String("profile", "", "profile to apply (default: generic)")
	dataDir := fs.String("data", defaultDataDir(), "RanA data directory")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	cmd := fs.Args()
	if len(cmd) == 0 {
		fmt.Fprintln(stderr, "rana run: a command is required:  rana run --profile <p> -- <cmd> [args]")
		return exitUsage
	}

	prof, err := loadProfileOrGeneric(*profileName)
	if err != nil {
		fmt.Fprintf(stderr, "rana run: loading profile: %v\n", err)
		return exitUsage
	}

	return runPlatform(runParams{
		Profile: prof,
		DataDir: *dataDir,
		Command: cmd,
		Stdout:  stdout,
		Stderr:  stderr,
	})
}

// cmdAdopt adopts a long-running agent (the openclaw hero path) into a
// recorded session. Detection and the systemd/guest placement are
// platform-specific (adoptPlatform).
//
// With an explicit target (`rana adopt openclaw`), behavior is unchanged
// from before auto-detect existed. With NO target, it scans running
// processes (detect.go/detect_linux.go/detect_darwin.go) for a match
// against the shipped adoptable packs and either adopts a single
// unambiguous, adoptable match or prints what it found so the user can
// pick explicitly — it never guesses among multiple candidates.
func cmdAdopt(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("adopt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", defaultDataDir(), "RanA data directory")
	yes := fs.Bool("yes", false, "skip the confirmation prompt (consent default is yes)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	if fs.NArg() == 0 {
		return cmdAdoptAutoDetect(adoptDetectParams{
			DataDir: *dataDir,
			Assume:  *yes,
			Stdout:  stdout,
			Stderr:  stderr,
			List:    listRunningProcesses,
		})
	}

	target := fs.Arg(0)
	prof, err := profile.Load(target)
	if err != nil {
		fmt.Fprintf(stderr, "rana adopt: no profile named %q (try: openclaw): %v\n", target, err)
		return exitUsage
	}
	if prof.Adopt == nil {
		fmt.Fprintf(stderr, "rana adopt: profile %q has no [adopt] section — it can't be adopted in place\n", target)
		return exitUsage
	}

	return adoptPlatform(adoptParams{
		Profile: prof,
		Target:  target,
		DataDir: *dataDir,
		Assume:  *yes,
		Stdout:  stdout,
		Stderr:  stderr,
	})
}

// adoptDetectParams carries the parsed CLI state into cmdAdoptAutoDetect.
// List is injectable so tests never touch a real process table.
type adoptDetectParams struct {
	DataDir string
	Assume  bool
	Stdout  io.Writer
	Stderr  io.Writer
	List    processLister
}

// cmdAdoptAutoDetect implements `rana adopt` with no target: scan running
// processes, match against the shipped adoptable packs
// (adoptableProfileNames), and either proceed (single adoptable match) or
// report what was found without guessing (zero, or more than one, match —
// or a match whose profile has no [adopt] section, e.g. claude-code/codex
// today, which are recognizable but not yet in-place-adoptable).
func cmdAdoptAutoDetect(p adoptDetectParams) int {
	candidates, err := detectAdoptCandidates(p.List)
	if err != nil {
		fmt.Fprintf(p.Stderr, "rana adopt: scanning running processes: %v\n", err)
		return exitUsage
	}

	if len(candidates) == 0 {
		fmt.Fprintln(p.Stdout, "rana adopt: no running adoptable agent detected (looked for: "+strings.Join(adoptableProfileNames, ", ")+").")
		fmt.Fprintln(p.Stdout, "Start the agent first, or adopt explicitly:  rana adopt <profile>")
		return exitOK
	}

	var adoptable []detectedCandidate
	for _, c := range candidates {
		if c.Profile.Adopt != nil {
			adoptable = append(adoptable, c)
		}
	}

	if len(candidates) > 1 || len(adoptable) != 1 {
		fmt.Fprintln(p.Stdout, "rana adopt: detected the following running agent(s):")
		for _, c := range candidates {
			note := ""
			if c.Profile.Adopt == nil {
				note = "  (no [adopt] section — recognized, but not yet adoptable in place)"
			}
			fmt.Fprintf(p.Stdout, "  - %s  (pid %d)%s\n", c.Profile.Name, c.Proc.Pid, note)
		}
		if len(adoptable) == 0 {
			fmt.Fprintln(p.Stdout, "\nNone of these can be adopted in place yet. See `rana adopt <profile>` for the full list.")
			return exitOK
		}
		fmt.Fprintln(p.Stdout, "\nMultiple candidates found — pick one explicitly:  rana adopt <profile>")
		return exitOK
	}

	match := adoptable[0]
	fmt.Fprintf(p.Stdout, "rana adopt: detected %s (pid %d) — adopting.\n", match.Profile.Name, match.Proc.Pid)
	return adoptPlatform(adoptParams{
		Profile: match.Profile,
		Target:  match.Profile.Name,
		DataDir: p.DataDir,
		Assume:  p.Assume,
		Stdout:  p.Stdout,
		Stderr:  p.Stderr,
	})
}

// runParams / adoptParams carry the parsed CLI state into the platform-
// specific implementations.
type runParams struct {
	Profile *profile.Profile
	DataDir string
	Command []string
	Stdout  io.Writer
	Stderr  io.Writer
}

type adoptParams struct {
	Profile *profile.Profile
	Target  string
	DataDir string
	Assume  bool
	Stdout  io.Writer
	Stderr  io.Writer
}
