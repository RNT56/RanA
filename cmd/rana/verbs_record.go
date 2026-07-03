package main

import (
	"flag"
	"fmt"
	"io"

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
func cmdAdopt(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("adopt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", defaultDataDir(), "RanA data directory")
	yes := fs.Bool("yes", false, "skip the confirmation prompt (consent default is yes)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	target := "openclaw"
	if fs.NArg() >= 1 {
		target = fs.Arg(0)
	}

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
