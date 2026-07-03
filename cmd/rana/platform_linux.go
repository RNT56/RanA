//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/RNT56/RanA/internal/bpf"
	"github.com/RNT56/RanA/internal/session"
)

// runPlatform (Linux) creates the session cgroup scope, execs the child
// inside it, and waits. Kernel-truth capture is delivered by ranad (the
// privileged collector) streaming into the session service over the local
// socket; this command sets up the attribution scope the collector filters
// on. Without a running ranad (and generated eBPF objects) the child still
// runs — observation is inert (P2) — but the timeline will be empty, which
// `rana doctor` explains.
func runPlatform(p runParams) int {
	// Raw cgroupfs driver — the systemd-free fallback. It requires write
	// access to the cgroup v2 hierarchy (root, or a delegated subtree).
	drv := &session.CgroupDriver{}
	sid := session.NewSessionID(nil)
	scopeName := session.ScopeName(sid)
	ctx := context.Background()
	if _, err := drv.CreateScope(ctx, scopeName); err != nil {
		fmt.Fprintf(p.Stderr, "rana run: creating session scope: %v\n", err)
		return exitUsage
	}
	defer func() { _ = drv.DestroyScope(ctx, scopeName) }()

	fmt.Fprintf(p.Stdout, "rana: session %s (profile %s)\n", sid, p.Profile.Name)

	cmd := exec.Command(p.Command[0], p.Command[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, p.Stdout, p.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(p.Stderr, "rana run: starting %q: %v\n", p.Command[0], err)
		return exitUsage
	}
	// Place the child (and thus its descendants, by cgroup inheritance) into
	// the session scope.
	if err := drv.AddProcess(ctx, scopeName, int32(cmd.Process.Pid)); err != nil {
		fmt.Fprintf(p.Stderr, "rana run: attributing child to session: %v\n", err)
		// Non-fatal: keep the child running (inertness), just unattributed.
	}
	if err := cmd.Wait(); err != nil {
		// Propagate the child's own exit code where possible.
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintf(p.Stderr, "rana run: %v\n", err)
		return exitUsage
	}
	return exitOK
}

// adoptPlatform (Linux) writes a systemd drop-in placing the target unit
// under rana.slice, prints it, and (with consent) would reload+restart the
// unit. It never edits the original unit file — adoption is a single,
// documented, reversible drop-in (session.DropIn).
func adoptPlatform(p adoptParams) int {
	unit := p.Target + ".service"
	path, content := session.DropIn(unit, session.ScopeName(p.Target))

	fmt.Fprintf(p.Stdout, "rana adopt %s — planned systemd drop-in:\n\n", p.Target)
	fmt.Fprintf(p.Stdout, "  %s\n", path)
	fmt.Fprintln(p.Stdout, indent(content, "    "))
	fmt.Fprintln(p.Stdout, "This places the gateway and every child it spawns into one recorded")
	fmt.Fprintln(p.Stdout, "session by cgroup inheritance. To undo: delete the file and run")
	fmt.Fprintln(p.Stdout, "`systemctl daemon-reload`.")

	if !p.Assume {
		fmt.Fprintln(p.Stdout, "\nRe-run with --yes to write the drop-in and restart the unit.")
		return exitOK
	}
	// Writing under /etc/systemd/system and restarting a unit requires root;
	// do it honestly and report if we can't.
	if os.Geteuid() != 0 {
		fmt.Fprintln(p.Stderr, "rana adopt: writing the drop-in requires root (sudo rana adopt --yes ...)")
		return exitUsage
	}
	fmt.Fprintf(p.Stdout, "\n(Writing %s and reloading systemd is left to the packaged installer;\n", path)
	fmt.Fprintln(p.Stdout, "this build prints the plan so you can review it first.)")
	return exitOK
}

// cmdVM on Linux is not applicable: native Linux records directly, with no
// guest VM.
func cmdVM(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stdout, "rana vm: not applicable on Linux — native Linux records directly (no guest VM).")
	return exitOK
}

// doctorPlatform (Linux) reports the kernel capability tier.
func doctorPlatform(w io.Writer) {
	fmt.Fprintln(w, "Platform: Linux (native eBPF)")
	tier, err := bpf.DetectKernelTier()
	if err != nil {
		fmt.Fprintf(w, "  kernel tier: unknown (%v)\n", err)
	} else {
		fmt.Fprintf(w, "  kernel tier: %s\n", tier)
	}
	fmt.Fprintln(w, "  (run ranad as root to attach the collector; see docs/ARCHITECTURE.md)")
	fmt.Fprintln(w, "")
}

func indent(s, pad string) string {
	out := ""
	for _, line := range splitLines(s) {
		out += pad + line + "\n"
	}
	return out
}
