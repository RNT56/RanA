//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/RNT56/RanA/internal/bpf"
	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/service"
	"github.com/RNT56/RanA/internal/session"
)

// runPlatform (Linux) implements the frozen `run` verb (part of the frozen
// verb set, per the session/adopt lifecycle): it
// hosts the per-user session service (svc) in-process, creates the session
// cgroup scope, emits session.start, execs the child inside the scope, and on
// exit emits session.end and seals the ledger.
//
// svc listens on the ranad socket (D10: "ranad ... no listening sockets" →
// svc is the listener; ranad, running as root, dials it, SO_PEERCRED-gated to
// root). The socket lives at <runDir>/ranad.sock where runDir defaults to the
// user runtime dir (svcRunDir) — see the v1.2 amendment note in
// docs/ARCHITECTURE.md §3 for why this path is the one documented integration
// choice otherwise left open. When ranad is attached (and its eBPF
// objects are generated), its redacted event stream flows into this svc and
// into the ledger; without ranad the child still runs unaffected (P2 —
// observation is inert) and the timeline is simply empty, which `rana doctor`
// explains.
func runPlatform(p runParams) int {
	ctx := context.Background()

	dir := ledger.Dir(p.DataDir)
	if err := dir.Ensure(); err != nil {
		fmt.Fprintf(p.Stderr, "rana run: preparing data dir: %v\n", err)
		return exitUsage
	}
	salt, err := dir.LoadOrCreateSalt()
	if err != nil {
		fmt.Fprintf(p.Stderr, "rana run: loading redaction salt: %v\n", err)
		return exitUsage
	}
	key, err := loadOrGenerateKey(p.DataDir)
	if err != nil {
		fmt.Fprintf(p.Stderr, "rana run: loading device key: %v\n", err)
		return exitUsage
	}

	sid := session.NewSessionID(nil)
	launchToken, err := service.GenerateLaunchToken()
	if err != nil {
		fmt.Fprintf(p.Stderr, "rana run: %v\n", err)
		return exitUsage
	}

	root := uint32(0)
	svc, err := service.NewService(service.Config{
		LedgerDir:       dir,
		Key:             key,
		Profile:         p.Profile,
		Session:         sid,
		SessionCWD:      workingDir(),
		RedactionSalt:   salt,
		LaunchToken:     launchToken,
		RequireRanadUID: &root, // only root (ranad) may feed the kernel-event socket
		// P5: surface any decode/persist failure loudly rather than dropping
		// events silently.
		OnFault: func(err error) { fmt.Fprintf(p.Stderr, "rana: WARNING event not recorded: %v\n", err) },
	})
	if err != nil {
		fmt.Fprintf(p.Stderr, "rana run: starting session service: %v\n", err)
		return exitUsage
	}
	defer svc.Close()

	// Bind the ranad socket (svc listens; ranad dials — D10). A missing/
	// unbindable socket is non-fatal: the child must still run (P2), just
	// unrecorded, so we warn and continue.
	sockPath := svcSocketPath()
	ln, lerr := listenRanadSocket(sockPath)
	if lerr != nil {
		fmt.Fprintf(p.Stderr, "rana run: not hosting the ranad socket (%v);\n  the agent will run unrecorded until a svc socket is available.\n", lerr)
	} else {
		defer func() { _ = ln.Close(); _ = os.Remove(sockPath) }()
		go acceptRanad(ctx, ln, svc)
	}

	if err := svc.EmitSessionStart(redact.Literal(p.Profile.Name), nil, hostFingerprint(), nil); err != nil {
		fmt.Fprintf(p.Stderr, "rana run: writing session.start: %v\n", err)
		return exitUsage
	}

	// Create the session cgroup scope and exec the child inside it.
	drv := &session.CgroupDriver{}
	scopeName := session.ScopeName(sid)
	if _, err := drv.CreateScope(ctx, scopeName); err != nil {
		fmt.Fprintf(p.Stderr, "rana run: creating session scope: %v\n  (RanA needs cgroup v2 write access; run `rana doctor`)\n", err)
		return exitUsage
	}
	defer func() { _ = drv.DestroyScope(ctx, scopeName) }()

	fmt.Fprintf(p.Stdout, "rana: recording session %s (profile %s)\n", sid, p.Profile.Name)

	cmd := exec.Command(p.Command[0], p.Command[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, p.Stdout, p.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(p.Stderr, "rana run: starting %q: %v\n", p.Command[0], err)
		return exitUsage
	}
	if err := drv.AddProcess(ctx, scopeName, int32(cmd.Process.Pid)); err != nil {
		// Non-fatal: keep the child running (inertness), just unattributed.
		fmt.Fprintf(p.Stderr, "rana run: attributing child to session: %v\n", err)
	}

	waitErr := cmd.Wait()

	// Seal the session regardless of how the child exited.
	if err := svc.EmitSessionEnd(); err != nil {
		fmt.Fprintf(p.Stderr, "rana run: writing session.end: %v\n", err)
	}
	if err := svc.Writer().SealSession(sid); err != nil {
		fmt.Fprintf(p.Stderr, "rana run: sealing session: %v\n", err)
	}
	fmt.Fprintf(p.Stdout, "rana: session %s sealed — `rana timeline` to view, `rana verify` to check.\n", sid)

	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintf(p.Stderr, "rana run: %v\n", waitErr)
		return exitUsage
	}
	return exitOK
}

// acceptRanad serves ranad connections until the listener closes. Each
// connection is handled independently; a hostile/malformed peer cannot take
// down the loop (HandleConn returns per-connection errors).
func acceptRanad(ctx context.Context, ln net.Listener, svc *service.Service) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed on shutdown
		}
		go func() { _ = svc.RanadHandler().HandleConn(conn) }()
	}
}

// listenRanadSocket binds a unix listener at path (creating its parent dir),
// removing any stale socket first.
func listenRanadSocket(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(path) // clear a stale socket from a prior crashed run
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// Owner-only: ranad runs as root and can still connect; no other user can.
	_ = os.Chmod(path, 0o600)
	return ln, nil
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

var errNoKey = errors.New("no device key and could not generate one")

// loadOrGenerateKey loads the datadir's ed25519 device key, generating one on
// first run. GenerateKey refuses to overwrite an existing key, so a
// concurrent first run is safe (the loser reloads).
func loadOrGenerateKey(dataDir string) (chain.KeyInfo, error) {
	key, err := chain.LoadKey(dataDir, "")
	if err == nil {
		return key, nil
	}
	gen, gerr := chain.GenerateKey(dataDir)
	if gerr == nil {
		return gen, nil
	}
	if errors.Is(gerr, chain.ErrKeyExists) {
		// Raced with another run that generated it first; reload.
		if key, err = chain.LoadKey(dataDir, ""); err == nil {
			return key, nil
		}
	}
	return chain.KeyInfo{}, errNoKey
}

// adoptPlatform (Linux) computes the systemd drop-in that would place the
// target unit under rana.slice (session.DropIn) and always prints it for
// review — it never edits the original unit file, and this build never
// itself writes the drop-in or reloads/restarts the unit even with --yes and
// root: that step is left to the packaged installer (see the printed plan
// below). --yes only gates past the "re-run to see what root would do" nudge
// far enough to surface the root-required error when not running as root.
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
		fmt.Fprintln(p.Stdout, "\nRe-run with --yes to confirm (this build still only prints the plan;")
		fmt.Fprintln(p.Stdout, "writing the drop-in and restarting the unit is left to the packaged installer).")
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

func indent(s, pad string) string {
	out := ""
	for _, line := range splitLines(s) {
		out += pad + line + "\n"
	}
	return out
}
