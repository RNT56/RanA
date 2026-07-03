//go:build linux

package alerts

import (
	"context"
	"os/exec"
	"time"
)

// Runner executes an external command, injectable so DesktopNotifier is
// testable without actually shelling out (CONTRACTS: "both best-effort,
// injectable runner for tests").
type Runner func(name string, args ...string) error

// notifyCommandTimeout bounds how long the real (non-injected) Runner will
// wait for the external notification helper (notify-send) before giving
// up. Notify is called synchronously from Engine.Observe, which is itself
// the svc's post-persist callback — CONTRACTS requires the notifier be
// best-effort and never able to block that pipeline. exec.Command's Run
// has no default timeout, so a wedged/hung notify-send (e.g. no
// notification daemon running to reap the D-Bus call, headless CI) would
// otherwise stall Observe indefinitely. A generous but finite bound
// preserves "best-effort, never blocks" without changing the
// injectable-Runner test surface.
const notifyCommandTimeout = 5 * time.Second

func execRunner(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), notifyCommandTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run()
}

// DesktopNotifier delivers a best-effort desktop notification via
// `notify-send` on Linux. It never blocks the alerts pipeline: Engine
// treats any Notifier error as non-fatal (see engine.go).
type DesktopNotifier struct {
	// Run executes the notification command. Defaults to actually running
	// notify-send when nil (production use); tests inject a fake.
	Run Runner
}

// NewDesktopNotifier returns a DesktopNotifier that shells out to
// notify-send.
func NewDesktopNotifier() *DesktopNotifier {
	return &DesktopNotifier{Run: execRunner}
}

// Notify implements Notifier.
func (d *DesktopNotifier) Notify(title, body string) error {
	run := d.Run
	if run == nil {
		run = execRunner
	}
	return run("notify-send", "--", title, body)
}
