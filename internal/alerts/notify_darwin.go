//go:build darwin

package alerts

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// Runner executes an external command, injectable so DesktopNotifier is
// testable without actually shelling out (CONTRACTS: "both best-effort,
// injectable runner for tests").
type Runner func(name string, args ...string) error

// notifyCommandTimeout bounds how long the real (non-injected) Runner will
// wait for the external notification helper (osascript) before giving up.
// Notify is called synchronously from Engine.Observe, which is itself the
// svc's post-persist callback — CONTRACTS requires the notifier be
// best-effort and never able to block that pipeline. exec.Command's Run
// has no default timeout, so a wedged/hung osascript (e.g. no Notification
// Center session, sandboxed/headless CI) would otherwise stall Observe
// indefinitely. A generous but finite bound preserves "best-effort,
// never blocks" without changing the injectable-Runner test surface.
const notifyCommandTimeout = 5 * time.Second

func execRunner(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), notifyCommandTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run()
}

// DesktopNotifier delivers a best-effort desktop notification via
// `osascript -e 'display notification …'` on macOS. It never blocks the
// alerts pipeline: Notify always returns whatever the runner returns, and
// Engine treats any Notifier error as non-fatal (see engine.go) — this type
// itself does not swallow errors so tests can observe runner failures, but
// it also never panics and never retries/blocks.
type DesktopNotifier struct {
	// Run executes the notification command. Defaults to actually running
	// osascript when nil (production use); tests inject a fake.
	Run Runner
}

// NewDesktopNotifier returns a DesktopNotifier that shells out to
// osascript.
func NewDesktopNotifier() *DesktopNotifier {
	return &DesktopNotifier{Run: execRunner}
}

// Notify implements Notifier.
func (d *DesktopNotifier) Notify(title, body string) error {
	run := d.Run
	if run == nil {
		run = execRunner
	}
	script := "display notification " + quoteAppleScript(body) + " with title " + quoteAppleScript(title)
	return run("osascript", "-e", script)
}

// quoteAppleScript renders s as a double-quoted AppleScript string literal,
// escaping backslashes and double quotes so redacted event text (which may
// contain arbitrary characters, though never raw secrets — it has already
// passed the redaction pipeline) cannot break out of the literal.
func quoteAppleScript(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
