//go:build darwin || linux

package alerts

import (
	"errors"
	"testing"
)

// TestDesktopNotifier_UsesInjectedRunner verifies the real platform
// notifier (osascript on darwin, notify-send on linux) never shells out
// directly in tests — it always goes through the injectable Runner
// (CONTRACTS: "injectable runner for tests").
func TestDesktopNotifier_UsesInjectedRunner(t *testing.T) {
	var gotName string
	var gotArgs []string
	d := &DesktopNotifier{Run: func(name string, args ...string) error {
		gotName = name
		gotArgs = args
		return nil
	}}

	if err := d.Notify("RanA", "new domain contacted: example.com"); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if gotName == "" {
		t.Fatal("Runner was never invoked")
	}
	if len(gotArgs) == 0 {
		t.Fatal("Runner invoked with no args")
	}
}

// TestDesktopNotifier_RunnerErrorIsReturnedNotSwallowed verifies Notify
// surfaces the runner's error to its own caller (the Engine is what
// swallows notifier errors — best-effort isolation lives at that layer,
// not silently inside the notifier itself, so tests and callers can still
// observe failures if they want to).
func TestDesktopNotifier_RunnerErrorIsReturnedNotSwallowed(t *testing.T) {
	wantErr := errors.New("no notification daemon running")
	d := &DesktopNotifier{Run: func(string, ...string) error { return wantErr }}

	err := d.Notify("t", "b")
	if !errors.Is(err, wantErr) {
		t.Fatalf("Notify err = %v, want %v", err, wantErr)
	}
}

// TestDesktopNotifier_NilRunnerFallsBackToRealCommand verifies a
// DesktopNotifier with no injected Runner does not panic when constructed
// via NewDesktopNotifier — it does not actually invoke the fallback here
// (that would shell out for real), only checks the zero-value/dfault
// wiring is safe to construct.
func TestDesktopNotifier_NilRunnerFallsBackToRealCommand(t *testing.T) {
	d := NewDesktopNotifier()
	if d == nil {
		t.Fatal("NewDesktopNotifier returned nil")
	}
	if d.Run == nil {
		t.Fatal("NewDesktopNotifier should wire a default Run function")
	}
}
