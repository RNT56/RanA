//go:build !darwin && !linux

package alerts

// DesktopNotifier is the fallback for platforms with no wired-up desktop
// notification mechanism (v1 targets darwin+linux only — CLAUDE.md §2,
// "Windows support (v1)" is out of scope). It behaves like NopNotifier so
// callers can construct one uniformly across platforms without a build-tag
// switch of their own.
type DesktopNotifier struct{}

// NewDesktopNotifier returns a no-op DesktopNotifier on unsupported
// platforms.
func NewDesktopNotifier() *DesktopNotifier { return &DesktopNotifier{} }

// Notify implements Notifier by doing nothing.
func (d *DesktopNotifier) Notify(string, string) error { return nil }
