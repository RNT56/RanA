package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/RNT56/RanA/internal/redact"
)

// svcSocketPath is where the session service (svc) binds the ranad socket and
// where ranad dials it (D10; v1.2 amendment in docs/ARCHITECTURE.md §3). It
// defaults to the user runtime dir so the socket is user-owned and
// user-writable (svc runs as the user; ranad connects as root, which can
// reach any user runtime dir). Overridable via RANA_RUN_DIR to match a
// system deployment's ranad configuration.
func svcSocketPath() string {
	return filepath.Join(svcRunDir(), "ranad.sock")
}

// svcRunDir resolves the runtime directory for the svc socket: RANA_RUN_DIR,
// else $XDG_RUNTIME_DIR/rana, else /run/user/<uid>/rana, else a temp
// fallback. These are all env/derived paths, never captured agent data (P3).
//
// The last-resort temp fallback is namespaced by uid
// (rana-run-<uid>, not a bare shared rana-run) so two different local users
// falling back to the same os.TempDir() (e.g. a bare /tmp with no
// XDG_RUNTIME_DIR set) never contend for the same directory: MkdirAll does
// not tighten the permissions of a directory that already exists, so a
// shared, unqualified fallback path would let whichever user runs `rana
// run` first "claim" it and leave every other local user unable to bind
// their own socket there (a denial of recording, not a spoofing vector —
// svc's RequirePeerUID still gates who may push events in — but worth
// closing since it costs nothing).
func svcRunDir() string {
	if d := os.Getenv("RANA_RUN_DIR"); d != "" {
		return d
	}
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		return filepath.Join(x, "rana")
	}
	if runDir := fmt.Sprintf("/run/user/%d/rana", os.Getuid()); dirUsable(filepath.Dir(runDir)) {
		return runDir
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("rana-run-%d", os.Getuid()))
}

// dirUsable reports whether path exists and is a directory, used to decide
// whether the /run/user/<uid> fallback is viable on this host before
// preferring it over the temp fallback.
func dirUsable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// workingDir returns the current working directory ($SESSION_CWD for the
// profile's digest scopes), or "" if it cannot be determined.
func workingDir() string {
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return ""
}

// hostFingerprint records the host context stamped into session.start
// (os/arch/rana version). It carries no secrets — only static, non-sensitive
// program-controlled facts — and no captured agent data.
//
// The values are wrapped in redact.Literal because they land in the
// session.start event's Data["host"] map, and the canonical encoder accepts a
// string value only as redact.Redacted or an exempt enum type (invariant 2):
// a plain string here makes the whole session.start event fail to encode with
// ErrRawString, silently dropping the session-anchoring event. redact.Literal
// is the correct mechanism for program constants (runtime.GOOS/GOARCH are
// compile-time constants; version is a build-injected program constant) — none
// is captured agent data, so none needs the pipeline.
func hostFingerprint() map[string]any {
	return map[string]any{
		"os":      redact.Literal(runtime.GOOS),
		"arch":    redact.Literal(runtime.GOARCH),
		"version": redact.Literal(version),
	}
}
