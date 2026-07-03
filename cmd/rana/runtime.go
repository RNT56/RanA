package main

import (
	"os"
	"path/filepath"
	"runtime"
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
func svcRunDir() string {
	if d := os.Getenv("RANA_RUN_DIR"); d != "" {
		return d
	}
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		return filepath.Join(x, "rana")
	}
	return filepath.Join(os.TempDir(), "rana-run")
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
// environment facts — and no captured agent data.
func hostFingerprint() map[string]any {
	return map[string]any{
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
		"version": version,
	}
}
