//go:build darwin && amd64 && cgo

package vm

import "errors"

// ErrSaveRestoreUnsupported is returned by SaveState/RestoreState on Intel
// Macs. Virtualization.framework exposes save/restore only on Apple Silicon
// (D16: "Apple Silicon primary; Intel best-effort"), so the warm pool is
// unavailable on Intel. Cold boot is unaffected — callers should fall back to
// always cold-booting when they see this error.
var ErrSaveRestoreUnsupported = errors.New("vm: warm-pool save/restore requires Apple Silicon (Intel is cold-boot only)")

// SaveState is unsupported on Intel; see ErrSaveRestoreUnsupported.
func (m *Machine) SaveState(path string) error { return ErrSaveRestoreUnsupported }

// RestoreState is unsupported on Intel; see ErrSaveRestoreUnsupported.
func (m *Machine) RestoreState(path string) error { return ErrSaveRestoreUnsupported }
