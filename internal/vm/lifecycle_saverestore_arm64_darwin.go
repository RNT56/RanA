//go:build darwin && arm64 && cgo

package vm

import "fmt"

// SaveState pauses the machine and saves its state to path, enabling a warm
// restore on the next Boot (docs/MACOS.md §3 "Warm start (macOS >=14)"; macOS
// 14+ only — callers on macOS 13 should always cold boot per the floor).
//
// Apple Silicon only: Virtualization.framework's save/restore surface is
// gated to arm64 (D16). Intel gets the stub in the amd64 sibling file.
func (m *Machine) SaveState(path string) error {
	if m.vm.CanPause() {
		if err := m.vm.Pause(); err != nil {
			return fmt.Errorf("vm: Pause: %w", err)
		}
	}
	if err := m.vm.SaveMachineStateToPath(path); err != nil {
		return fmt.Errorf("vm: SaveMachineStateToPath: %w", err)
	}
	return nil
}

// RestoreState restores previously saved guest state from path before the
// next Boot. Must be called before Boot for the restore to take effect (vz
// restores as part of Start after RestoreMachineStateFromURL on the
// not-yet-started machine).
func (m *Machine) RestoreState(path string) error {
	if err := m.vm.RestoreMachineStateFromURL(path); err != nil {
		return fmt.Errorf("vm: RestoreMachineStateFromURL: %w", err)
	}
	return nil
}
