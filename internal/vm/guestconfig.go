package vm

import (
	"errors"
	"fmt"
	"sort"
)

// DefaultGuestUID is the fixed uid the guest agent process runs as inside
// every RanA guest (docs/ARCHITECTURE.md §6.2: "Guest agent uid pinned
// 1000; a mount-time normalization maps ownership").
// Pinning it lets host-side virtiofs ownership normalization be a fixed,
// well-known mapping rather than something computed per session.
const DefaultGuestUID = 1000

// VirtiofsTag is one resolved virtiofs device configuration entry: a
// granted host directory, its virtiofs device tag, and the fixed path it
// mounts to inside the guest (docs/ARCHITECTURE.md §6.2: "each granted
// host dir -> its own VZVirtioFileSystemDeviceConfiguration tag, mounted
// read-write at /mnt/host/<name> in-guest").
type VirtiofsTag struct {
	Tag            string
	HostRoot       string
	GuestMountPath string
}

// GuestConfig assembles everything needed to boot one RanA guest VM: the
// kernel command line, the set of virtiofs projections, the persistent
// data-volume path, and vsock/uid parameters
// (CONTRACTS §internal/vm: "guest config assembly (kernel cmdline,
// virtiofs tag list, data-volume path — pure struct builders, golden
// tests)").
//
// GuestConfig itself performs no I/O and does not touch vz — it is a pure
// value type whose methods are deterministic string/slice builders, so it
// is fully testable on any platform. The darwin+cgo boot path consumes a
// GuestConfig to build the actual VZVirtualMachineConfiguration.
type GuestConfig struct {
	// DataVolumePath is the host path to the persistent, host-file-backed
	// ext4 disk image for guest-side installs (docs/MACOS.md §1 "Data
	// volume").
	DataVolumePath string

	// Mounts are the granted host directories to project into the guest
	// via virtiofs, one tag each.
	Mounts []Mount

	// VsockCID is the guest's vsock context id for the control/event
	// stream connection (docs/ARCHITECTURE.md §6.2 "Control/data plane:
	// vsock").
	VsockCID uint32

	// GuestUID is the uid the guest agent process runs as. Defaults to
	// DefaultGuestUID (1000) at call sites that don't override it;
	// Validate rejects 0 (root) explicitly — the guest agent must never
	// run as root inside the guest (least privilege applies here too,
	// not just to ranad on the host — P-adjacent hardening, not a
	// frozen CLAUDE.md principle by number, but consistent with D10's
	// "hold the least privilege it can").
	GuestUID uint32
}

// ErrInvalidGuestConfig is returned by Validate when required fields are
// missing or structurally invalid.
var ErrInvalidGuestConfig = errors.New("vm: invalid guest config")

// Validate checks that cfg is well-formed: DataVolumePath is set, VsockCID
// is non-zero (0 is reserved/invalid for vsock context ids), GuestUID is
// non-zero (the guest agent must not run as root), and Mounts contains no
// duplicate tags (delegated to NewPathXlate, which performs the same
// duplicate/shape checks GuestToHost/HostToGuest rely on).
func (c GuestConfig) Validate() error {
	if c.DataVolumePath == "" {
		return fmt.Errorf("%w: DataVolumePath is required", ErrInvalidGuestConfig)
	}
	if c.VsockCID == 0 {
		return fmt.Errorf("%w: VsockCID must be non-zero", ErrInvalidGuestConfig)
	}
	if c.GuestUID == 0 {
		return fmt.Errorf("%w: GuestUID must not be 0 (root)", ErrInvalidGuestConfig)
	}
	if _, err := NewPathXlate(c.Mounts); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidGuestConfig, err)
	}
	return nil
}

// KernelCmdline builds the guest kernel command line. It is a pure,
// deterministic function of fixed boot parameters — CONTRACTS's "pure
// struct builders" — and does not currently vary by GuestConfig field
// (session-specific parameters are passed to the init process over vsock
// after boot, not baked into the cmdline), but takes a value receiver on
// GuestConfig so a future per-session cmdline parameter has an obvious
// home without changing the call signature at every call site.
func (c GuestConfig) KernelCmdline() string {
	return "console=hvc0 root=/dev/vda rw init=/sbin/rana-init panic=1"
}

// VirtiofsTags resolves Mounts into the ordered list of virtiofs device
// configurations to attach at boot, sorted by Tag for deterministic,
// golden-testable output. Returns an empty (non-nil-typed but possibly
// zero-length) slice when Mounts is empty.
func (c GuestConfig) VirtiofsTags() []VirtiofsTag {
	out := make([]VirtiofsTag, 0, len(c.Mounts))
	for _, m := range c.Mounts {
		out = append(out, VirtiofsTag{
			Tag:            m.Tag,
			HostRoot:       m.HostRoot,
			GuestMountPath: guestMountBase + "/" + m.Tag,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out
}
