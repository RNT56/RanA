//go:build darwin && cgo

package vm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	vz "github.com/Code-Hex/vz/v3"
)

// Boot parameters fixed by docs/ARCHITECTURE.md §6.2 for every
// RanA guest: minimal footprint, no graphics/audio/USB, one vsock device
// for the control/event stream, one virtiofs device per granted host dir,
// one virtio-block root disk (the layered base+runtime image), and one
// virtio-block data-volume disk (persistent ext4 for guest-side installs).
const (
	// minGuestCPUs / minGuestMemory are conservative floors; callers may
	// raise them via VMConfig, never below these (the base layer alone
	// needs enough headroom to run ranad + a guest svc + a real agent
	// process tree, docs/MACOS.md).
	minGuestCPUs   = 1
	minGuestMemory = 512 * 1024 * 1024 // 512MiB
)

// ErrVMNotStopped is returned by SaveState when the machine is not in a
// state vz allows saving from.
var ErrVMNotStopped = errors.New("vm: machine must be paused before SaveMachineStateToPath")

// VMConfig bundles what's needed to boot one RanA guest on top of a
// GuestConfig: the resolved kernel/initrd paths (from the verified base
// layer, see image.go), the root and data-volume disk image paths, and
// resource sizing. It is the darwin+cgo counterpart of the portable
// GuestConfig — GuestConfig describes *what* the guest should look like
// (paths, tags, cmdline); VMConfig is what actually drives vz to build
// that.
type VMConfig struct {
	Guest GuestConfig

	// VmlinuzPath and InitrdPath are host paths to the base layer's
	// kernel and initramfs, already extracted from the verified
	// embedded BaseLayer (image.go) to a location vz can open by path.
	VmlinuzPath string
	InitrdPath  string

	// RootDiskPath is the base+runtime layered disk image (read-only
	// or overlay-backed; layering mechanics live in the guest image
	// itself, not here — docs/MACOS.md §1).
	RootDiskPath string

	// CPUCount and MemoryBytes size the guest. Zero values fall back to
	// minGuestCPUs / minGuestMemory.
	CPUCount    uint
	MemoryBytes uint64
}

// resolvedResources returns CPUCount/MemoryBytes with the package floors
// applied.
func (c VMConfig) resolvedResources() (uint, uint64) {
	cpus := c.CPUCount
	if cpus < minGuestCPUs {
		cpus = minGuestCPUs
	}
	mem := c.MemoryBytes
	if mem < minGuestMemory {
		mem = minGuestMemory
	}
	return cpus, mem
}

// Machine wraps a Code-Hex/vz VirtualMachine with RanA's boot/stop/
// save/restore lifecycle and vsock-based control/event connection
// (docs/ARCHITECTURE.md §6.2 "Runtime: Code-Hex/vz/v3 ... Control/data
// plane: vsock").
type Machine struct {
	vm     *vz.VirtualMachine
	socket *vz.VirtioSocketDevice
}

// NewMachine assembles a vz.VirtualMachineConfiguration from cfg
// (validating cfg.Guest via GuestConfig.Validate first) and constructs the
// underlying vz.VirtualMachine. It does not start the machine — call
// Boot for that.
func NewMachine(cfg VMConfig) (*Machine, error) {
	if err := cfg.Guest.Validate(); err != nil {
		return nil, fmt.Errorf("vm: %w", err)
	}
	if cfg.VmlinuzPath == "" {
		return nil, errors.New("vm: VMConfig.VmlinuzPath is required")
	}
	if cfg.RootDiskPath == "" {
		return nil, errors.New("vm: VMConfig.RootDiskPath is required")
	}

	bootOpts := []vz.LinuxBootLoaderOption{
		vz.WithCommandLine(cfg.Guest.KernelCmdline()),
	}
	if cfg.InitrdPath != "" {
		bootOpts = append(bootOpts, vz.WithInitrd(cfg.InitrdPath))
	}
	bootLoader, err := vz.NewLinuxBootLoader(cfg.VmlinuzPath, bootOpts...)
	if err != nil {
		return nil, fmt.Errorf("vm: NewLinuxBootLoader: %w", err)
	}

	cpus, mem := cfg.resolvedResources()
	vmConfig, err := vz.NewVirtualMachineConfiguration(bootLoader, cpus, mem)
	if err != nil {
		return nil, fmt.Errorf("vm: NewVirtualMachineConfiguration: %w", err)
	}

	// Root disk (layered base+runtime image).
	rootAttach, err := vz.NewDiskImageStorageDeviceAttachment(cfg.RootDiskPath, false)
	if err != nil {
		return nil, fmt.Errorf("vm: root disk attachment: %w", err)
	}
	rootDisk, err := vz.NewVirtioBlockDeviceConfiguration(rootAttach)
	if err != nil {
		return nil, fmt.Errorf("vm: root disk device: %w", err)
	}

	// Persistent data volume (docs/MACOS.md §1 "Data volume").
	dataAttach, err := vz.NewDiskImageStorageDeviceAttachment(cfg.Guest.DataVolumePath, false)
	if err != nil {
		return nil, fmt.Errorf("vm: data volume attachment: %w", err)
	}
	dataDisk, err := vz.NewVirtioBlockDeviceConfiguration(dataAttach)
	if err != nil {
		return nil, fmt.Errorf("vm: data volume device: %w", err)
	}

	vmConfig.SetStorageDevicesVirtualMachineConfiguration([]vz.StorageDeviceConfiguration{rootDisk, dataDisk})

	// Virtiofs projections: one tag per granted host dir, mounted
	// read-write, never as rootfs (docs/ARCHITECTURE.md §6.2).
	tags := cfg.Guest.VirtiofsTags()
	fsDevices := make([]vz.DirectorySharingDeviceConfiguration, 0, len(tags))
	for _, t := range tags {
		shared, err := vz.NewSharedDirectory(t.HostRoot, false)
		if err != nil {
			return nil, fmt.Errorf("vm: NewSharedDirectory(%q): %w", t.HostRoot, err)
		}
		share, err := vz.NewSingleDirectoryShare(shared)
		if err != nil {
			return nil, fmt.Errorf("vm: NewSingleDirectoryShare(%q): %w", t.Tag, err)
		}
		fsConfig, err := vz.NewVirtioFileSystemDeviceConfiguration(t.Tag)
		if err != nil {
			return nil, fmt.Errorf("vm: NewVirtioFileSystemDeviceConfiguration(%q): %w", t.Tag, err)
		}
		fsConfig.SetDirectoryShare(share)
		fsDevices = append(fsDevices, fsConfig)
	}
	if len(fsDevices) > 0 {
		vmConfig.SetDirectorySharingDevicesVirtualMachineConfiguration(fsDevices)
	}

	// vsock control/event plane (docs/ARCHITECTURE.md §6.2).
	sockConfig, err := vz.NewVirtioSocketDeviceConfiguration()
	if err != nil {
		return nil, fmt.Errorf("vm: NewVirtioSocketDeviceConfiguration: %w", err)
	}
	vmConfig.SetSocketDevicesVirtualMachineConfiguration([]vz.SocketDeviceConfiguration{sockConfig})

	if ok, err := vmConfig.Validate(); !ok {
		return nil, fmt.Errorf("vm: invalid VirtualMachineConfiguration: %w", err)
	}

	vm, err := vz.NewVirtualMachine(vmConfig)
	if err != nil {
		return nil, fmt.Errorf("vm: NewVirtualMachine: %w", err)
	}

	m := &Machine{vm: vm}
	if devs := vm.SocketDevices(); len(devs) > 0 {
		m.socket = devs[0]
	}
	return m, nil
}

// Boot starts the guest (docs/MACOS.md §3 "Cold boot: <=10s (gate G3)").
// vz's Start blocks until the machine has been told to start (not until
// it finishes booting the kernel — callers wanting to wait for a
// specific runtime milestone should use WaitState or their own
// vsock-based readiness signal from the guest).
func (m *Machine) Boot(ctx context.Context) error {
	type result struct{ err error }
	ch := make(chan result, 1)
	go func() {
		ch <- result{m.vm.Start()}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return fmt.Errorf("vm: Start: %w", r.err)
		}
		return nil
	}
}

// Stop requests a graceful guest shutdown, falling back to a hard Stop if
// the guest does not support a graceful stop request.
func (m *Machine) Stop() error {
	if m.vm.CanRequestStop() {
		if _, err := m.vm.RequestStop(); err == nil {
			return nil
		}
	}
	if !m.vm.CanStop() {
		return errors.New("vm: machine cannot be stopped from its current state")
	}
	return m.vm.Stop()
}

// SaveState/RestoreState (warm-pool save/restore) live in
// lifecycle_saverestore_{arm64,amd64}_darwin.go: the underlying vz APIs
// (SaveMachineStateToPath/RestoreMachineStateFromURL) exist only on Apple
// Silicon, so Intel gets a stub returning ErrSaveRestoreUnsupported (D16:
// "Apple Silicon primary; Intel best-effort" — cold boot still works on
// Intel; only the warm pool is unavailable there).

// State reports the current vz machine state, for `rana vm status`.
func (m *Machine) State() vz.VirtualMachineState {
	return m.vm.State()
}

// ErrNoSocketDevice is returned by DialVsock when the machine was
// constructed with no vsock device configured.
var ErrNoSocketDevice = errors.New("vm: no vsock socket device configured on this machine")

// DialVsock connects to the given vsock port inside the guest, returning a
// net.Conn suitable for use as PortForward's DialFunc (docs/ARCHITECTURE.md
// §6.2: "vz ... exposes it as net.Conn"). This is the production
// implementation of DialFunc — PortForward and the wire-frame client code
// consume it through that portable interface, never importing vz directly.
func (m *Machine) DialVsock(ctx context.Context, port uint32) (net.Conn, error) {
	if m.socket == nil {
		return nil, ErrNoSocketDevice
	}

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := m.socket.Connect(port)
		ch <- result{conn, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("vm: vsock connect port %d: %w", port, r.err)
		}
		return r.conn, nil
	}
}

// ListenVsock listens for guest-initiated connections on the given vsock
// port (used for the guest->host event stream, where the guest dials out
// to the host rather than the host dialing in).
func (m *Machine) ListenVsock(port uint32) (*vz.VirtioSocketListener, error) {
	if m.socket == nil {
		return nil, ErrNoSocketDevice
	}
	l, err := m.socket.Listen(port)
	if err != nil {
		return nil, fmt.Errorf("vm: vsock listen port %d: %w", port, err)
	}
	return l, nil
}

// WaitState blocks until the machine reaches want or ctx is cancelled,
// polling StateChangedNotify.
func (m *Machine) WaitState(ctx context.Context, want vz.VirtualMachineState) error {
	if m.vm.State() == want {
		return nil
	}
	ch := m.vm.StateChangedNotify()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case s, ok := <-ch:
			if !ok {
				return fmt.Errorf("vm: state-change channel closed before reaching state %v", want)
			}
			if s == want {
				return nil
			}
		case <-time.After(30 * time.Second):
			return fmt.Errorf("vm: timed out waiting for state %v (current: %v)", want, m.vm.State())
		}
	}
}
