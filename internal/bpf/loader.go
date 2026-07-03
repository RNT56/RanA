//go:build linux

package bpf

// loader.go is the linux-gated attach path: it loads the bpf2go-generated
// CO-RE objects, pins programs/maps under /sys/fs/bpf/rana (idempotent
// re-attach via loader_tier.go's ReattachPlan/PinPath), and emits
// gap{daemon_restart} on every restart (CONTRACTS §internal/bpf). This
// file is linux-only and is compiled but NOT unit-tested by `go test` on
// darwin — CONTRACTS requires only `GOOS=linux go build` to succeed for
// this file; the tier-decision table and pin-path logic it calls into
// (loader_tier.go) carry the actual unit test coverage, portably.
//
// Compile-check happens in CI (make gen; clang -target bpf; then this
// file builds against the generated bindings), never inside `go test`.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// bpffsRoot is the mount point loader.go pins objects under, namespaced
// by PinPath's "/sys/fs/bpf/rana" root (loader_tier.go).
const bpffsRoot = "/sys/fs/bpf/rana"

// Loader owns the lifetime of every attached CO-RE program and pinned
// map for one ranad process. Zero value is not usable; construct via
// NewLoader.
type Loader struct {
	tier       Tier
	links      []link.Link
	reader     *ringbuf.Reader
	prevPinned []string
}

// ErrBPFFSUnavailable is returned when /sys/fs/bpf is not mounted or not
// writable by the caller (must run as the privileged ranad process, D10).
var ErrBPFFSUnavailable = errors.New("bpf: /sys/fs/bpf not available (ranad must run with CAP_BPF and a mounted bpffs)")

// ensureBPFFSRoot makes sure /sys/fs/bpf/rana/{prog,map} exist, returning
// ErrBPFFSUnavailable if /sys/fs/bpf itself is missing (kernels without
// bpffs mounted, or running unprivileged).
func ensureBPFFSRoot() error {
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		return fmt.Errorf("%w: %v", ErrBPFFSUnavailable, err)
	}
	for _, kind := range []string{"prog", "map"} {
		dir := filepath.Join(bpffsRoot, kind)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("bpf: creating pin dir %s: %w", dir, err)
		}
	}
	return nil
}

// pinnedProgramNames lists the names currently pinned under
// /sys/fs/bpf/rana/prog, for ReattachPlan's "pinned" input. Returns an
// empty slice (not an error) if the directory doesn't exist yet (fresh
// install, per ReattachPlan's "fresh start" behavior).
func pinnedProgramNames() ([]string, error) {
	dir := filepath.Join(bpffsRoot, "prog")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// pinProgram pins prog at PinPath("prog", name), removing any stale pin
// at that path first (idempotent re-attach: re-pinning over a live pin
// fails with EEXIST otherwise).
func pinProgram(prog *ebpf.Program, name string) error {
	path, err := SafePinPath("prog", name)
	if err != nil {
		return err
	}
	_ = os.Remove(path) // best-effort: fine if it didn't exist
	return prog.Pin(path)
}

// pinMap pins m at PinPath("map", name), same idempotency treatment as
// pinProgram.
func pinMap(m *ebpf.Map, name string) error {
	path, err := SafePinPath("map", name)
	if err != nil {
		return err
	}
	_ = os.Remove(path)
	return m.Pin(path)
}

// unpinStale removes pins for program names ReattachPlan reported as no
// longer wanted (a hook removed in a newer RanA version).
func unpinStale(names []string) {
	for _, name := range names {
		path, err := SafePinPath("prog", name)
		if err != nil {
			continue // an unsafe name could never have been pinned by us
		}
		_ = os.Remove(path)
	}
}

// DetectKernelTier probes the running kernel's uname release and returns
// the Tier it qualifies for (docs/ARCHITECTURE.md §7). Thin linux-only
// shim over the portable TierForKernel/ParseKernelRelease.
func DetectKernelTier() (Tier, error) {
	release, err := unameRelease()
	if err != nil {
		return TierUnsupported, fmt.Errorf("bpf: reading kernel release: %w", err)
	}
	major, minor, patch, err := ParseKernelRelease(release)
	if err != nil {
		return TierUnsupported, fmt.Errorf("bpf: parsing kernel release %q: %w", release, err)
	}
	return TierForKernel(major, minor, patch)
}
