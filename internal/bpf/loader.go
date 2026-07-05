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
// NewLoader (loader_attach.go — requires the rana_bpf_generated build
// tag, i.e. `go generate ./internal/bpf` must have run).
type Loader struct {
	tier       Tier
	links      []link.Link
	reader     *ringbuf.Reader
	prevPinned []string

	// Shared maps, populated by NewLoader from the first-loaded object
	// group and shared into every other group via MapReplacements (each
	// group's ELF declares the same common.h maps; without replacement
	// each load would create its own disjoint ringbuf/session set).
	sessions     *ebpf.Map
	sessionPids  *ebpf.Map
	events       *ebpf.Map
	sensPrefixes *ebpf.Map
	sensInodes   *ebpf.Map

	// closers holds the generated object groups' Close funcs (their
	// Close detaches nothing — links do that — but releases program/map
	// FDs; ebpf.Collection.Close returns no error, hence func()).
	closers []func()

	// lsmDegraded records why the optional lsm/socket_connect hook did
	// not attach ("" when attached or not wanted at this tier). Optional
	// coverage, not v1-completeness (loader_tier.go Features) — but the
	// degradation must be loud (P5/P10), so it is surfaced, never
	// swallowed.
	lsmDegraded string
}

// Tier reports the kernel tier the loader attached at.
func (l *Loader) Tier() Tier { return l.tier }

// LSMDegraded reports why the optional lsm/socket_connect hook is not
// active ("" when it is, or when the tier never wanted it). Callers
// surface this in doctor/status output — never silently (P10).
func (l *Loader) LSMDegraded() string { return l.lsmDegraded }

// Events returns the ring buffer reader for rana_events. The caller owns
// the read loop; Close on the Loader closes the reader (unblocking any
// blocked Read).
func (l *Loader) Events() *ringbuf.Reader { return l.reader }

// RegisterSession marks cgid as a recorded session in the in-kernel
// filter map (rana_sessions): from this moment the kernel emits events
// for tasks in that cgroup. Idempotent.
func (l *Loader) RegisterSession(cgid uint64) error {
	var one uint8 = 1
	if l.sessions == nil {
		return errors.New("bpf: loader has no sessions map (not constructed via NewLoader)")
	}
	return l.sessions.Put(cgid, one)
}

// UnregisterSession removes cgid from the in-kernel filter map. Removing
// a never-registered cgid is not an error (idempotent teardown).
func (l *Loader) UnregisterSession(cgid uint64) error {
	if l.sessions == nil {
		return errors.New("bpf: loader has no sessions map (not constructed via NewLoader)")
	}
	if err := l.sessions.Delete(cgid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// sensitivePrefixKey mirrors bpf/src/common.h's
// struct rana_sensitive_prefix_key exactly: 1 length byte + 256 prefix
// bytes, no padding (257-byte key).
type sensitivePrefixKey struct {
	Len    uint8
	Prefix [256]uint8
}

// AddSensitivePrefix registers a watchlisted path in the in-kernel D9
// sensitive-read map. The path must be absolute and resolved; matching in
// the kernel is an exact-length hash lookup against the resolved path
// (bpf/src/rana_fs.c), so callers register each watched path at its
// natural full length. Paths longer than 256 bytes are rejected (the
// kernel-side key is fixed-size; such paths fall back to inode pinning).
func (l *Loader) AddSensitivePrefix(path string, rule uint32) error {
	if l.sensPrefixes == nil {
		return errors.New("bpf: loader has no sensitive-prefix map (not constructed via NewLoader)")
	}
	if len(path) == 0 || len(path) > 256 {
		return fmt.Errorf("bpf: sensitive prefix must be 1..256 bytes, got %d", len(path))
	}
	var key sensitivePrefixKey
	key.Len = uint8(len(path))
	copy(key.Prefix[:], path)
	return l.sensPrefixes.Put(&key, rule)
}

// Close detaches every link, closes the ring buffer reader, and releases
// the generated object groups. Pins under /sys/fs/bpf/rana are left in
// place deliberately — they are the idempotent-reattach handshake for the
// next ranad process (ReattachPlan); a clean uninstall removes them via
// `rana doctor --cleanup` (out of this package's scope).
func (l *Loader) Close() error {
	var firstErr error
	if l.reader != nil {
		if err := l.reader.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, lk := range l.links {
		if err := lk.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, c := range l.closers {
		c()
	}
	return firstErr
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
