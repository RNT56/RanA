// Package bpf owns RanA's eBPF CO-RE programs (bpf/src/*.c), the
// bpf2go-generated Go bindings, and the loader that attaches them on
// Linux (CONTRACTS §internal/bpf, plan D4/D5/D7, docs/ARCHITECTURE.md
// §2/§7).
//
// This file (loader_tier.go) is deliberately portable — no linux build
// tag, no cgo, no dependency on github.com/cilium/ebpf's linux-only
// surface — so the tier-decision table and pin-path logic that govern
// *what* the linux-gated loader (loader.go) attaches can be unit-tested
// on darwin, per CONTRACTS' instruction to "put the tier-decision table +
// pin-path logic in a PORTABLE file... so it runs on darwin".
package bpf

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/RNT56/RanA/internal/schema"
)

// Tier identifies which feature tier a running kernel supports, per
// docs/ARCHITECTURE.md §7 / plan D5. `rana doctor` reports the active
// tier; the loader uses it to decide which optional programs to attach.
type Tier int

// Tier values, ordered baseline-and-up so callers can compare with >=.
const (
	// TierUnsupported means the kernel is below RanA's 5.15 floor (D5)
	// and cannot run any hook set; ranad refuses to start and `rana
	// doctor` reports remediation.
	TierUnsupported Tier = iota
	// TierBaseline is the 5.15 LTS floor: tracepoints, ringbuf, fentry,
	// cgroup/connect4·6, sensitive-read map — the complete v1 product
	// (plan D5: "The product is complete at Baseline; higher tiers are
	// efficiency and coverage, not features.").
	TierBaseline
	// TierEnhanced (>=5.18) adds kprobe-multi for cheaper fs attach.
	TierEnhanced
	// TierPreferred (>=6.6) adds tcx flow accounting, tightening
	// io_uring network coverage.
	TierPreferred
)

// String renders a Tier's stable, human-readable name, used by `rana
// doctor` output and log lines.
func (t Tier) String() string {
	switch t {
	case TierUnsupported:
		return "unsupported"
	case TierBaseline:
		return "baseline"
	case TierEnhanced:
		return "enhanced"
	case TierPreferred:
		return "preferred"
	default:
		return "unknown"
	}
}

// Features describes which optional capabilities a Tier unlocks. Every
// field is additive: a higher tier's Features has every lower (attained)
// tier's fields also true, per docs/ARCHITECTURE.md §7 ("higher tiers are
// efficiency and coverage, not features").
type Features struct {
	// Ringbuf, CgroupSockAddr, Fentry, SensitiveReadMap are the
	// complete v1 hook set (D7), all available starting at the 5.15
	// floor (D5).
	Ringbuf          bool
	CgroupSockAddr   bool
	Fentry           bool
	SensitiveReadMap bool
	// KprobeMulti is available from TierEnhanced (>=5.18): a cheaper
	// attach mechanism for fs hooks, not a new capability.
	KprobeMulti bool
	// Tcx is available from TierPreferred (>=6.6): tightens io_uring
	// network coverage.
	Tcx bool
	// LSMSocketConnect is available from TierEnhanced (>=5.18): attaches
	// rana_socket_connect (bpf/src/rana_net.c), an lsm/socket_connect
	// hook that closes the io_uring IORING_OP_CONNECT escape documented
	// in LIMITS.md's "io_uring socket ops" row — BPF LSM program
	// attachment is a well-supported, stable mechanism from this tier up
	// (docs/ARCHITECTURE.md §7). Coverage, not a v1-completeness
	// requirement (D5): baseline's cgroup/connect4·6 already catches the
	// overwhelming majority of connects; this closes the one documented
	// gap on kernels that support it.
	LSMSocketConnect bool
}

// Features returns the capability set unlocked at tier t. TierUnsupported
// unlocks nothing.
func (t Tier) Features() Features {
	if t < TierBaseline {
		return Features{}
	}
	f := Features{
		Ringbuf:          true,
		CgroupSockAddr:   true,
		Fentry:           true,
		SensitiveReadMap: true,
	}
	if t >= TierEnhanced {
		f.KprobeMulti = true
		f.LSMSocketConnect = true
	}
	if t >= TierPreferred {
		f.Tcx = true
	}
	return f
}

// Kernel floor and tier thresholds, per plan D5 / docs/ARCHITECTURE.md §7.
var (
	kernelFloor    = kernelVersion{5, 15, 0}
	enhancedFloor  = kernelVersion{5, 18, 0}
	preferredFloor = kernelVersion{6, 6, 0}
)

type kernelVersion struct{ major, minor, patch int }

// less reports whether v is strictly older than other.
func (v kernelVersion) less(other kernelVersion) bool {
	if v.major != other.major {
		return v.major < other.major
	}
	if v.minor != other.minor {
		return v.minor < other.minor
	}
	return v.patch < other.patch
}

// ErrKernelTooOld is returned by TierForKernel when the given version is
// below RanA's 5.15 LTS floor (D5). `rana doctor` surfaces this as
// remediation guidance, not a crash.
var ErrKernelTooOld = errors.New("bpf: kernel below RanA's 5.15 floor")

// TierForKernel maps a (major, minor, patch) kernel version to a Tier per
// the table in docs/ARCHITECTURE.md §7:
//
//	Baseline  : 5.15
//	Enhanced  : >= 5.18
//	Preferred : >= 6.6
//
// Returns ErrKernelTooOld (wrapped) for anything below 5.15.
func TierForKernel(major, minor, patch int) (Tier, error) {
	v := kernelVersion{major, minor, patch}
	if v.less(kernelFloor) {
		return TierUnsupported, fmt.Errorf("bpf: kernel %d.%d.%d: %w", major, minor, patch, ErrKernelTooOld)
	}
	if !v.less(preferredFloor) {
		return TierPreferred, nil
	}
	if !v.less(enhancedFloor) {
		return TierEnhanced, nil
	}
	return TierBaseline, nil
}

// ParseKernelRelease parses a uname-release-shaped string (e.g.
// "5.15.0-102-generic", "6.6.30-mainline", "6.1") into (major, minor,
// patch). Only the leading dotted-numeric prefix is significant; any
// suffix starting at the first non-digit, non-dot character (a distro
// build tag, "-generic", "+", etc.) is ignored. A missing patch component
// defaults to 0. Returns an error if no valid major.minor can be parsed.
func ParseKernelRelease(release string) (major, minor, patch int, err error) {
	// Isolate the leading "N.N.N"-shaped prefix: split on the first rune
	// that isn't a digit or '.', then parse the dotted numeric fields
	// that remain.
	cut := len(release)
	for i, r := range release {
		if !(r >= '0' && r <= '9') && r != '.' {
			cut = i
			break
		}
	}
	numeric := release[:cut]
	numeric = strings.Trim(numeric, ".")
	if numeric == "" {
		return 0, 0, 0, fmt.Errorf("bpf: cannot parse kernel release %q", release)
	}
	parts := strings.Split(numeric, ".")
	if len(parts) < 2 {
		return 0, 0, 0, fmt.Errorf("bpf: kernel release %q missing minor version", release)
	}
	nums := make([]int, 0, 3)
	for _, p := range parts {
		if p == "" {
			return 0, 0, 0, fmt.Errorf("bpf: kernel release %q has an empty version component", release)
		}
		n, convErr := strconv.Atoi(p)
		if convErr != nil {
			return 0, 0, 0, fmt.Errorf("bpf: kernel release %q: %w", release, convErr)
		}
		nums = append(nums, n)
		if len(nums) == 3 {
			break
		}
	}
	major = nums[0]
	minor = nums[1]
	if len(nums) == 3 {
		patch = nums[2]
	}
	return major, minor, patch, nil
}

// pinRoot is the fixed root every RanA pin lives under (CONTRACTS
// §internal/bpf: "pins under /sys/fs/bpf/rana").
const pinRoot = "/sys/fs/bpf/rana"

// PinPath returns the bpffs pin path for a named program or map of the
// given kind ("prog" or "map"), e.g. PinPath("prog", "rana_on_exec") ->
// "/sys/fs/bpf/rana/prog/rana_on_exec". Stable across calls (required for
// idempotent re-attach: the loader recomputes the same path on every
// start and checks whether something is already pinned there). Does not
// validate name safety — see SafePinPath for the validating variant used
// on any name that did not originate from a compile-time constant in this
// package.
func PinPath(kind, name string) string {
	return pinRoot + "/" + kind + "/" + name
}

// ErrUnsafePinName is returned by SafePinPath when name is not a safe,
// single-path-segment identifier.
var ErrUnsafePinName = errors.New("bpf: unsafe pin name")

// SafePinPath is PinPath with validation: name must be non-empty, contain
// no '/' or NUL, and no path-traversal segment ("." or ".."), and must
// not contain whitespace (pin names are program/map symbol names, which
// are always valid C identifiers — anything else is treated as unsafe
// rather than silently sanitized, since pin paths are filesystem paths
// under a root ranad, running as root, controls).
func SafePinPath(kind, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: empty name", ErrUnsafePinName)
	}
	if strings.ContainsAny(name, "/\x00") {
		return "", fmt.Errorf("%w: %q contains a path separator or NUL", ErrUnsafePinName, name)
	}
	if name == "." || name == ".." {
		return "", fmt.Errorf("%w: %q is a path-traversal segment", ErrUnsafePinName, name)
	}
	for _, r := range name {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return "", fmt.Errorf("%w: %q contains whitespace", ErrUnsafePinName, name)
		}
	}
	return PinPath(kind, name), nil
}

// ReattachResult is the outcome of comparing what is currently pinned
// against what this loader run wants attached.
type ReattachResult struct {
	// ToLoad are program names that need to be loaded and pinned (not
	// currently present).
	ToLoad []string
	// Skip are program names already pinned and wanted again — the
	// loader leaves these alone (idempotent re-attach).
	Skip []string
	// Stale are program names currently pinned but no longer in the
	// wanted set (e.g. a hook removed in a newer RanA version) — the
	// linux-gated loader unpins these.
	Stale []string
}

// ReattachPlan computes the idempotent re-attach decision described in
// CONTRACTS §internal/bpf ("idempotent re-attach"): given the program
// names currently pinned under /sys/fs/bpf/rana and the set this loader
// run wants attached, it partitions wanted into ToLoad/Skip and reports
// any currently-pinned name no longer wanted as Stale. A restart with an
// identical wanted set against its own prior pins is a no-op (ToLoad and
// Stale both empty).
func ReattachPlan(pinned, wanted []string) ReattachResult {
	pinnedSet := make(map[string]bool, len(pinned))
	for _, p := range pinned {
		pinnedSet[p] = true
	}
	wantedSet := make(map[string]bool, len(wanted))

	var result ReattachResult
	for _, w := range wanted {
		if wantedSet[w] {
			continue // de-dup a caller passing the same name twice
		}
		wantedSet[w] = true
		if pinnedSet[w] {
			result.Skip = append(result.Skip, w)
		} else {
			result.ToLoad = append(result.ToLoad, w)
		}
	}
	for _, p := range pinned {
		if !wantedSet[p] {
			result.Stale = append(result.Stale, p)
		}
	}
	return result
}

// baselineProgramNames are the complete v1 hook set (D5: "the product is
// complete at Baseline; higher tiers are efficiency and coverage, not
// features"), wanted at every supported tier (Baseline/Enhanced/
// Preferred). Names match the SEC() function symbol bpf2go generates a Go
// accessor for in bpf/src/*.c — these are the names the linux-gated
// loader passes to ReattachPlan and pins under PinPath("prog", name).
//
// rana_path_link (bpf/src/rana_fs.c, fentry/security_path_link) is part
// of this baseline set, not gated to a higher tier: it closes the
// hardlink-into-watchlist dodge (LIMITS.md) using only a plain fentry
// attach, which has been available since the 5.15 floor — there is no
// coverage reason to withhold it below Enhanced/Preferred.
var baselineProgramNames = []string{
	"rana_on_exec", "rana_on_fork", "rana_on_exit",
	"rana_connect4", "rana_connect6", "rana_sendmsg4", "rana_sendmsg6",
	"rana_unix_connect", "rana_flow_close",
	"rana_file_open", "rana_path_unlink", "rana_path_rename", "rana_path_mkdir",
	"rana_vfs_truncate", "rana_path_link",
	"rana_dns_egress",
	"rana_cgroup_attach_task",
}

// WantedPrograms returns the BPF program names the loader should attach
// at the given tier: the complete baseline hook set at every supported
// tier, plus rana_socket_connect (the io_uring-closing LSM hook,
// bpf/src/rana_net.c) once Features().LSMSocketConnect unlocks at
// TierEnhanced+. Returns an empty slice for TierUnsupported — nothing
// attaches on a kernel below RanA's floor (ranad refuses to start).
//
// This is the portable half of "what should be attached"; the linux-gated
// loader (loader.go/loader_attach.go) is responsible for actually loading
// and pinning the bpf2go-generated program with each of these names and
// for feeding the result, plus whatever is currently pinned, into
// ReattachPlan.
func WantedPrograms(tier Tier) []string {
	if tier < TierBaseline {
		return nil
	}
	names := make([]string, len(baselineProgramNames))
	copy(names, baselineProgramNames)
	if tier.Features().LSMSocketConnect {
		names = append(names, "rana_socket_connect")
	}
	return names
}

// GapReasonDaemonRestart mirrors schema.GapReasonDaemonRestart — re-typed
// here as a schema.GapReason so callers never need to import schema
// separately just to compare a constant (P5: "Ring-buffer drops, governor
// sheds, daemon restarts MUST each produce a first-class gap event").
const GapReasonDaemonRestart = schema.GapReasonDaemonRestart

// GapDescriptor is the portable, pre-schema.Event shape of a gap the
// loader detected. The linux-gated loader (or ranad's main) turns this
// into a schema.Event via schema.NewGap once it has a session/seg/idx to
// stamp it with; this type carries only what the loader itself knows.
type GapDescriptor struct {
	Reason schema.GapReason
	Counts map[string]uint64
	FromNs uint64
	ToNs   uint64
}

// DaemonRestartGap builds the gap{daemon_restart} descriptor CONTRACTS
// requires the loader to emit on every restart ("emit gap{daemon_restart}
// on restart"): fromNs is the last-known-good timestamp before the
// restart (e.g. the last successfully-processed record's ts_mono, or the
// previous ranad process's clean-shutdown timestamp), toNs is the
// timestamp recording resumed. Counts is always non-nil (possibly empty)
// so callers can range over it without a nil check; the linux loader
// fills in per-kind drop counts where it can determine them from the
// ringbuf's own drop counter, leaving it empty when unknown rather than
// guessing (P5: losses are loud, never fabricated).
func DaemonRestartGap(fromNs, toNs uint64) GapDescriptor {
	return GapDescriptor{
		Reason: GapReasonDaemonRestart,
		Counts: map[string]uint64{},
		FromNs: fromNs,
		ToNs:   toNs,
	}
}
