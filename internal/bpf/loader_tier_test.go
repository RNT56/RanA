package bpf

import (
	"errors"
	"testing"
)

// TestTierForKernel exercises the tier-decision table (docs/ARCHITECTURE.md
// §7, plan D5): baseline at 5.15, kprobe-multi ("enhanced") at >=5.18, tcx
// ("preferred") at >=6.6, and a hard floor below 5.15.
func TestTierForKernel(t *testing.T) {
	tests := []struct {
		name    string
		major   int
		minor   int
		patch   int
		want    Tier
		wantErr error
	}{
		{"below floor 5.14", 5, 14, 99, TierUnsupported, ErrKernelTooOld},
		{"way below floor", 4, 18, 0, TierUnsupported, ErrKernelTooOld},
		{"exact floor 5.15.0", 5, 15, 0, TierBaseline, nil},
		{"baseline mid-range 5.17", 5, 17, 5, TierBaseline, nil},
		{"exact enhanced floor 5.18.0", 5, 18, 0, TierEnhanced, nil},
		{"enhanced mid-range 6.1", 6, 1, 0, TierEnhanced, nil},
		{"just below preferred 6.5", 6, 5, 99, TierEnhanced, nil},
		{"exact preferred floor 6.6.0", 6, 6, 0, TierPreferred, nil},
		{"well above preferred", 6, 12, 3, TierPreferred, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TierForKernel(tt.major, tt.minor, tt.patch)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("TierForKernel(%d,%d,%d) err = %v, want %v", tt.major, tt.minor, tt.patch, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("TierForKernel(%d,%d,%d) unexpected err: %v", tt.major, tt.minor, tt.patch, err)
			}
			if got != tt.want {
				t.Fatalf("TierForKernel(%d,%d,%d) = %v, want %v", tt.major, tt.minor, tt.patch, got, tt.want)
			}
		})
	}
}

// TestTierString gives every Tier a stable, human-readable name — used by
// `rana doctor` output and log lines.
func TestTierString(t *testing.T) {
	tests := []struct {
		tier Tier
		want string
	}{
		{TierUnsupported, "unsupported"},
		{TierBaseline, "baseline"},
		{TierEnhanced, "enhanced"},
		{TierPreferred, "preferred"},
		{Tier(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.tier.String(); got != tt.want {
			t.Errorf("Tier(%d).String() = %q, want %q", tt.tier, got, tt.want)
		}
	}
}

// TestTierFeatures asserts each tier's feature set matches
// docs/ARCHITECTURE.md §7 exactly: baseline gets the full v1 hook set via
// tracepoints/fentry/cgroup-sock-addr; enhanced adds kprobe-multi; preferred
// adds tcx.
func TestTierFeatures(t *testing.T) {
	base := TierBaseline.Features()
	if !base.Ringbuf || !base.CgroupSockAddr || !base.Fentry || !base.SensitiveReadMap {
		t.Fatalf("baseline tier missing a required-at-baseline feature: %+v", base)
	}
	if base.KprobeMulti || base.Tcx {
		t.Fatalf("baseline tier must not claim enhanced/preferred features: %+v", base)
	}

	enh := TierEnhanced.Features()
	if !enh.KprobeMulti {
		t.Fatalf("enhanced tier must add KprobeMulti: %+v", enh)
	}
	if enh.Tcx {
		t.Fatalf("enhanced tier must not claim Tcx (that's preferred-only): %+v", enh)
	}
	// Enhanced is additive over baseline.
	if !enh.Ringbuf || !enh.CgroupSockAddr || !enh.Fentry || !enh.SensitiveReadMap {
		t.Fatalf("enhanced tier must retain all baseline features: %+v", enh)
	}

	pref := TierPreferred.Features()
	if !pref.Tcx || !pref.KprobeMulti {
		t.Fatalf("preferred tier must add Tcx and retain KprobeMulti: %+v", pref)
	}
	if !pref.Ringbuf || !pref.CgroupSockAddr || !pref.Fentry || !pref.SensitiveReadMap {
		t.Fatalf("preferred tier must retain all baseline features: %+v", pref)
	}

	unsup := TierUnsupported.Features()
	if unsup.Ringbuf || unsup.CgroupSockAddr || unsup.Fentry || unsup.SensitiveReadMap || unsup.KprobeMulti || unsup.Tcx {
		t.Fatalf("unsupported tier must claim zero features: %+v", unsup)
	}
}

// TestParseKernelRelease covers the uname-release parsing that feeds
// TierForKernel from a raw `uname -r`-shaped string (e.g. from
// golang.org/x/sys/unix.Uname on linux, or a doctor-probe string on any
// platform for testability).
func TestParseKernelRelease(t *testing.T) {
	tests := []struct {
		in                  string
		major, minor, patch int
		wantErr             bool
	}{
		{"5.15.0-102-generic", 5, 15, 0, false},
		{"6.6.30-mainline", 6, 6, 30, false},
		{"6.1.0", 6, 1, 0, false},
		{"6.1", 6, 1, 0, false},
		{"5", 0, 0, 0, true},
		{"", 0, 0, 0, true},
		{"not-a-version", 0, 0, 0, true},
		{"5.15.0+", 5, 15, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			major, minor, patch, err := ParseKernelRelease(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseKernelRelease(%q) expected error, got nil", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseKernelRelease(%q) unexpected error: %v", tt.in, err)
			}
			if major != tt.major || minor != tt.minor || patch != tt.patch {
				t.Fatalf("ParseKernelRelease(%q) = (%d,%d,%d), want (%d,%d,%d)",
					tt.in, major, minor, patch, tt.major, tt.minor, tt.patch)
			}
		})
	}
}

// TestPinPath asserts every program's pin path lives under the documented
// /sys/fs/bpf/rana root (CONTRACTS §internal/bpf: "pins under
// /sys/fs/bpf/rana"), is stable across calls (idempotent re-attach depends
// on recomputing the same path), and namespaces distinct programs/maps so
// two different names never collide.
func TestPinPath(t *testing.T) {
	p1 := PinPath("prog", "rana_on_exec")
	p2 := PinPath("prog", "rana_on_exec")
	if p1 != p2 {
		t.Fatalf("PinPath not stable: %q vs %q", p1, p2)
	}
	if got, want := p1, "/sys/fs/bpf/rana/prog/rana_on_exec"; got != want {
		t.Fatalf("PinPath(prog, rana_on_exec) = %q, want %q", got, want)
	}

	pMap := PinPath("map", "rana_sessions")
	if pMap == p1 {
		t.Fatalf("PinPath must namespace by kind: prog and map collided at %q", pMap)
	}
	if got, want := pMap, "/sys/fs/bpf/rana/map/rana_sessions"; got != want {
		t.Fatalf("PinPath(map, rana_sessions) = %q, want %q", got, want)
	}
}

// TestPinPathRejectsUnsafeNames guards against path traversal or separator
// injection via a malformed program/map name reaching PinPath — pin paths
// are filesystem paths under a root ranad (root) controls, so a name like
// "../../etc" must never escape the /sys/fs/bpf/rana root.
func TestPinPathRejectsUnsafeNames(t *testing.T) {
	tests := []string{"../escape", "a/b", "", "with space", "with\x00nul"}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := SafePinPath("prog", name)
			if err == nil {
				t.Fatalf("SafePinPath(prog, %q) expected error, got nil", name)
			}
		})
	}
	p, err := SafePinPath("prog", "rana_on_exec")
	if err != nil {
		t.Fatalf("SafePinPath(prog, rana_on_exec) unexpected error: %v", err)
	}
	if p != "/sys/fs/bpf/rana/prog/rana_on_exec" {
		t.Fatalf("SafePinPath = %q, want /sys/fs/bpf/rana/prog/rana_on_exec", p)
	}
}

// TestReattachPlan verifies the idempotent re-attach decision: given a set
// of already-pinned program names and the set this loader run wants
// attached, ReattachPlan reports which need loading, which are already
// present (skip), and which are stale (pinned but no longer wanted) so the
// linux-gated loader can clean them up. Restarting ranad with the same
// program set must be a no-op plan (all skip).
func TestReattachPlan(t *testing.T) {
	pinned := []string{"rana_on_exec", "rana_on_fork", "stale_prog"}
	wanted := []string{"rana_on_exec", "rana_on_fork", "rana_on_exit"}

	plan := ReattachPlan(pinned, wanted)

	assertSet(t, "ToLoad", plan.ToLoad, []string{"rana_on_exit"})
	assertSet(t, "Skip", plan.Skip, []string{"rana_on_exec", "rana_on_fork"})
	assertSet(t, "Stale", plan.Stale, []string{"stale_prog"})
}

func TestReattachPlanNoOpOnIdenticalRestart(t *testing.T) {
	names := []string{"rana_on_exec", "rana_on_fork", "rana_on_exit"}
	plan := ReattachPlan(names, names)
	if len(plan.ToLoad) != 0 {
		t.Fatalf("identical restart should need no loads, got %v", plan.ToLoad)
	}
	if len(plan.Stale) != 0 {
		t.Fatalf("identical restart should have no stale pins, got %v", plan.Stale)
	}
	assertSet(t, "Skip", plan.Skip, names)
}

func TestReattachPlanFreshStart(t *testing.T) {
	wanted := []string{"rana_on_exec", "rana_on_fork"}
	plan := ReattachPlan(nil, wanted)
	assertSet(t, "ToLoad", plan.ToLoad, wanted)
	if len(plan.Skip) != 0 {
		t.Fatalf("fresh start should skip nothing, got %v", plan.Skip)
	}
	if len(plan.Stale) != 0 {
		t.Fatalf("fresh start should have no stale pins, got %v", plan.Stale)
	}
}

func assertSet(t *testing.T, label string, got, want []string) {
	t.Helper()
	gm := map[string]bool{}
	for _, g := range got {
		gm[g] = true
	}
	wm := map[string]bool{}
	for _, w := range want {
		wm[w] = true
	}
	if len(gm) != len(wm) {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
	for k := range wm {
		if !gm[k] {
			t.Fatalf("%s = %v, want %v (missing %q)", label, got, want, k)
		}
	}
}

// TestDaemonRestartGap ensures a restarting loader can compute a
// gap{daemon_restart} descriptor with a well-formed reason and non-nil
// counts map, matching the schema.EventTypeGap contract's frozen reason
// set {ringbuf_full, governor, daemon_restart} (CONTRACTS §internal/schema).
func TestDaemonRestartGap(t *testing.T) {
	g := DaemonRestartGap(1234, 5678)
	if g.Reason != GapReasonDaemonRestart {
		t.Fatalf("Reason = %q, want %q", g.Reason, GapReasonDaemonRestart)
	}
	if g.FromNs != 1234 || g.ToNs != 5678 {
		t.Fatalf("FromNs/ToNs = %d/%d, want 1234/5678", g.FromNs, g.ToNs)
	}
	if g.Counts == nil {
		t.Fatalf("Counts must be non-nil (even if empty) so callers can range over it safely")
	}
}
