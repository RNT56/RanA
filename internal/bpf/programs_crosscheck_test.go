package bpf

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// This file cross-checks the SEC()-annotated program symbol names actually
// declared in bpf/src/*.c against loader_tier.go's WantedPrograms/
// baselineProgramNames — a textual, not compiled, cross-check (clang
// cannot run inside `go test` per CONTRACTS), catching the failure mode
// that matters here: a new or renamed BPF program landing in bpf/src
// without a matching update to the portable tier-decision table that
// decides whether the loader ever attaches it.

// secProgramNameRe matches a SEC("...") line followed (possibly on the
// same or next non-blank line) by either a bare `int name(` declaration
// or a `int BPF_PROG(name, ...)` declaration — the two shapes every
// program in bpf/src/*.c uses.
var (
	secLineRe     = regexp.MustCompile(`SEC\("([^"]+)"\)`)
	bpfProgDeclRe = regexp.MustCompile(`(?:int\s+BPF_PROG\(\s*([A-Za-z0-9_]+)|int\s+([A-Za-z0-9_]+)\s*\()`)
)

// discoveredPrograms parses every bpf/src/*.c file and returns the set of
// program symbol names declared via SEC(...) followed by a function
// declaration (skipping SEC("license"), which has no function). The
// license line's own regex match is filtered out since it's followed by a
// variable, not a function, declaration.
func discoveredPrograms(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join("..", "..", "bpf", "src")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading %s: %v", root, err)
	}

	progs := make(map[string]string) // name -> section
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".c" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, e.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		src := string(b)

		secMatches := secLineRe.FindAllStringSubmatchIndex(src, -1)
		for _, m := range secMatches {
			section := src[m[2]:m[3]]
			if section == "license" {
				continue
			}
			// Look at the remainder of the source after this SEC(...)
			// line for the next function declaration.
			rest := src[m[1]:]
			declMatch := bpfProgDeclRe.FindStringSubmatch(rest)
			if declMatch == nil {
				t.Errorf("%s: SEC(%q) has no recognizable following function declaration", e.Name(), section)
				continue
			}
			name := declMatch[1]
			if name == "" {
				name = declMatch[2]
			}
			progs[name] = section
		}
	}
	return progs
}

// TestEveryBPFProgramIsInWantedProgramsSuperset asserts every SEC()
// program symbol discovered in bpf/src/*.c appears somewhere in
// WantedPrograms across the tier range (using TierPreferred, the
// superset tier, as the union) — a program landing in the C source
// without ever being wired into the portable tier table would otherwise
// silently never attach, regardless of kernel.
func TestEveryBPFProgramIsInWantedProgramsSuperset(t *testing.T) {
	discovered := discoveredPrograms(t)
	if len(discovered) == 0 {
		t.Fatal("no SEC() programs discovered in bpf/src/*.c — cross-check has nothing to check")
	}

	superset := make(map[string]bool)
	for _, name := range WantedPrograms(TierPreferred) {
		superset[name] = true
	}

	for name, section := range discovered {
		if !superset[name] {
			t.Errorf("bpf/src program %q (SEC(%q)) is not in WantedPrograms(TierPreferred) — it will never be attached by the loader", name, section)
		}
	}
}

// TestWantedProgramsHasNoPhantomNames is the converse check: every name
// WantedPrograms ever returns (at any tier) must correspond to an actual
// SEC()-declared program in bpf/src/*.c — a typo'd or stale program name
// in the tier table would otherwise silently no-op forever (the linux
// loader would simply never find a matching generated object).
func TestWantedProgramsHasNoPhantomNames(t *testing.T) {
	discovered := discoveredPrograms(t)
	for _, tier := range []Tier{TierBaseline, TierEnhanced, TierPreferred} {
		for _, name := range WantedPrograms(tier) {
			if _, ok := discovered[name]; !ok {
				t.Errorf("WantedPrograms(%v) names %q, which has no matching SEC() program in bpf/src/*.c", tier, name)
			}
		}
	}
}

// TestLSMSocketConnectSectionMatchesIOUringCoverageClaim asserts
// rana_socket_connect really is attached via SEC("lsm/socket_connect")
// (not, say, accidentally left as a cgroup or fentry hook during editing)
// — this is the specific attach mechanism LIMITS.md's io_uring coverage
// claim depends on (LSM hooks fire for io_uring-issued connects; a
// cgroup/connect4·6-shaped attach would not).
func TestLSMSocketConnectSectionMatchesIOUringCoverageClaim(t *testing.T) {
	discovered := discoveredPrograms(t)
	section, ok := discovered["rana_socket_connect"]
	if !ok {
		t.Fatal("rana_socket_connect not found among discovered bpf/src programs")
	}
	if section != "lsm/socket_connect" {
		t.Errorf("rana_socket_connect SEC(%q), want SEC(\"lsm/socket_connect\") — LIMITS.md's io_uring coverage claim depends on this exact attach type", section)
	}
}

// TestHardlinkRepinSectionIsPlainFentry asserts rana_path_link attaches
// via a plain fentry hook (available since the 5.15 floor, per D5) —
// LIMITS.md and loader_tier.go's baselineProgramNames both claim the
// hardlink re-pin needs no tier gate; this pins that claim to the actual
// attach type declared in the C source.
func TestHardlinkRepinSectionIsPlainFentry(t *testing.T) {
	discovered := discoveredPrograms(t)
	section, ok := discovered["rana_path_link"]
	if !ok {
		t.Fatal("rana_path_link not found among discovered bpf/src programs")
	}
	if section != "fentry/security_path_link" {
		t.Errorf("rana_path_link SEC(%q), want SEC(\"fentry/security_path_link\")", section)
	}
}
