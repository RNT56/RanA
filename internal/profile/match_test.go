package profile

import "testing"

func loadAll(t *testing.T) []*Profile {
	t.Helper()
	var out []*Profile
	for _, n := range []string{"generic", "claude-code", "codex", "openclaw"} {
		p, err := Load(n)
		if err != nil {
			t.Fatalf("Load(%q): %v", n, err)
		}
		out = append(out, p)
	}
	return out
}

func TestMatch_ExeBasename(t *testing.T) {
	packs := loadAll(t)
	got := Match(packs, "/usr/local/bin/codex", nil)
	if got == nil || got.Name != "codex" {
		t.Fatalf("Match = %v, want codex", got)
	}
}

func TestMatch_ExeBasenameClaudeCode(t *testing.T) {
	packs := loadAll(t)
	got := Match(packs, "/usr/bin/claude", []string{"claude", "--dangerously-skip-permissions"})
	if got == nil || got.Name != "claude-code" {
		t.Fatalf("Match = %v, want claude-code", got)
	}
}

func TestMatch_ArgvContains(t *testing.T) {
	packs := loadAll(t)
	// claude-code also matches on argv_contains "claude-code" per the shipped pack.
	got := Match(packs, "/usr/bin/node", []string{"node", "claude-code", "run"})
	if got == nil || got.Name != "claude-code" {
		t.Fatalf("Match = %v, want claude-code", got)
	}
}

func TestMatch_OpenClawByExeBasename(t *testing.T) {
	// [match] rule lists are independent alternatives (OR), not a
	// conjunction: exe_basename=["openclaw"] alone is sufficient for the
	// coarse rana-run auto-select heuristic. Narrowing to specifically the
	// gateway sub-invocation is `rana adopt openclaw`'s job ([adopt]
	// section), not [match]'s.
	packs := loadAll(t)
	got := Match(packs, "/usr/bin/openclaw", []string{"openclaw", "gateway"})
	if got == nil || got.Name != "openclaw" {
		t.Fatalf("Match = %v, want openclaw", got)
	}
}

func TestMatch_OpenClawByExeBasenameEvenWithoutGatewayArg(t *testing.T) {
	packs := loadAll(t)
	got := Match(packs, "/usr/bin/openclaw", []string{"openclaw", "status"})
	if got == nil || got.Name != "openclaw" {
		t.Fatalf("Match = %v, want openclaw (exe_basename alone is sufficient)", got)
	}
}

func TestMatch_NoMatchReturnsNil(t *testing.T) {
	packs := loadAll(t)
	got := Match(packs, "/usr/bin/bash", []string{"bash", "-c", "echo hi"})
	if got != nil {
		t.Fatalf("Match = %v, want nil", got)
	}
}

func TestMatch_GenericNeverAutoMatches(t *testing.T) {
	// generic has auto=false; it must never be returned by Match even if
	// somehow its rules would otherwise line up (it has none, but this
	// documents the invariant explicitly).
	packs := loadAll(t)
	for _, p := range packs {
		if p.Name == "generic" && p.Match.Auto {
			t.Fatalf("generic profile must have auto=false")
		}
	}
}

func TestMatch_PrecedenceExeBasenameOverArgv(t *testing.T) {
	// Construct two synthetic profiles where one would match by exe_basename
	// and another only by argv_contains; exe_basename match should win when
	// both could apply, and Match must be deterministic regardless of input
	// slice order.
	a, err := Parse(mustHeaderNamed("a")+"\n[match]\nauto = true\nexe_basename = [\"myagent\"]\n", "a")
	if err != nil {
		t.Fatalf("Parse a: %v", err)
	}
	b, err := Parse(mustHeaderNamed("b")+"\n[match]\nauto = true\nargv_contains = [\"myagent\"]\n", "b")
	if err != nil {
		t.Fatalf("Parse b: %v", err)
	}
	got := Match([]*Profile{b, a}, "/usr/bin/myagent", []string{"myagent"})
	if got == nil || got.Name != "a" {
		t.Fatalf("Match = %v, want a (exe_basename precedence)", got)
	}
}

func TestMatch_NonAutoProfileNeverMatches(t *testing.T) {
	a, err := Parse(mustHeaderNamed("a")+"\n[match]\nauto = false\nexe_basename = [\"myagent\"]\n", "a")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := Match([]*Profile{a}, "/usr/bin/myagent", []string{"myagent"})
	if got != nil {
		t.Fatalf("Match = %v, want nil (auto=false)", got)
	}
}

func mustHeaderNamed(name string) string {
	return "[profile]\nname = \"" + name + "\"\ndescription = \"d\"\nversion = 1\n"
}

// TestMatch_NilCandidateDoesNotPanic guards against a nil *Profile entering
// the candidates slice (e.g. a caller appending the result of a failed,
// unchecked Load/LoadFile). Match must skip it, not dereference it.
func TestMatch_NilCandidateDoesNotPanic(t *testing.T) {
	packs := loadAll(t)
	candidates := append([]*Profile{nil}, packs...)
	got := Match(candidates, "/usr/bin/codex", []string{"codex"})
	if got == nil || got.Name != "codex" {
		t.Fatalf("Match with a leading nil candidate = %v, want codex", got)
	}

	// All-nil slice must return nil, not panic.
	if got := Match([]*Profile{nil, nil}, "/usr/bin/anything", nil); got != nil {
		t.Fatalf("Match(all-nil) = %v, want nil", got)
	}
}
