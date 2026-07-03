package profile

import (
	"path/filepath"
	"strings"
)

// Match auto-selects a profile from candidates for a process identified by
// its executable path and argv (docs/PROFILES.md [match]: "Matching is a
// convenience, not attribution — attribution is always the cgroup").
//
// A candidate profile matches when Match.Auto is true AND at least one of
// its declared rule lists is satisfied: exe_basename (the executable's base
// name is a member) OR argv_contains (some argv element contains one of the
// listed substrings). The two lists are independent alternatives, not a
// conjunction — e.g. claude-code.toml declares both exe_basename=["claude"]
// and argv_contains=["claude-code"] and matches on either alone. A profile
// that wants a narrower, conjunctive rule (e.g. "only the gateway
// sub-invocation of this binary") expresses that via its own [adopt]-driven
// liveness probe, not via [match] — [match] stays a coarse, convenience-only
// heuristic per docs/PROFILES.md. A profile with auto=true but both rule
// lists empty never auto-matches — there is nothing to match on.
//
// Precedence when multiple candidates match: a candidate matched by
// exe_basename ranks above one matched purely by argv_contains, since the
// executable identity is the stronger signal; ties within the same
// precedence tier are broken by candidate order (first match wins), making
// Match deterministic for a fixed input slice. Returns nil when no
// candidate matches.
func Match(candidates []*Profile, exePath string, argv []string) *Profile {
	base := filepath.Base(exePath)

	var best *Profile
	bestRank := -1
	for _, p := range candidates {
		if p == nil || !p.Match.Auto {
			continue
		}
		rank, ok := matchRank(p, base, argv)
		if !ok {
			continue
		}
		if rank > bestRank {
			best = p
			bestRank = rank
		}
	}
	return best
}

// matchRank reports whether p matches (base, argv) and, if so, a precedence
// rank: 2 when exe_basename matched, 1 when only argv_contains matched. The
// two rule lists are independent alternatives (OR), not a conjunction — see
// the Match doc comment.
func matchRank(p *Profile, base string, argv []string) (int, bool) {
	if len(p.Match.ExeBasename) > 0 && containsString(p.Match.ExeBasename, base) {
		return 2, true
	}
	if len(p.Match.ArgvContains) > 0 && argvContainsAny(argv, p.Match.ArgvContains) {
		return 1, true
	}
	return 0, false
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func argvContainsAny(argv []string, substrs []string) bool {
	for _, a := range argv {
		for _, s := range substrs {
			if strings.Contains(a, s) {
				return true
			}
		}
	}
	return false
}
