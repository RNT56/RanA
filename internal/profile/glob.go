package profile

import (
	"fmt"
	"path"
	"strings"
)

// Glob is a compiled path-glob pattern supporting the syntax
// docs/PROFILES.md's [digest]/[sensitive_read] sections use: literal path
// segments, single-segment path.Match wildcards (`*`, `?`, `[...]`), and
// `**` matching zero or more whole path segments (does cross `/`, unlike
// `*`).
//
// No new dependency is used: per-segment matching is path.Match-based
// (stdlib), and `**` is handled by this package's own segment-recursive
// matcher, per CONTRACTS.md's "use path.Match-based segments or write a
// simple ** globber — no new deps" instruction.
type Glob struct {
	pattern  string
	segments []string
}

// compileGlob parses pattern into a Glob, validating that every non-`**`
// segment is a syntactically valid path.Match pattern (rejects e.g. an
// unclosed `[` character class).
func compileGlob(pattern string) (*Glob, error) {
	segs := splitPath(pattern)
	for _, s := range segs {
		if s == "**" {
			continue
		}
		if _, err := path.Match(s, ""); err != nil {
			return nil, fmt.Errorf("segment %q: %w", s, err)
		}
	}
	return &Glob{pattern: pattern, segments: segs}, nil
}

// splitPath splits a glob pattern (or a concrete path) into its `/`-
// delimited segments, dropping empty segments produced by a leading `/` or
// repeated `/`s so absolute and relative patterns compare uniformly.
func splitPath(p string) []string {
	raw := strings.Split(p, "/")
	out := raw[:0:0]
	for _, s := range raw {
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Match reports whether path matches the compiled glob.
//
// Matching is memoized on (pattern-index, path-index) pairs (see
// matchSegmentsMemo). A naive recursive backtracker here is exponential in
// the number of `**` segments — a pattern with N `**` segments matched
// against a non-matching path of comparable depth costs O(2^N) without
// memoization, which is a real algorithmic-complexity DoS: these globs come
// from profile TOML ([digest].scopes/exclude, [sensitive_read].extra) and
// are evaluated against every fs event path at runtime by the digest worker
// and sensitive-read extension logic, so an adversarial or merely
// careless profile (many chained `**/` segments) could hang that code path
// (in tension with P2 — observation must stay inert). Memoized, this is
// O(len(pattern) * len(path)).
func (g *Glob) Match(target string) bool {
	pathSegs := splitPath(target)
	memo := make(map[[2]int]bool, len(g.segments)*len(pathSegs))
	return matchSegmentsMemo(g.segments, pathSegs, 0, 0, memo)
}

// matchSegmentsMemo matches g.segments[pi:] against path[si:], memoizing on
// (pi, si) so repeated sub-problems created by `**`'s backtracking loop are
// solved once. `**` matches zero-or-more whole path segments (tried
// greedily: try consuming 0 segments first, then more, so the common
// `prefix/**/suffix` shape matches the shortest span — memoization does not
// change which match is found, only how many times each sub-problem is
// evaluated).
func matchSegmentsMemo(pat, path []string, pi, si int, memo map[[2]int]bool) bool {
	key := [2]int{pi, si}
	if v, ok := memo[key]; ok {
		return v
	}

	var result bool
	switch {
	case pi == len(pat):
		result = si == len(path)
	case pat[pi] == "**":
		if pi == len(pat)-1 {
			result = true // ** at the end matches everything remaining, including nothing
		} else {
			for i := si; i <= len(path); i++ {
				if matchSegmentsMemo(pat, path, pi+1, i, memo) {
					result = true
					break
				}
			}
		}
	case si == len(path):
		result = false
	default:
		ok, err := path_Match(pat[pi], path[si])
		result = err == nil && ok && matchSegmentsMemo(pat, path, pi+1, si+1, memo)
	}

	memo[key] = result
	return result
}

// path_Match wraps path.Match; segment patterns were already validated at
// compile time, so an error here should not occur in practice, but Match
// still treats it as "no match" defensively rather than panicking.
func path_Match(pattern, name string) (bool, error) {
	return path.Match(pattern, name)
}
