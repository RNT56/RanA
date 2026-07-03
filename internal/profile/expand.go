package profile

import "strings"

// sessionCWDPlaceholder is the literal token profile authors write in
// [digest].scopes/[digest].exclude to mean "the directory the session
// started in" (docs/PROFILES.md [digest]). It is expanded at session-start
// time (ExpandSessionCWD), never at parse time, since the working directory
// is not known until then.
const sessionCWDPlaceholder = "$SESSION_CWD"

// ExpandSessionCWD replaces every occurrence of $SESSION_CWD in pattern
// with cwd. Patterns without the placeholder are returned unchanged.
func ExpandSessionCWD(pattern, cwd string) string {
	return strings.ReplaceAll(pattern, sessionCWDPlaceholder, cwd)
}

// ExpandSessionCWDAll applies ExpandSessionCWD to every element of
// patterns, returning a new slice (patterns is not mutated).
func ExpandSessionCWDAll(patterns []string, cwd string) []string {
	out := make([]string, len(patterns))
	for i, p := range patterns {
		out[i] = ExpandSessionCWD(p, cwd)
	}
	return out
}
