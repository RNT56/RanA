package profile

import (
	"strings"
	"testing"
	"time"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		// literal
		{"/a/b/c", "/a/b/c", true},
		{"/a/b/c", "/a/b/d", false},

		// single-segment *
		{"/a/*/c", "/a/b/c", true},
		{"/a/*/c", "/a/b/x/c", false},
		{"/a/*.txt", "/a/foo.txt", true},
		{"/a/*.txt", "/a/foo.md", false},
		{"/a/*.txt", "/a/b/foo.txt", false}, // * does not cross /

		// ** matches zero or more path segments
		{"/a/**", "/a", true},
		{"/a/**", "/a/b", true},
		{"/a/**", "/a/b/c", true},
		{"/a/**/z", "/a/z", true},
		{"/a/**/z", "/a/b/z", true},
		{"/a/**/z", "/a/b/c/z", true},
		{"/a/**/z", "/a/b/c/y", false},
		{"**/node_modules/**", "/repo/x/node_modules/y/z", true},
		{"**/node_modules/**", "/repo/node_modules", true},
		{"**/node_modules/**", "/repo/other", false},

		// ? single char
		{"/a/?.txt", "/a/x.txt", true},
		{"/a/?.txt", "/a/xy.txt", false},

		// $SESSION_CWD placeholder must be expanded by caller, not the
		// matcher itself; matcher treats it as a literal segment.
		{"$SESSION_CWD/**", "$SESSION_CWD/foo", true},
	}
	for _, tc := range cases {
		g, err := compileGlob(tc.pattern)
		if err != nil {
			t.Fatalf("compileGlob(%q): %v", tc.pattern, err)
		}
		if got := g.Match(tc.path); got != tc.want {
			t.Errorf("Match(%q) against pattern %q = %v, want %v", tc.path, tc.pattern, got, tc.want)
		}
	}
}

func TestGlobCompile_Invalid(t *testing.T) {
	cases := []string{
		"[unclosed",
		"/a/[z-",
	}
	for _, pat := range cases {
		if _, err := compileGlob(pat); err == nil {
			t.Errorf("compileGlob(%q): expected error", pat)
		}
	}
}

func TestGlobMatch_CharClass(t *testing.T) {
	g, err := compileGlob("/a/[bc].txt")
	if err != nil {
		t.Fatalf("compileGlob: %v", err)
	}
	if !g.Match("/a/b.txt") {
		t.Error("expected match b.txt")
	}
	if !g.Match("/a/c.txt") {
		t.Error("expected match c.txt")
	}
	if g.Match("/a/d.txt") {
		t.Error("expected no match d.txt")
	}
}

// TestGlobMatch_ManyStarStarSegmentsNoExponentialBlowup guards against
// unmemoized `**` backtracking, which is exponential in the number of `**`
// segments for a non-matching path of comparable depth (confirmed pre-fix:
// 20 chained "a/**/" segments took >3s; unmemoized cost roughly quadruples
// per added segment). These globs come from profile TOML
// ([digest].scopes/exclude, [sensitive_read].extra) and are evaluated
// against every fs event path at runtime, so unbounded cost here is a real
// algorithmic-complexity DoS risk against the digest worker / collector
// (in tension with P2, "observation is inert" — a hang is not inert).
func TestGlobMatch_ManyStarStarSegmentsNoExponentialBlowup(t *testing.T) {
	pattern := strings.Repeat("a/**/", 200) + "NEVERMATCH"
	g, err := compileGlob(pattern)
	if err != nil {
		t.Fatalf("compileGlob: %v", err)
	}
	target := strings.Repeat("a/x/", 200) + "b"

	done := make(chan bool, 1)
	go func() {
		done <- g.Match(target)
	}()
	select {
	case got := <-done:
		if got {
			t.Errorf("Match unexpectedly true for a deliberately non-matching target")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Match took >2s on 200 chained ** segments — exponential backtracking regression")
	}
}
