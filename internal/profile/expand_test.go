package profile

import "testing"

func TestExpandSessionCWD(t *testing.T) {
	cases := []struct {
		pattern string
		cwd     string
		want    string
	}{
		{"$SESSION_CWD/**", "/home/u/proj", "/home/u/proj/**"},
		{"$SESSION_CWD", "/home/u/proj", "/home/u/proj"},
		{"~/.ssh/**", "/home/u/proj", "~/.ssh/**"}, // no placeholder: unchanged
		{"$SESSION_CWD/**/$SESSION_CWD", "/x", "/x/**//x"},
	}
	for _, tc := range cases {
		if got := ExpandSessionCWD(tc.pattern, tc.cwd); got != tc.want {
			t.Errorf("ExpandSessionCWD(%q, %q) = %q, want %q", tc.pattern, tc.cwd, got, tc.want)
		}
	}
}

func TestExpandSessionCWDAll(t *testing.T) {
	in := []string{"$SESSION_CWD/**", "~/.ssh/**"}
	got := ExpandSessionCWDAll(in, "/home/u")
	want := []string{"/home/u/**", "~/.ssh/**"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
