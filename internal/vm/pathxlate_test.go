package vm

import (
	"strings"
	"testing"
)

func TestNewPathXlateRejectsDuplicateTag(t *testing.T) {
	_, err := NewPathXlate([]Mount{
		{Tag: "work", HostRoot: "/Users/alice/proj"},
		{Tag: "work", HostRoot: "/Users/alice/other"},
	})
	if err == nil {
		t.Fatal("expected error for duplicate tag, got nil")
	}
}

func TestNewPathXlateRejectsEmptyTagOrRoot(t *testing.T) {
	cases := []struct {
		name  string
		mount Mount
	}{
		{"empty tag", Mount{Tag: "", HostRoot: "/Users/alice/proj"}},
		{"empty root", Mount{Tag: "work", HostRoot: ""}},
		{"relative root", Mount{Tag: "work", HostRoot: "relative/path"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPathXlate([]Mount{tc.mount})
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestNewPathXlateRejectsTagWithSlash(t *testing.T) {
	_, err := NewPathXlate([]Mount{
		{Tag: "a/b", HostRoot: "/Users/alice/proj"},
	})
	if err == nil {
		t.Fatal("expected error for tag containing '/', got nil")
	}
}

func TestGuestToHost(t *testing.T) {
	px, err := NewPathXlate([]Mount{
		{Tag: "work", HostRoot: "/Users/alice/proj"},
		{Tag: "home", HostRoot: "/Users/alice"},
	})
	if err != nil {
		t.Fatalf("NewPathXlate: %v", err)
	}

	cases := []struct {
		name    string
		guest   string
		want    string
		wantErr bool
	}{
		{"file at root", "/mnt/host/work/main.go", "/Users/alice/proj/main.go", false},
		{"nested", "/mnt/host/work/a/b/c.txt", "/Users/alice/proj/a/b/c.txt", false},
		{"tag root itself, no trailing slash", "/mnt/host/work", "/Users/alice/proj", false},
		{"tag root with trailing slash", "/mnt/host/work/", "/Users/alice/proj", false},
		{"longest prefix wins - home is a prefix substring but distinct tag", "/mnt/host/home/notes.txt", "/Users/alice/notes.txt", false},
		{"unknown tag", "/mnt/host/nope/x", "", true},
		{"not under /mnt/host", "/etc/passwd", "", true},
		{"prefix collision - homework is not home", "/mnt/host/homework/x", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := px.GuestToHost(tc.guest)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("GuestToHost(%q) = %q, nil; want error", tc.guest, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("GuestToHost(%q) unexpected error: %v", tc.guest, err)
			}
			if got != tc.want {
				t.Fatalf("GuestToHost(%q) = %q, want %q", tc.guest, got, tc.want)
			}
		})
	}
}

func TestGuestToHostTraversalSafety(t *testing.T) {
	px, err := NewPathXlate([]Mount{
		{Tag: "work", HostRoot: "/Users/alice/proj"},
	})
	if err != nil {
		t.Fatalf("NewPathXlate: %v", err)
	}

	// A guest path must never translate to a host path outside its tag
	// root, even when it contains ../ segments designed to escape it.
	cases := []string{
		"/mnt/host/work/../../../etc/passwd",
		"/mnt/host/work/../work-evil/x",
		"/mnt/host/work/a/../../b",
		"/mnt/host/work/./../../../root",
	}
	for _, guest := range cases {
		t.Run(guest, func(t *testing.T) {
			got, err := px.GuestToHost(guest)
			if err != nil {
				// Rejecting outright is an acceptable safe outcome.
				return
			}
			if !strings.HasPrefix(got, "/Users/alice/proj") {
				t.Fatalf("GuestToHost(%q) = %q, escaped tag root /Users/alice/proj", guest, got)
			}
		})
	}
}

func TestHostToGuest(t *testing.T) {
	px, err := NewPathXlate([]Mount{
		{Tag: "work", HostRoot: "/Users/alice/proj"},
		{Tag: "home", HostRoot: "/Users/alice"},
	})
	if err != nil {
		t.Fatalf("NewPathXlate: %v", err)
	}

	cases := []struct {
		name    string
		host    string
		want    string
		wantErr bool
	}{
		{"nested under work", "/Users/alice/proj/main.go", "/mnt/host/work/main.go", false},
		{"exact tag root", "/Users/alice/proj", "/mnt/host/work", false},
		// Longest-prefix match: /Users/alice/proj/main.go is under both
		// "home" (/Users/alice) and "work" (/Users/alice/proj); the
		// longer (more specific) root must win.
		{"longest prefix wins over shorter overlapping root", "/Users/alice/proj/deep/file", "/mnt/host/work/deep/file", false},
		{"under home only", "/Users/alice/notes.txt", "/mnt/host/home/notes.txt", false},
		{"outside all roots", "/etc/passwd", "", true},
		{"prefix collision - aliceX is not alice", "/Users/aliceX/notes.txt", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := px.HostToGuest(tc.host)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("HostToGuest(%q) = %q, nil; want error", tc.host, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("HostToGuest(%q) unexpected error: %v", tc.host, err)
			}
			if got != tc.want {
				t.Fatalf("HostToGuest(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

func TestRoundTripGuestHostGuest(t *testing.T) {
	px, err := NewPathXlate([]Mount{
		{Tag: "work", HostRoot: "/Users/alice/proj"},
		{Tag: "home", HostRoot: "/Users/alice"},
		{Tag: "data", HostRoot: "/Volumes/data/set"},
	})
	if err != nil {
		t.Fatalf("NewPathXlate: %v", err)
	}

	guestPaths := []string{
		"/mnt/host/work/main.go",
		"/mnt/host/work",
		"/mnt/host/home/deep/nested/file.txt",
		"/mnt/host/data/x.bin",
	}
	for _, g := range guestPaths {
		t.Run(g, func(t *testing.T) {
			host, err := px.GuestToHost(g)
			if err != nil {
				t.Fatalf("GuestToHost(%q): %v", g, err)
			}
			back, err := px.HostToGuest(host)
			if err != nil {
				t.Fatalf("HostToGuest(%q): %v", host, err)
			}
			// Normalize trailing-slash variants before comparing (e.g.
			// "/mnt/host/work" both ways).
			if back != g && back+"/" != g && back != g+"/" {
				t.Fatalf("round trip mismatch: %q -> %q -> %q", g, host, back)
			}
		})
	}
}

func TestRoundTripHostGuestHost(t *testing.T) {
	px, err := NewPathXlate([]Mount{
		{Tag: "work", HostRoot: "/Users/alice/proj"},
	})
	if err != nil {
		t.Fatalf("NewPathXlate: %v", err)
	}

	hostPaths := []string{
		"/Users/alice/proj",
		"/Users/alice/proj/main.go",
		"/Users/alice/proj/a/b/c",
	}
	for _, h := range hostPaths {
		t.Run(h, func(t *testing.T) {
			guest, err := px.HostToGuest(h)
			if err != nil {
				t.Fatalf("HostToGuest(%q): %v", h, err)
			}
			back, err := px.GuestToHost(guest)
			if err != nil {
				t.Fatalf("GuestToHost(%q): %v", guest, err)
			}
			if back != h {
				t.Fatalf("round trip mismatch: %q -> %q -> %q", h, guest, back)
			}
		})
	}
}

func TestMountsReturnsSortedCopy(t *testing.T) {
	px, err := NewPathXlate([]Mount{
		{Tag: "zzz", HostRoot: "/Users/alice/z"},
		{Tag: "aaa", HostRoot: "/Users/alice/a"},
	})
	if err != nil {
		t.Fatalf("NewPathXlate: %v", err)
	}
	mounts := px.Mounts()
	if len(mounts) != 2 {
		t.Fatalf("got %d mounts, want 2", len(mounts))
	}
	if mounts[0].Tag != "aaa" || mounts[1].Tag != "zzz" {
		t.Fatalf("Mounts() not sorted by tag: %+v", mounts)
	}
	// Mutating the returned slice must not affect internal state.
	mounts[0].Tag = "mutated"
	again := px.Mounts()
	if again[0].Tag != "aaa" {
		t.Fatalf("Mounts() returned a non-copy: mutation leaked, got %q", again[0].Tag)
	}
}
