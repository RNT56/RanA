package profile

import (
	"os"
	"path/filepath"
	"testing"
)

// TestShippedPacks_ParseAndValidate is the CONTRACTS.md-required test that
// all 4 shipped packs parse and pass validation.
func TestShippedPacks_ParseAndValidate(t *testing.T) {
	for _, name := range []string{"generic", "claude-code", "codex", "openclaw"} {
		t.Run(name, func(t *testing.T) {
			p, err := Load(name)
			if err != nil {
				t.Fatalf("Load(%q): %v", name, err)
			}
			if p.Name != name {
				t.Errorf("Name = %q, want %q", p.Name, name)
			}
		})
	}
}

// TestOpenclawAdoptRoundTrips confirms openclaw.toml's [adopt] table decodes
// into Profile.Adopt with the authored values, and that the other three
// shipped packs (which declare no [adopt] table) have a nil Adopt.
func TestOpenclawAdoptRoundTrips(t *testing.T) {
	oc, err := Load("openclaw")
	if err != nil {
		t.Fatalf("Load(openclaw): %v", err)
	}
	if oc.Adopt == nil {
		t.Fatal("openclaw Adopt is nil, want populated [adopt] section")
	}
	want := Adopt{
		ConfigDir:       "~/.openclaw",
		GatewayPort:     18789,
		LinuxSupervisor: "systemd",
		MacOSSupervisor: "launchd",
		ConsentDefault:  "yes",
	}
	if *oc.Adopt != want {
		t.Errorf("openclaw Adopt = %#v, want %#v", *oc.Adopt, want)
	}

	for _, name := range []string{"generic", "claude-code", "codex"} {
		t.Run(name, func(t *testing.T) {
			p, err := Load(name)
			if err != nil {
				t.Fatalf("Load(%q): %v", name, err)
			}
			if p.Adopt != nil {
				t.Errorf("%s Adopt = %#v, want nil (no [adopt] table)", name, *p.Adopt)
			}
		})
	}
}

func TestLoad_UnknownProfile(t *testing.T) {
	_, err := Load("does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "custom.toml")
	src := "[profile]\nname = \"custom\"\ndescription = \"d\"\nversion = 1\n"
	if err := os.WriteFile(fp, []byte(src), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	p, err := LoadFile(fp)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if p.Name != "custom" {
		t.Errorf("Name = %q", p.Name)
	}
}

func TestLoadFile_NotFound(t *testing.T) {
	_, err := LoadFile(filepath.Join(t.TempDir(), "nope.toml"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAvailable_ListsShippedPacks(t *testing.T) {
	names := Available()
	want := map[string]bool{"generic": true, "claude-code": true, "codex": true, "openclaw": true}
	if len(names) != len(want) {
		t.Fatalf("Available() = %#v, want 4 entries", names)
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected profile name %q", n)
		}
	}
}

// TestEmbeddedPacksMatchCanonicalSource guards against the embedded copy
// under internal/profile/embedded/ (required because go:embed cannot embed
// files outside its own package's directory subtree — see this package's
// final report for the CONTRACTS.md conflict this resolves) drifting from
// the canonical profiles/*.toml at the repo root. If this test fails, sync
// internal/profile/embedded/<name>.toml from profiles/<name>.toml.
func TestEmbeddedPacksMatchCanonicalSource(t *testing.T) {
	root := repoRootProfilesDir(t)
	if root == "" {
		t.Skip("repo root profiles/ directory not found relative to test working directory; skipping drift check")
	}
	for _, name := range []string{"generic", "claude-code", "codex", "openclaw"} {
		t.Run(name, func(t *testing.T) {
			canonical, err := os.ReadFile(filepath.Join(root, name+".toml"))
			if err != nil {
				t.Fatalf("reading canonical: %v", err)
			}
			embedded, err := embeddedPacks.ReadFile("embedded/" + name + ".toml")
			if err != nil {
				t.Fatalf("reading embedded: %v", err)
			}
			if string(canonical) != string(embedded) {
				t.Errorf("internal/profile/embedded/%s.toml has drifted from profiles/%s.toml", name, name)
			}
		})
	}
}

// repoRootProfilesDir walks upward from the working directory looking for a
// profiles/ directory that is a sibling of internal/ (i.e. the repo root),
// so the drift-check test works regardless of `go test`'s invocation cwd.
func repoRootProfilesDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for i := 0; i < 10; i++ {
		cand := filepath.Join(dir, "profiles")
		if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
			if _, err := os.Stat(filepath.Join(dir, "internal")); err == nil {
				return cand
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}
