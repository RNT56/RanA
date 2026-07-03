package profile

import "testing"

func TestBuiltinSensitivePaths_ContainsD9Locations(t *testing.T) {
	want := []string{
		"~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", "~/.config/gcloud",
	}
	for _, w := range want {
		if !containsPrefix(BuiltinSensitivePaths(""), w) {
			t.Errorf("BuiltinSensitivePaths missing %q: %#v", w, BuiltinSensitivePaths(""))
		}
	}
}

func TestBuiltinSensitivePaths_IncludesRanaDatadir(t *testing.T) {
	paths := BuiltinSensitivePaths("/home/u/.local/share/rana")
	found := false
	for _, p := range paths {
		if p == "/home/u/.local/share/rana" || p == "/home/u/.local/share/rana/**" {
			found = true
		}
	}
	if !found {
		t.Errorf("BuiltinSensitivePaths(datadir) missing datadir entry: %#v", paths)
	}
}

func TestBuiltinSensitivePaths_EmptyDatadirOmitted(t *testing.T) {
	base := BuiltinSensitivePaths("")
	for _, p := range base {
		if p == "" || p == "**" {
			t.Errorf("empty datadir produced a bogus entry: %#v", base)
		}
	}
}

func containsPrefix(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}
