package session

import (
	"strings"
	"testing"
)

// TestDropIn_GoldenOpenClaw pins the exact drop-in content for the hero
// adopt case (docs/ARCHITECTURE.md §3, RANA-plan-v1.md §4.2, plan §6.3):
// adopting the OpenClaw gateway unit under the fixed rana.slice. Any change
// to this output is a deliberate, reviewed format change — that is the
// point of a golden test.
func TestDropIn_GoldenOpenClaw(t *testing.T) {
	path, content := DropIn("openclaw-gateway.service", "rana-01ARZ3NDEKTSV4RRFFQ69G5FAV")

	wantPath := "/etc/systemd/system/openclaw-gateway.service.d/50-rana.conf"
	if path != wantPath {
		t.Fatalf("DropIn path = %q, want %q", path, wantPath)
	}

	want := "" +
		"# Managed by RanA (rana adopt). Do not edit by hand — re-running\n" +
		"# `rana adopt` will overwrite this file. Remove it and reload systemd\n" +
		"# (systemctl daemon-reload) to fully undo adoption.\n" +
		"[Service]\n" +
		"Slice=rana.slice\n"

	if content != want {
		t.Fatalf("DropIn content mismatch\n--- got ---\n%s\n--- want ---\n%s", content, want)
	}
}

func TestDropIn_PathIsUnitDirDotConf(t *testing.T) {
	tests := []struct {
		unit string
		want string
	}{
		{"foo.service", "/etc/systemd/system/foo.service.d/50-rana.conf"},
		{"bar.socket", "/etc/systemd/system/bar.socket.d/50-rana.conf"},
	}
	for _, tt := range tests {
		path, _ := DropIn(tt.unit, "rana-abc")
		if path != tt.want {
			t.Errorf("DropIn(%q) path = %q, want %q", tt.unit, path, tt.want)
		}
	}
}

func TestDropIn_ContentReferencesFixedSlice(t *testing.T) {
	// A systemd Slice= property must reference a .slice unit, never a
	// .scope unit (docs/ARCHITECTURE.md §3, RANA-plan-v1.md §4.2): the
	// emitted drop-in always targets the fixed rana.slice regardless of
	// the scope argument.
	_, content := DropIn("gateway.service", "rana-XYZ")
	if !strings.Contains(content, "Slice=rana.slice\n") {
		t.Fatalf("DropIn content does not set Slice=rana.slice:\n%s", content)
	}
	if !strings.Contains(content, "[Service]") {
		t.Fatalf("DropIn content missing [Service] section:\n%s", content)
	}
}

func TestDropIn_ScopeArgumentDoesNotAffectSlice(t *testing.T) {
	// Regardless of what is passed as scope (bare name, with or without a
	// trailing ".scope"), DropIn must always emit the fixed rana.slice —
	// there is no per-adoption *.scope unit to nest under (see doc
	// comment on DropIn).
	for _, scope := range []string{"rana-XYZ", "rana-XYZ.scope", "", "anything"} {
		_, content := DropIn("gateway.service", scope)
		if !strings.Contains(content, "Slice=rana.slice\n") {
			t.Fatalf("DropIn(scope=%q) content does not set Slice=rana.slice:\n%s", scope, content)
		}
	}
}

func TestDropIn_DeterministicForSameInputs(t *testing.T) {
	p1, c1 := DropIn("openclaw-gateway.service", "rana-01ARZ3NDEKTSV4RRFFQ69G5FAV")
	p2, c2 := DropIn("openclaw-gateway.service", "rana-01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if p1 != p2 || c1 != c2 {
		t.Fatalf("DropIn is not deterministic for identical inputs")
	}
}

// TestDropIn_SliceValueIsNotAScopeUnit guards against regressing to the
// bug this test suite once golden-pinned: emitting Slice=<name>.scope.
// systemd rejects (or at minimum never applies as intended) a Slice=
// property that names a .scope unit — Slice= must name a .slice unit.
// This is a correctness invariant, not just a formatting preference: a
// wrong value here means `rana adopt` silently fails to place the unit
// where docs/ARCHITECTURE.md §3 promises ("placing its unit under
// `rana.slice`"), which breaks attribution (D6) for every adopted daemon.
func TestDropIn_SliceValueIsNotAScopeUnit(t *testing.T) {
	for _, scope := range []string{"rana-abc", "rana-abc.scope", "rana-01ARZ3NDEKTSV4RRFFQ69G5FAV"} {
		_, content := DropIn("gateway.service", scope)
		if strings.Contains(content, ".scope\n") {
			t.Fatalf("DropIn(scope=%q) emitted a Slice= value ending in .scope (invalid systemd config — Slice= must name a .slice unit):\n%s", scope, content)
		}
	}
}

// TestDropIn_Reversible documents and asserts the reversal contract stated
// in DropIn's own generated comment: the drop-in is a single additive file
// under unit.d/; removing it and reloading systemd fully undoes adoption
// with no other on-disk state touched (DropIn itself performs no I/O, so
// this test asserts the *content* promises reversibility rather than
// exercising real systemctl calls, which are out of scope for a unit
// test — see the "Remove it ... to fully undo adoption" line).
func TestDropIn_Reversible(t *testing.T) {
	_, content := DropIn("openclaw-gateway.service", "rana-01ARZ3NDEKTSV4RRFFQ69G5FAV")

	if !strings.Contains(content, "to fully undo adoption") {
		t.Fatalf("DropIn content does not document the reversal procedure:\n%s", content)
	}
	// The file must contain exactly one override key (Slice=) inside a
	// single [Service] section — anything more starts to look like a
	// non-reversible mutation of unrelated unit behavior.
	if strings.Count(content, "[Service]") != 1 {
		t.Fatalf("DropIn content must have exactly one [Service] section for a clean, single-property reversal:\n%s", content)
	}
	if strings.Count(content, "Slice=") != 1 {
		t.Fatalf("DropIn content must set exactly one Slice= override:\n%s", content)
	}
}
