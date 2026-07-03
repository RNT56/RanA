package session

import "testing"

func TestScopeName(t *testing.T) {
	got := ScopeName("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	want := "rana-01ARZ3NDEKTSV4RRFFQ69G5FAV"
	if got != want {
		t.Errorf("ScopeName = %q, want %q", got, want)
	}
}

func TestSliceName(t *testing.T) {
	if got, want := SliceName(), "rana.slice"; got != want {
		t.Errorf("SliceName() = %q, want %q", got, want)
	}
}

func TestScopeUnitName(t *testing.T) {
	got := ScopeUnitName("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	want := "rana-01ARZ3NDEKTSV4RRFFQ69G5FAV.scope"
	if got != want {
		t.Errorf("ScopeUnitName = %q, want %q", got, want)
	}
}
