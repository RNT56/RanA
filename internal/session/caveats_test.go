package session

import (
	"strings"
	"testing"
)

func TestAdoptCaveats_UnitAdoption(t *testing.T) {
	caveats := AdoptCaveats(AdoptModeUnit)
	if len(caveats) == 0 {
		t.Fatal("AdoptCaveats(AdoptModeUnit): expected at least one caveat")
	}
	joined := strings.Join(caveats, " | ")
	// The session/adopt lifecycle documents this exact caveat for unit
	// adoption: membership begins at restart, so pre-restart history is
	// not covered.
	if !strings.Contains(strings.ToLower(joined), "restart") {
		t.Errorf("AdoptCaveats(AdoptModeUnit) = %v, want a caveat mentioning restart", caveats)
	}
}

func TestAdoptCaveats_PidAdoption(t *testing.T) {
	caveats := AdoptCaveats(AdoptModePID)
	if len(caveats) == 0 {
		t.Fatal("AdoptCaveats(AdoptModePID): expected at least one caveat")
	}
	joined := strings.ToLower(strings.Join(caveats, " | "))
	// The session/adopt lifecycle: "threads migrate; already-open fds
	// predate the record".
	if !strings.Contains(joined, "thread") {
		t.Errorf("AdoptCaveats(AdoptModePID) = %v, want a caveat mentioning threads", caveats)
	}
	if !strings.Contains(joined, "fd") && !strings.Contains(joined, "file descriptor") {
		t.Errorf("AdoptCaveats(AdoptModePID) = %v, want a caveat mentioning open file descriptors", caveats)
	}
	if !strings.Contains(joined, "predate") && !strings.Contains(joined, "before") {
		t.Errorf("AdoptCaveats(AdoptModePID) = %v, want a caveat noting pre-adoption activity is not recorded", caveats)
	}
}

func TestAdoptCaveats_UnknownModeReturnsEmpty(t *testing.T) {
	caveats := AdoptCaveats(AdoptMode("bogus"))
	if len(caveats) != 0 {
		t.Errorf("AdoptCaveats(unknown mode) = %v, want empty", caveats)
	}
}

func TestAdoptCaveats_Deterministic(t *testing.T) {
	a := AdoptCaveats(AdoptModePID)
	b := AdoptCaveats(AdoptModePID)
	if len(a) != len(b) {
		t.Fatalf("AdoptCaveats not deterministic: %v vs %v", a, b)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("AdoptCaveats not deterministic at index %d: %q vs %q", i, a[i], b[i])
		}
	}
}

func TestAdoptCaveats_RunModeHasNoCaveats(t *testing.T) {
	// `rana run` starts the process inside the scope from birth — there is
	// nothing to caveat (no pre-existing state predates the record).
	caveats := AdoptCaveats(AdoptModeRun)
	if len(caveats) != 0 {
		t.Errorf("AdoptCaveats(AdoptModeRun) = %v, want empty (run starts clean)", caveats)
	}
}
