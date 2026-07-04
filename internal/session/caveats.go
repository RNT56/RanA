package session

// AdoptMode identifies how a session came to include its members: freshly
// spawned by `rana run`, an existing systemd unit slotted into the slice by
// `rana adopt`, or a live process tree migrated by `rana adopt --pid N`.
// Each non-trivial mode carries honest caveats about what the record does
// and does not cover (P4, P10, the session/adopt lifecycle).
type AdoptMode string

// AdoptMode values.
const (
	// AdoptModeRun is `rana run`: the child is exec'd inside the scope
	// from birth. No pre-existing state predates the record.
	AdoptModeRun AdoptMode = "run"

	// AdoptModeUnit is `rana adopt <unit>`: an existing systemd unit is
	// slotted into rana.slice via a drop-in and restarted (adopt).
	AdoptModeUnit AdoptMode = "unit"

	// AdoptModePID is `rana adopt --pid N`: a live, already-running
	// process tree is migrated into the scope in place, without a
	// restart (the session/adopt lifecycle).
	AdoptModePID AdoptMode = "pid"
)

// AdoptCaveats returns the honest, user-facing caveat strings for the given
// adoption mode (P4 "claim exactly what the chain delivers", P10
// "documented honesty is a feature"). These strings are written verbatim
// into session.start's adopt_caveats field (schema.NewSessionStart) so the
// record itself states its own scope, not just the docs.
//
// An unrecognized mode returns nil rather than erroring — callers that
// construct AdoptMode from a fixed set of constants cannot hit this case;
// it exists so a caller cannot accidentally fabricate a caveat for a mode
// this package does not know about.
func AdoptCaveats(mode AdoptMode) []string {
	switch mode {
	case AdoptModeRun:
		return nil
	case AdoptModeUnit:
		return []string{
			"session membership begins at unit restart: activity before the restart that placed this unit under rana.slice is not recorded.",
		}
	case AdoptModePID:
		return []string{
			"threads of the adopted process tree migrate into the session cgroup, but per-thread history before migration is not recorded.",
			"file descriptors already open at adoption time predate the record: reads/writes through them will not show a corresponding open event.",
			"any process activity before this adoption is not recorded; only effects from the point of adoption forward appear in the ledger.",
		}
	default:
		return nil
	}
}
