package session

// SliceName returns RanA's fixed top-level systemd slice name, under which
// every session scope lives: rana.slice/rana-<id>.scope
// (docs/ARCHITECTURE.md §1).
func SliceName() string { return "rana.slice" }

// ScopeName returns the bare scope name for a session id, without a
// trailing ".scope" suffix: "rana-<sessionID>". This is the Scope.Name
// value passed to Driver.CreateScope.
func ScopeName(sessionID string) string { return "rana-" + sessionID }

// ScopeUnitName returns the full systemd unit name for a session's scope:
// "rana-<sessionID>.scope".
func ScopeUnitName(sessionID string) string { return ScopeName(sessionID) + ".scope" }
