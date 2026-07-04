package session

import "strings"

// DropIn generates the systemd drop-in path and content that places an
// existing unit under RanA's fixed top-level slice, rana.slice
// (docs/ARCHITECTURE.md §3: "generate a systemd drop-in placing its unit
// under `rana.slice`").
//
// The emitted `Slice=` value is always the fixed slice name (SliceName(),
// "rana.slice") — a systemd Slice= property must reference a .slice unit,
// never a .scope unit, so the adopted unit cannot be nested inside a
// per-session *.scope the way `rana run`-created processes are (those get
// their own cgroup leaf via Driver.CreateScope, a different mechanism).
// Adoption groups the unit at the slice level; per-session attribution for
// adopted units comes from the session id recorded in session.start
// (adopt caveats), not from a distinct per-unit scope path.
//
// unit is the systemd unit name being adopted (e.g.
// "openclaw-gateway.service"). scope is accepted for call-site symmetry
// with the rest of this package's session-scope vocabulary and reserved
// for future per-adoption scope nesting, but does not currently affect the
// emitted Slice= value — see above.
//
// DropIn is a pure string builder: it performs no I/O. Callers are
// responsible for writing the returned content to the returned path and
// running `systemctl daemon-reload` + restart. Adoption is fully
// reversible: removing the drop-in file and reloading systemd restores
// the unit to its original (non-RanA) slice with no other state changed.
func DropIn(unit string, scope string) (path string, content string) {
	_ = scope // reserved; see doc comment — Slice= is always the fixed rana.slice

	path = "/etc/systemd/system/" + unit + ".d/50-rana.conf"

	var b strings.Builder
	b.WriteString("# Managed by RanA (rana adopt). Do not edit by hand — re-running\n")
	b.WriteString("# `rana adopt` will overwrite this file. Remove it and reload systemd\n")
	b.WriteString("# (systemctl daemon-reload) to fully undo adoption.\n")
	b.WriteString("[Service]\n")
	b.WriteString("Slice=" + SliceName() + "\n")

	return path, b.String()
}
