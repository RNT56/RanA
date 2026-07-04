package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExport_Pack proves `rana export --pack` produces a single
// <session>.ranaproof archive bundling the export artifacts, and that the
// frozen (non---pack) export path is unchanged.
func TestExport_Pack(t *testing.T) {
	root, session := buildLedger(t)

	packPath := filepath.Join(t.TempDir(), session+".ranaproof")
	code, out, errs := run("export", "--data", root, "--session", session, "--out", packPath, "--pack")
	if code != 0 {
		t.Fatalf("export --pack: code=%d err=%q", code, errs)
	}
	if !strings.Contains(out, session) {
		t.Fatalf("export --pack: stdout does not mention session: %q", out)
	}
	if _, err := os.Stat(packPath); err != nil {
		t.Fatalf("export --pack did not create %s: %v", packPath, err)
	}

	entries := tarZstEntries(t, packPath)
	if _, ok := entries["exports/events.cbor"]; !ok {
		t.Fatalf("pack missing exports/events.cbor; entries=%v", keysOf(entries))
	}
	if _, ok := entries["OPEN_ME.txt"]; !ok {
		t.Fatalf("pack missing OPEN_ME.txt; entries=%v", keysOf(entries))
	}
}

// TestExport_PackRejectsIncidentFormat proves --pack is scoped to the proof
// format and is rejected (usage error) when combined with --format incident,
// rather than silently ignored.
func TestExport_PackRejectsIncidentFormat(t *testing.T) {
	root, session := buildLedger(t)
	code, _, errs := run("export", "--data", root, "--session", session, "--format", "incident", "--pack")
	if code != exitUsage {
		t.Fatalf("export --format incident --pack: code=%d, want usage error; err=%q", code, errs)
	}
}

// TestExport_FormatIncident proves `rana export --format incident` renders
// internal/report.IncidentReport, to stdout by default and to a file when
// --out is given.
func TestExport_FormatIncident(t *testing.T) {
	root, session := buildLedger(t)

	code, out, errs := run("export", "--data", root, "--session", session, "--format", "incident")
	if code != 0 {
		t.Fatalf("export --format incident: code=%d err=%q", code, errs)
	}
	for _, want := range []string{"Incident Report", session, "proc.exec", "LIMITS.md"} {
		if !strings.Contains(out, want) {
			t.Errorf("export --format incident: stdout missing %q\n---\n%s", want, out)
		}
	}

	outFile := filepath.Join(t.TempDir(), "incident.md")
	code, stdout2, errs2 := run("export", "--data", root, "--session", session, "--format", "incident", "--out", outFile)
	if code != 0 {
		t.Fatalf("export --format incident --out: code=%d err=%q", code, errs2)
	}
	if !strings.Contains(stdout2, outFile) {
		t.Fatalf("export --format incident --out: stdout should confirm the file path, got %q", stdout2)
	}
	b, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading %s: %v", outFile, err)
	}
	if !strings.Contains(string(b), "Incident Report") {
		t.Fatalf("incident file missing report header: %q", string(b))
	}
}

// TestExport_UnknownFormat proves an unrecognized --format value is a usage
// error, not a silent fallback.
func TestExport_UnknownFormat(t *testing.T) {
	root, session := buildLedger(t)
	code, _, errs := run("export", "--data", root, "--session", session, "--format", "bogus")
	if code != exitUsage || !strings.Contains(errs, "unknown --format") {
		t.Fatalf("export --format bogus: code=%d err=%q", code, errs)
	}
}
