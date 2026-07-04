package main

import (
	"strings"
	"testing"
)

// TestDoctor_ReportProducesTrustCard proves `rana doctor --report` emits a
// plain-text, copy-pasteable "trust card": capability tier (the existing
// platform section), a redaction-corpus/version stamp, a ledger integrity
// quick-check, and a LIMITS.md pointer — against a real (clean) ledger.
func TestDoctor_ReportProducesTrustCard(t *testing.T) {
	root, _ := buildLedger(t)

	code, out, errs := run("doctor", "--data", root, "--report")
	if code != 0 {
		t.Fatalf("doctor --report: code=%d err=%q", code, errs)
	}
	for _, want := range []string{
		"RanA Trust Card",
		"Platform:",
		"Redaction:",
		"chain intact",
		"LIMITS.md",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor --report missing %q in:\n%s", want, out)
		}
	}
}

// TestDoctor_ReportOnEmptyDataDir proves --report degrades honestly (no
// panic, a clear "no ledger yet" note) when there is nothing recorded yet —
// mirroring plain `doctor`'s existing behavior on an empty datadir.
func TestDoctor_ReportOnEmptyDataDir(t *testing.T) {
	dir := t.TempDir()
	code, out, errs := run("doctor", "--data", dir, "--report")
	if code != 0 {
		t.Fatalf("doctor --report (empty): code=%d err=%q", code, errs)
	}
	if !strings.Contains(out, "RanA Trust Card") {
		t.Fatalf("doctor --report (empty) missing trust card header: %q", out)
	}
	if !strings.Contains(out, "none yet") {
		t.Fatalf("doctor --report (empty) should note no ledger yet: %q", out)
	}
}

// TestDoctor_ReportFlagsBrokenChain proves the trust card is honest when
// the chain is broken — it must never claim "intact" over a tampered
// ledger (P4/P10: documented honesty).
func TestDoctor_ReportFlagsBrokenChain(t *testing.T) {
	root, _ := buildLedger(t)
	corruptEventByte(t, root)

	code, out, errs := run("doctor", "--data", root, "--report")
	if code != 0 {
		t.Fatalf("doctor --report (broken): code=%d err=%q", code, errs)
	}
	if !strings.Contains(out, "BROKEN") {
		t.Fatalf("doctor --report (broken) should say BROKEN, got: %q", out)
	}
	if strings.Contains(out, "chain intact") {
		t.Fatalf("doctor --report (broken) must not claim chain intact: %q", out)
	}
}

// TestDoctor_DefaultUnchangedWithoutReportFlag proves --report is strictly
// additive: plain `rana doctor` output is unaffected.
func TestDoctor_DefaultUnchangedWithoutReportFlag(t *testing.T) {
	dir := t.TempDir()
	code, out, errs := run("doctor", "--data", dir)
	if code != 0 {
		t.Fatalf("doctor: code=%d err=%q", code, errs)
	}
	if strings.Contains(out, "RanA Trust Card") {
		t.Fatalf("doctor without --report should not print the trust card: %q", out)
	}
}
