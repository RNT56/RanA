package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestAdopt_ExplicitTargetStillWorks is the regression guard for keeping
// `rana adopt <target>` working exactly as before auto-detect landed
// (task requirement: "Keep the explicit rana adopt <target> path
// working").
func TestAdopt_ExplicitTargetStillWorks(t *testing.T) {
	dir := t.TempDir()
	code, out, errs := run("adopt", "--data", dir, "openclaw")
	if code != exitOK {
		t.Fatalf("adopt openclaw: code=%d err=%q", code, errs)
	}
	if !strings.Contains(out, "openclaw") {
		t.Fatalf("adopt openclaw: stdout does not mention target: %q", out)
	}
}

// TestAdopt_ExplicitUnknownTargetIsUsageError preserves the pre-existing
// error behavior for an unrecognized explicit target.
func TestAdopt_ExplicitUnknownTargetIsUsageError(t *testing.T) {
	dir := t.TempDir()
	code, _, errs := run("adopt", "--data", dir, "not-a-real-profile")
	if code != exitUsage || !strings.Contains(errs, "no profile named") {
		t.Fatalf("adopt <bogus>: code=%d err=%q", code, errs)
	}
}

// TestAdoptAutoDetect_SingleAdoptableMatchProceeds proves that with no
// target and exactly one running, adoptable candidate, cmdAdoptAutoDetect
// proceeds straight to adoptPlatform (same output shape as an explicit
// `rana adopt openclaw`).
func TestAdoptAutoDetect_SingleAdoptableMatchProceeds(t *testing.T) {
	var out, errb bytes.Buffer
	code := cmdAdoptAutoDetect(adoptDetectParams{
		DataDir: t.TempDir(),
		Stdout:  &out,
		Stderr:  &errb,
		List: fakeLister([]runningProcess{
			{Pid: 42, ExePath: "/usr/local/bin/openclaw", Argv: []string{"openclaw", "gateway"}},
		}),
	})
	if code != exitOK {
		t.Fatalf("cmdAdoptAutoDetect: code=%d err=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "detected openclaw") {
		t.Fatalf("expected detection message, got: %q", out.String())
	}
	if !strings.Contains(out.String(), "openclaw") {
		t.Fatalf("expected adoptPlatform output to mention openclaw, got: %q", out.String())
	}
}

// TestAdoptAutoDetect_NoCandidatesReportsHonestly proves a clean "nothing
// found" outcome rather than a spurious error or a silent no-op.
func TestAdoptAutoDetect_NoCandidatesReportsHonestly(t *testing.T) {
	var out, errb bytes.Buffer
	code := cmdAdoptAutoDetect(adoptDetectParams{
		DataDir: t.TempDir(),
		Stdout:  &out,
		Stderr:  &errb,
		List:    fakeLister(nil),
	})
	if code != exitOK {
		t.Fatalf("cmdAdoptAutoDetect (none): code=%d err=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "no running adoptable agent detected") {
		t.Fatalf("expected an honest none-found message, got: %q", out.String())
	}
}

// TestAdoptAutoDetect_MultipleCandidatesNeverGuesses proves that when more
// than one distinct profile matches, auto-detect lists them and refuses to
// pick one — the explicit path is always required to disambiguate.
func TestAdoptAutoDetect_MultipleCandidatesNeverGuesses(t *testing.T) {
	var out, errb bytes.Buffer
	code := cmdAdoptAutoDetect(adoptDetectParams{
		DataDir: t.TempDir(),
		Stdout:  &out,
		Stderr:  &errb,
		List: fakeLister([]runningProcess{
			{Pid: 1, ExePath: "/usr/local/bin/openclaw", Argv: []string{"openclaw", "gateway"}},
			{Pid: 2, ExePath: "/usr/local/bin/claude", Argv: []string{"claude", "--claude-code"}},
		}),
	})
	if code != exitOK {
		t.Fatalf("cmdAdoptAutoDetect (multi): code=%d err=%q", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, "openclaw") || !strings.Contains(got, "claude-code") {
		t.Fatalf("expected both candidates listed, got: %q", got)
	}
	if !strings.Contains(got, "pick one explicitly") {
		t.Fatalf("expected a disambiguation instruction, got: %q", got)
	}
}

// TestAdoptAutoDetect_MatchWithNoAdoptSectionIsReportedNotAdopted proves a
// recognized-but-not-adoptable match (e.g. codex/claude-code today, which
// have no [adopt] section) is reported honestly rather than silently
// skipped or incorrectly adopted.
func TestAdoptAutoDetect_MatchWithNoAdoptSectionIsReportedNotAdopted(t *testing.T) {
	var out, errb bytes.Buffer
	code := cmdAdoptAutoDetect(adoptDetectParams{
		DataDir: t.TempDir(),
		Stdout:  &out,
		Stderr:  &errb,
		List: fakeLister([]runningProcess{
			{Pid: 7, ExePath: "/usr/local/bin/codex", Argv: []string{"codex"}},
		}),
	})
	if code != exitOK {
		t.Fatalf("cmdAdoptAutoDetect (codex only): code=%d err=%q", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, "codex") {
		t.Fatalf("expected codex mentioned, got: %q", got)
	}
	if !strings.Contains(got, "not yet adoptable") && !strings.Contains(got, "None of these can be adopted") {
		t.Fatalf("expected an honest not-adoptable note, got: %q", got)
	}
}

// TestAdoptAutoDetect_ListerErrorSurfaces proves a scan failure is reported
// as a usage error rather than silently treated as "nothing found".
func TestAdoptAutoDetect_ListerErrorSurfaces(t *testing.T) {
	var out, errb bytes.Buffer
	code := cmdAdoptAutoDetect(adoptDetectParams{
		DataDir: t.TempDir(),
		Stdout:  &out,
		Stderr:  &errb,
		List:    func() ([]runningProcess, error) { return nil, errBoom },
	})
	if code != exitUsage {
		t.Fatalf("cmdAdoptAutoDetect (lister error): code=%d out=%q", code, out.String())
	}
	if !strings.Contains(errb.String(), "boom") {
		t.Fatalf("expected the lister error surfaced, got: %q", errb.String())
	}
}

// TestDispatch_AdoptNoArgsRoutesToAutoDetect is an end-to-end smoke test
// that `rana adopt` (no positional target) at least reaches auto-detect
// without crashing, using the REAL platform lister. It does not assert on
// specific output content (the real process table is untestable
// deterministically) — only that dispatch completes cleanly.
func TestDispatch_AdoptNoArgsRoutesToAutoDetect(t *testing.T) {
	dir := t.TempDir()
	code, _, errs := run("adopt", "--data", dir)
	if code != exitOK && code != exitUsage {
		t.Fatalf("adopt (auto-detect): unexpected code=%d err=%q", code, errs)
	}
}

var errBoom = &boomError{}

type boomError struct{}

func (*boomError) Error() string { return "boom" }
