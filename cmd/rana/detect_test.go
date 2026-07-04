package main

import (
	"errors"
	"testing"
)

// fakeLister builds a processLister returning a fixed process list, for
// deterministic tests with no dependency on the real process table.
func fakeLister(procs []runningProcess) processLister {
	return func() ([]runningProcess, error) { return procs, nil }
}

func TestDetectAdoptCandidates_MatchesOpenClaw(t *testing.T) {
	procs := []runningProcess{
		{Pid: 100, ExePath: "/usr/bin/bash", Argv: []string{"/usr/bin/bash"}},
		{Pid: 200, ExePath: "/usr/local/bin/openclaw", Argv: []string{"openclaw", "gateway"}},
	}
	got, err := detectAdoptCandidates(fakeLister(procs))
	if err != nil {
		t.Fatalf("detectAdoptCandidates: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(got), got)
	}
	if got[0].Profile.Name != "openclaw" || got[0].Proc.Pid != 200 {
		t.Fatalf("got %+v, want openclaw/pid 200", got[0])
	}
}

func TestDetectAdoptCandidates_NoMatch(t *testing.T) {
	procs := []runningProcess{
		{Pid: 1, ExePath: "/sbin/init", Argv: []string{"/sbin/init"}},
		{Pid: 2, ExePath: "/usr/bin/bash", Argv: []string{"bash"}},
	}
	got, err := detectAdoptCandidates(fakeLister(procs))
	if err != nil {
		t.Fatalf("detectAdoptCandidates: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d candidates, want 0: %+v", len(got), got)
	}
}

func TestDetectAdoptCandidates_MultipleDistinctMatches(t *testing.T) {
	procs := []runningProcess{
		{Pid: 10, ExePath: "/usr/local/bin/openclaw", Argv: []string{"openclaw", "gateway"}},
		{Pid: 20, ExePath: "/usr/local/bin/claude", Argv: []string{"claude", "--claude-code"}},
	}
	got, err := detectAdoptCandidates(fakeLister(procs))
	if err != nil {
		t.Fatalf("detectAdoptCandidates: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d candidates, want 2: %+v", len(got), got)
	}
	// Deterministic, sorted-by-name order.
	if got[0].Profile.Name != "claude-code" || got[1].Profile.Name != "openclaw" {
		t.Fatalf("got order %q, %q; want claude-code, openclaw", got[0].Profile.Name, got[1].Profile.Name)
	}
}

func TestDetectAdoptCandidates_DedupesSameProfileMultipleProcesses(t *testing.T) {
	procs := []runningProcess{
		{Pid: 10, ExePath: "/usr/local/bin/openclaw", Argv: []string{"openclaw", "gateway"}},
		{Pid: 11, ExePath: "/usr/local/bin/openclaw", Argv: []string{"openclaw", "gateway"}},
	}
	got, err := detectAdoptCandidates(fakeLister(procs))
	if err != nil {
		t.Fatalf("detectAdoptCandidates: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d candidates, want 1 (deduped): %+v", len(got), got)
	}
	if got[0].Proc.Pid != 10 {
		t.Fatalf("expected first-match-wins pid 10, got %d", got[0].Proc.Pid)
	}
}

func TestDetectAdoptCandidates_ListerError(t *testing.T) {
	wantErr := errors.New("boom")
	_, err := detectAdoptCandidates(func() ([]runningProcess, error) { return nil, wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("detectAdoptCandidates error = %v, want %v", err, wantErr)
	}
}

// TestDetectAdoptCandidates_NeverSeesEnviron is a structural regression
// guard for P3: runningProcess has no field capable of carrying
// environment data, so a lister literally cannot smuggle envp/environ
// content through this path. This test documents that invariant by
// construction rather than by behavior (there is nothing to assert at
// runtime — the type itself is the guarantee).
func TestDetectAdoptCandidates_NeverSeesEnviron(t *testing.T) {
	var p runningProcess
	// If this ever needs an Env field, P3 requires a design review before
	// adding one, not a quiet field addition — this test exists to be a
	// visible speed bump.
	_ = p.Pid
	_ = p.ExePath
	_ = p.Argv
}
