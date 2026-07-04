package collector

import (
	"testing"

	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// ---- exe-provenance: exe_first_seen / exe_changed / exe_known ----
//
// D1 (kernel truth over agent self-report): the digest itself is computed
// upstream (ranad hashes the exe file) and handed to the Enricher as
// already-known data — this package never reads envp/environ and never
// re-derives the digest; it only tracks (exe_path, digest) pairs it is
// told about, per session, and classifies the path against a small
// embedded local allowlist. No network call, no new EventType: these are
// purely additive Data fields on proc.exec (schema is "frozen fields ⊕
// extensible attrs").

var digestA = [32]byte{0xAA}
var digestB = [32]byte{0xBB}

func execRecWithDigest(cgid uint64, exePath string, digest [32]byte) ExecRecord {
	return ExecRecord{
		Pid: 1, Cgid: cgid, Comm: "x", ExePath: exePath, Cwd: "/",
		ExeDigest:    digest,
		ExeDigestSet: true,
	}
}

func TestEnrichExecFirstSeenTrueOnFirstSighting(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")

	ev, err := e.EnrichExec(execRecWithDigest(1, "/usr/bin/node", digestA), 0)
	if err != nil {
		t.Fatalf("EnrichExec: %v", err)
	}
	firstSeen, ok := ev.Data["exe_first_seen"].(bool)
	if !ok || !firstSeen {
		t.Errorf("Data[exe_first_seen] = %#v, want true", ev.Data["exe_first_seen"])
	}
	if changed, ok := ev.Data["exe_changed"].(bool); !ok || changed {
		t.Errorf("Data[exe_changed] = %#v, want false on first sighting", ev.Data["exe_changed"])
	}
	if err := schema.Validate(ev); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestEnrichExecFirstSeenFalseOnRepeatSameDigest(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")

	rec := execRecWithDigest(1, "/usr/bin/node", digestA)
	if _, err := e.EnrichExec(rec, 0); err != nil {
		t.Fatalf("EnrichExec (1st): %v", err)
	}
	ev2, err := e.EnrichExec(rec, 0)
	if err != nil {
		t.Fatalf("EnrichExec (2nd): %v", err)
	}
	if firstSeen, ok := ev2.Data["exe_first_seen"].(bool); !ok || firstSeen {
		t.Errorf("Data[exe_first_seen] = %#v, want false on repeat", ev2.Data["exe_first_seen"])
	}
	if changed, ok := ev2.Data["exe_changed"].(bool); !ok || changed {
		t.Errorf("Data[exe_changed] = %#v, want false — same digest is not a swap", ev2.Data["exe_changed"])
	}
}

func TestEnrichExecChangedTrueWhenDigestDiffers(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")

	if _, err := e.EnrichExec(execRecWithDigest(1, "/usr/bin/node", digestA), 0); err != nil {
		t.Fatalf("EnrichExec (1st): %v", err)
	}
	ev2, err := e.EnrichExec(execRecWithDigest(1, "/usr/bin/node", digestB), 0)
	if err != nil {
		t.Fatalf("EnrichExec (2nd, swapped digest): %v", err)
	}
	if changed, ok := ev2.Data["exe_changed"].(bool); !ok || !changed {
		t.Errorf("Data[exe_changed] = %#v, want true — same path, different digest is a swapped binary", ev2.Data["exe_changed"])
	}
	// A swapped binary at the same path is, from the digest-pairing
	// perspective, also a first sighting of THIS (path, digest) pair.
	if firstSeen, ok := ev2.Data["exe_first_seen"].(bool); !ok || !firstSeen {
		t.Errorf("Data[exe_first_seen] = %#v, want true for a never-before-seen (path,digest) pair", ev2.Data["exe_first_seen"])
	}
}

func TestEnrichExecProvenanceScopedPerSession(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")
	e.BindCgid(2, "sess-2")

	if _, err := e.EnrichExec(execRecWithDigest(1, "/usr/bin/node", digestA), 0); err != nil {
		t.Fatalf("EnrichExec sess-1: %v", err)
	}
	// A different session seeing the exact same (path, digest) pair for
	// the first time is still a first sighting *for that session* — the
	// seen-map is keyed by session (CONTRACTS: "in-enricher seen-map keyed
	// by session").
	ev, err := e.EnrichExec(execRecWithDigest(2, "/usr/bin/node", digestA), 0)
	if err != nil {
		t.Fatalf("EnrichExec sess-2: %v", err)
	}
	if firstSeen, ok := ev.Data["exe_first_seen"].(bool); !ok || !firstSeen {
		t.Errorf("Data[exe_first_seen] = %#v, want true — session-scoped seen-map", ev.Data["exe_first_seen"])
	}
}

func TestEnrichExecNoDigestOmitsProvenanceFields(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")

	// No ExeDigestSet: the record's exe digest is unknown (e.g. ranad
	// couldn't stat/hash the exe in time) — provenance fields must be
	// omitted entirely rather than fabricated as false/unknown, per P5's
	// spirit (never assert a fact you don't have).
	rec := ExecRecord{Pid: 1, Cgid: 1, Comm: "x", ExePath: "/usr/bin/node", Cwd: "/"}
	ev, err := e.EnrichExec(rec, 0)
	if err != nil {
		t.Fatalf("EnrichExec: %v", err)
	}
	if _, ok := ev.Data["exe_first_seen"]; ok {
		t.Error("did not expect exe_first_seen when no digest was supplied")
	}
	if _, ok := ev.Data["exe_changed"]; ok {
		t.Error("did not expect exe_changed when no digest was supplied")
	}
	if _, ok := ev.Data["exe_known"]; ok {
		t.Error("did not expect exe_known when no digest was supplied")
	}
}

// ---- exe_known classification against the embedded allowlist ----

func TestEnrichExecKnownInterpreterClassifiedKnown(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")

	for _, p := range []string{"/usr/bin/bash", "/bin/sh", "/usr/bin/python3", "/usr/bin/node", "/usr/bin/env"} {
		rec := execRecWithDigest(1, p, digestA)
		ev, err := e.EnrichExec(rec, 0)
		if err != nil {
			t.Fatalf("EnrichExec(%q): %v", p, err)
		}
		known, ok := ev.Data["exe_known"].(redact.Redacted)
		if !ok {
			t.Fatalf("EnrichExec(%q): Data[exe_known] type = %T, want redact.Redacted", p, ev.Data["exe_known"])
		}
		if string(known) != ExeKnownAllowlisted {
			t.Errorf("EnrichExec(%q): exe_known = %q, want %q", p, known, ExeKnownAllowlisted)
		}
	}
}

func TestEnrichExecUnknownPathClassifiedUnknown(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")

	rec := execRecWithDigest(1, "/tmp/.hidden/payload", digestA)
	ev, err := e.EnrichExec(rec, 0)
	if err != nil {
		t.Fatalf("EnrichExec: %v", err)
	}
	known, ok := ev.Data["exe_known"].(redact.Redacted)
	if !ok {
		t.Fatalf("Data[exe_known] type = %T, want redact.Redacted", ev.Data["exe_known"])
	}
	if string(known) != ExeKnownUnclassified {
		t.Errorf("exe_known = %q, want %q", known, ExeKnownUnclassified)
	}
}

func TestClassifyExePathPortable(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/bin/bash", ExeKnownAllowlisted},
		{"/usr/bin/bash", ExeKnownAllowlisted},
		{"/usr/local/bin/python3.11", ExeKnownAllowlisted},
		{"/usr/bin/perl", ExeKnownAllowlisted},
		{"/usr/bin/ruby", ExeKnownAllowlisted},
		{"/opt/evil/bash", ExeKnownUnclassified}, // path spoofing a known name elsewhere is NOT allowlisted
		{"", ExeKnownUnclassified},
		{"/home/user/my-script", ExeKnownUnclassified},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := ClassifyExePath(tt.path)
			if got != tt.want {
				t.Errorf("ClassifyExePath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// TestEnrichExecProvenanceRedactedTypesOnly guards P3 by construction: any
// string-shaped provenance field reaching Data must be a redact.Redacted,
// never a plain string (the exe_known classification label is a fixed,
// non-secret enum value, but it still travels through the same
// redact.Redacted wrapper as every other string field for schema/type
// uniformity, so cborcanon's plain-string rejection can't be tripped by a
// provenance addition).
func TestEnrichExecProvenanceRedactedTypesOnly(t *testing.T) {
	clk := newFakeClock()
	e := newTestEnricher(t, clk)
	e.BindCgid(1, "sess-1")
	ev, err := e.EnrichExec(execRecWithDigest(1, "/bin/bash", digestA), 0)
	if err != nil {
		t.Fatalf("EnrichExec: %v", err)
	}
	if v, ok := ev.Data["exe_known"]; ok {
		if _, ok := v.(redact.Redacted); !ok {
			t.Errorf("Data[exe_known] type = %T, want redact.Redacted", v)
		}
	}
}
