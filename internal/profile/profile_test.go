package profile

import (
	"strings"
	"testing"
)

func TestParse_MinimalValid(t *testing.T) {
	src := `
[profile]
name = "custom"
description = "a test profile"
version = 1

[match]
auto = true
exe_basename = ["myagent"]
argv_contains = []

[capture]
exec            = true
fork_exit       = true
file_write      = true
file_meta_ops   = true
network_connect = true
network_flow    = true
unix_sockets    = true

[digest]
scopes = ["$SESSION_CWD/**"]
exclude = []

[sensitive_read]
extra = ["~/.custom/**"]

[markers]
enabled = false

[timeline]
lens = "tree"

[retention]
ttl_days = 30
`
	p, err := Parse(src, "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Name != "custom" {
		t.Errorf("Name = %q", p.Name)
	}
	if p.Version != 1 {
		t.Errorf("Version = %d", p.Version)
	}
	if !p.Match.Auto {
		t.Errorf("Match.Auto = false")
	}
	if len(p.Match.ExeBasename) != 1 || p.Match.ExeBasename[0] != "myagent" {
		t.Errorf("ExeBasename = %#v", p.Match.ExeBasename)
	}
	if !p.Capture.Exec || !p.Capture.NetworkConnect {
		t.Errorf("capture booleans not parsed: %#v", p.Capture)
	}
	if len(p.SensitiveRead.Extra) != 1 {
		t.Errorf("SensitiveRead.Extra = %#v", p.SensitiveRead.Extra)
	}
	if p.Timeline.Lens != "tree" {
		t.Errorf("Timeline.Lens = %q", p.Timeline.Lens)
	}
	if p.Retention.TTLDays != 30 {
		t.Errorf("Retention.TTLDays = %d", p.Retention.TTLDays)
	}
}

func TestParse_MissingProfileSection(t *testing.T) {
	src := `
[match]
auto = false
`
	_, err := Parse(src, "test")
	if err == nil {
		t.Fatal("expected error for missing [profile] section")
	}
}

func TestParse_MissingName(t *testing.T) {
	src := `
[profile]
description = "x"
version = 1
`
	_, err := Parse(src, "test")
	if err == nil {
		t.Fatal("expected error for missing profile.name")
	}
}

func TestParse_SyntaxErrorWrapsSource(t *testing.T) {
	_, err := Parse("not valid toml =", "myfile.toml")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "myfile.toml") {
		t.Errorf("error should reference source name, got: %v", err)
	}
}

func TestParse_MarkersFields(t *testing.T) {
	src := `
[profile]
name = "m"
description = "d"
version = 1

[markers]
enabled = true
socket = "$RANA_MARKER_SOCKET"
events = ["run.start", "run.end"]
carry_fields = ["runId", "agentId"]
forbid_fields = ["text", "prompt"]

[timeline]
lens = "causality"
cluster_by = "runId"
fallback_lens = "inferred"
`
	p, err := Parse(src, "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Markers.Enabled {
		t.Error("Markers.Enabled = false")
	}
	if p.Markers.Socket != "$RANA_MARKER_SOCKET" {
		t.Errorf("Markers.Socket = %q", p.Markers.Socket)
	}
	if len(p.Markers.Events) != 2 {
		t.Errorf("Markers.Events = %#v", p.Markers.Events)
	}
	if len(p.Markers.CarryFields) != 2 || len(p.Markers.ForbidFields) != 2 {
		t.Errorf("carry/forbid = %#v / %#v", p.Markers.CarryFields, p.Markers.ForbidFields)
	}
	if p.Timeline.ClusterBy != "runId" || p.Timeline.FallbackLens != "inferred" {
		t.Errorf("Timeline = %#v", p.Timeline)
	}
}

func TestParse_RedactionSection(t *testing.T) {
	src := `
[profile]
name = "m"
description = "d"
version = 1

[redaction]
extra_patterns = ["foo-[a-z]+"]
entropy_min_len = 10
entropy_threshold = 4.5
`
	p, err := Parse(src, "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Redaction.ExtraPatterns) != 1 {
		t.Errorf("ExtraPatterns = %#v", p.Redaction.ExtraPatterns)
	}
	if p.Redaction.EntropyMinLen != 10 {
		t.Errorf("EntropyMinLen = %d", p.Redaction.EntropyMinLen)
	}
}

func TestParse_DefaultsWhenSectionsAbsent(t *testing.T) {
	src := `
[profile]
name = "m"
description = "d"
version = 1
`
	p, err := Parse(src, "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// capture defaults to all-true (D7 baseline) when [capture] is absent.
	if !p.Capture.Exec || !p.Capture.ForkExit || !p.Capture.FileWrite ||
		!p.Capture.FileMetaOps || !p.Capture.NetworkConnect || !p.Capture.NetworkFlow ||
		!p.Capture.UnixSockets {
		t.Errorf("capture defaults not all true: %#v", p.Capture)
	}
}
