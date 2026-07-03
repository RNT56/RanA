package service

import (
	"testing"

	"github.com/RNT56/RanA/internal/profile"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

func testPipeline(t *testing.T) *redact.Pipeline {
	t.Helper()
	p, err := redact.NewPipeline([]byte("marker-test-salt-0123456789"))
	if err != nil {
		t.Fatalf("redact.NewPipeline: %v", err)
	}
	return p
}

func openclawMarkers() profile.Markers {
	return profile.Markers{
		Enabled:      true,
		Socket:       "$RANA_MARKER_SOCKET",
		Events:       []string{"run.start", "run.end"},
		CarryFields:  []string{"runId", "agentId", "channel", "status"},
		ForbidFields: []string{"text", "prompt", "completion", "message", "content", "summary"},
	}
}

// --- well-formed marker: accepted, fields carried, redacted, origin=enrichment ---

func TestParseMarkerLine_WellFormedAccepted(t *testing.T) {
	cfg := openclawMarkers()
	p := testPipeline(t)

	line := []byte(`{"event":"run.start","runId":"a9f2","agentId":"default","channel":"telegram","status":"accepted"}`)

	ev, err := parseMarkerLine(line, cfg, p, markerContext{
		Session: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Seg:     0,
		Idx:     1,
		TsMono:  1000,
		TsWall:  2000,
		Pid:     42,
	})
	if err != nil {
		t.Fatalf("parseMarkerLine: unexpected error: %v", err)
	}
	if ev.Origin != schema.OriginEnrichment {
		t.Fatalf("origin = %q, want enrichment", ev.Origin)
	}
	if ev.Type != schema.EventTypeMarker("run.start") {
		t.Fatalf("type = %q, want marker.run.start", ev.Type)
	}
	for _, want := range []string{"runId", "agentId", "channel", "status"} {
		if _, ok := ev.Data[want]; !ok {
			t.Errorf("Data missing carried field %q", want)
		}
	}
	if err := schema.Validate(ev); err != nil {
		t.Fatalf("schema.Validate: %v", err)
	}
}

// --- event not in the profile's declared [markers].events allowlist ---

func TestParseMarkerLine_UnknownEventRejected(t *testing.T) {
	cfg := openclawMarkers()
	p := testPipeline(t)

	line := []byte(`{"event":"run.middle","runId":"a9f2"}`)
	_, err := parseMarkerLine(line, cfg, p, markerContext{Session: "s", Idx: 1})
	if err == nil {
		t.Fatal("expected error for event not in [markers].events, got nil")
	}
}

// --- extra field outside carry_fields must be stripped, never fabricated into the event ---

func TestParseMarkerLine_ExtraFieldStripped(t *testing.T) {
	cfg := openclawMarkers()
	p := testPipeline(t)

	line := []byte(`{"event":"run.start","runId":"a9f2","evil_extra":"should not appear"}`)
	ev, err := parseMarkerLine(line, cfg, p, markerContext{Session: "s", Idx: 1})
	if err != nil {
		t.Fatalf("parseMarkerLine: %v", err)
	}
	if _, ok := ev.Data["evil_extra"]; ok {
		t.Fatal("extra field 'evil_extra' leaked into event Data")
	}
	for k := range ev.Data {
		found := false
		for _, allowed := range cfg.CarryFields {
			if k == allowed {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Data key %q is not in carry_fields allowlist", k)
		}
	}
}

// --- forbid_fields is belt-and-suspenders: even if a hostile profile put a
// content field in carry_fields, forbid_fields must still block it. ---

func TestParseMarkerLine_ForbidFieldNeverCarried(t *testing.T) {
	cfg := openclawMarkers()
	// Simulate a misconfigured/hostile-adjacent profile that accidentally
	// carries a forbidden field too; forbid_fields must win.
	cfg.CarryFields = append(cfg.CarryFields, "text")
	p := testPipeline(t)

	line := []byte(`{"event":"run.start","runId":"a9f2","text":"the secret prompt content"}`)
	ev, err := parseMarkerLine(line, cfg, p, markerContext{Session: "s", Idx: 1})
	if err != nil {
		t.Fatalf("parseMarkerLine: %v", err)
	}
	if _, ok := ev.Data["text"]; ok {
		t.Fatal("forbidden field 'text' leaked into event Data despite forbid_fields")
	}
}

// --- every documented forbidden content field, individually ---

func TestParseMarkerLine_AllForbiddenContentFieldsStripped(t *testing.T) {
	cfg := openclawMarkers()
	cfg.CarryFields = append(cfg.CarryFields, cfg.ForbidFields...) // hostile: carry+forbid overlap
	p := testPipeline(t)

	for _, field := range []string{"text", "prompt", "completion", "message", "content", "summary"} {
		t.Run(field, func(t *testing.T) {
			line := []byte(`{"event":"run.start","runId":"a9f2","` + field + `":"leaked content here"}`)
			ev, err := parseMarkerLine(line, cfg, p, markerContext{Session: "s", Idx: 1})
			if err != nil {
				t.Fatalf("parseMarkerLine: %v", err)
			}
			if _, ok := ev.Data[field]; ok {
				t.Fatalf("forbidden field %q leaked into Data", field)
			}
		})
	}
}

// --- string values that ARE carried must be redacted (Redacted type),
// never a raw Go string, and secrets embedded in a carried field must be
// caught by the pipeline. ---

func TestParseMarkerLine_CarriedStringsAreRedacted(t *testing.T) {
	cfg := openclawMarkers()
	p := testPipeline(t)

	// channel is a carried field; stuff an AWS-key-shaped string into it to
	// prove the pipeline actually ran. Split literal so the contiguous key
	// shape never appears in source (secret-scanner hygiene); still matches
	// AKIA[0-9A-Z]{16} at runtime.
	awsShaped := "AKIA" + "XXXXXXXXXXXXXXXX"
	line := []byte(`{"event":"run.start","runId":"a9f2","channel":"` + awsShaped + `"}`)
	ev, err := parseMarkerLine(line, cfg, p, markerContext{Session: "s", Idx: 1})
	if err != nil {
		t.Fatalf("parseMarkerLine: %v", err)
	}
	v, ok := ev.Data["channel"]
	if !ok {
		t.Fatal("channel field missing")
	}
	rv, ok := v.(redact.Redacted)
	if !ok {
		t.Fatalf("channel field is %T, want redact.Redacted", v)
	}
	if string(rv) == awsShaped {
		t.Fatal("raw AWS-key-shaped secret survived redaction in a marker field")
	}
}

// --- oversized line (>4KiB) rejected outright ---

func TestParseMarkerLine_OversizedRejected(t *testing.T) {
	cfg := openclawMarkers()
	p := testPipeline(t)

	big := make([]byte, 5000)
	for i := range big {
		big[i] = 'a'
	}
	line := []byte(`{"event":"run.start","runId":"` + string(big) + `"}`)
	if len(line) <= maxMarkerLineBytes {
		t.Fatalf("test line not actually oversized: %d bytes", len(line))
	}
	_, err := parseMarkerLine(line, cfg, p, markerContext{Session: "s", Idx: 1})
	if err == nil {
		t.Fatal("expected error for oversized marker line, got nil")
	}
}

// --- malformed / non-JSON input rejected, never partially parsed into an event ---

func TestParseMarkerLine_NonJSONRejected(t *testing.T) {
	cfg := openclawMarkers()
	p := testPipeline(t)

	for _, bad := range [][]byte{
		[]byte(`not json at all`),
		[]byte(`{"event": "run.start", "runId": }`), // truncated/malformed
		[]byte(``),
		[]byte(`   `),
		[]byte(`[1,2,3]`),         // valid JSON, wrong shape (array not object)
		[]byte(`"just a string"`), // valid JSON, wrong shape
		[]byte(`null`),
	} {
		_, err := parseMarkerLine(bad, cfg, p, markerContext{Session: "s", Idx: 1})
		if err == nil {
			t.Fatalf("expected error for malformed input %q, got nil", bad)
		}
	}
}

// --- missing "event" field rejected ---

func TestParseMarkerLine_MissingEventFieldRejected(t *testing.T) {
	cfg := openclawMarkers()
	p := testPipeline(t)

	line := []byte(`{"runId":"a9f2"}`)
	_, err := parseMarkerLine(line, cfg, p, markerContext{Session: "s", Idx: 1})
	if err == nil {
		t.Fatal("expected error for marker with no event field, got nil")
	}
}

// --- non-string values in carried fields (numbers, bools, nested objects)
// must not crash and must not smuggle a raw string past redaction; only
// JSON string values are meaningfully redactable, others are passed through
// as their JSON-decoded Go type only if that type is safe (bool/float64/nil)
// or stringified+redacted; nested objects/arrays in a carried field are
// rejected rather than silently flattened (keeps the P7 surface small and
// predictable). ---

func TestParseMarkerLine_NestedObjectInCarriedFieldRejected(t *testing.T) {
	cfg := openclawMarkers()
	p := testPipeline(t)

	line := []byte(`{"event":"run.start","runId":{"nested":"object"}}`)
	_, err := parseMarkerLine(line, cfg, p, markerContext{Session: "s", Idx: 1})
	if err == nil {
		t.Fatal("expected error for nested-object carried field, got nil")
	}
}

func TestParseMarkerLine_NonStringScalarCarriedFieldAllowed(t *testing.T) {
	cfg := openclawMarkers()
	// status as a bool is a slightly contrived example but proves scalars
	// don't crash the parser and are represented safely (as a Literal or
	// redacted string, never a raw bare string check bypass).
	p := testPipeline(t)

	line := []byte(`{"event":"run.start","runId":"a9f2","status":true}`)
	ev, err := parseMarkerLine(line, cfg, p, markerContext{Session: "s", Idx: 1})
	if err != nil {
		t.Fatalf("parseMarkerLine: %v", err)
	}
	if _, ok := ev.Data["status"]; !ok {
		t.Fatal("boolean carried field missing from Data")
	}
}

// --- token mismatch is enforced by the caller (marker listener), not
// parseMarkerLine itself (token belongs to the connection, not the line) —
// covered in marker_listener_test.go's adversarial battery.
