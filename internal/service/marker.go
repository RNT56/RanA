package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/RNT56/RanA/internal/profile"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// maxMarkerLineBytes is the hard cap on one marker ndjson line
// (CONTRACTS §internal/service: "newline-delimited JSON ≤4KiB/line").
const maxMarkerLineBytes = 4096

// Marker ingest is a P7/P3 hotspot: a marker is agent-provided, untrusted
// input (origin=enrichment, never load-bearing per P1) that MUST NOT be
// able to fabricate a kernel event, inject message content, or smuggle a
// raw (unredacted) string into the ledger. Every string that survives
// field filtering is redacted before it ever reaches a schema constructor.
var (
	// ErrMarkerLineTooLarge is returned when a marker line exceeds
	// maxMarkerLineBytes.
	ErrMarkerLineTooLarge = errors.New("service: marker line exceeds 4KiB")
	// ErrMarkerNotJSONObject is returned when a marker line is not
	// well-formed JSON, or is valid JSON but not a top-level object.
	ErrMarkerNotJSONObject = errors.New("service: marker line is not a JSON object")
	// ErrMarkerMissingEvent is returned when a marker object has no
	// "event" string field.
	ErrMarkerMissingEvent = errors.New("service: marker missing \"event\" field")
	// ErrMarkerUnknownEvent is returned when a marker's "event" value is
	// not in the profile's declared [markers].events allowlist.
	ErrMarkerUnknownEvent = errors.New("service: marker event not in profile's declared events")
	// ErrMarkerFieldShape is returned when a carried field's JSON value is
	// a shape svc does not know how to safely carry (nested object/array).
	ErrMarkerFieldShape = errors.New("service: marker carries a field with an unsupported (nested) shape")
)

// markerContext supplies the envelope fields parseMarkerLine cannot derive
// from the marker line itself (session id, sequencing, timestamps, pid —
// all svc-assigned, never agent-supplied, since a marker source must never
// be able to claim another session's identity or forge a kernel-style
// timestamp).
type markerContext struct {
	Session string
	Seg     uint64
	Idx     uint64
	TsMono  uint64
	TsWall  uint64
	Pid     uint32
}

// eventFieldName is the fixed top-level key naming which marker event this
// line represents (docs/OPENCLAW.md: {runId, agentId, channel, status});
// it is consumed to select the marker.<suffix> type and is never itself
// carried into Data (it becomes the event Type, not a data field).
const eventFieldName = "event"

// parseMarkerLine parses one ndjson marker line against cfg (the active
// profile's [markers] table) and builds a marker.<event> schema.Event with
// origin=enrichment. It is the sole authority for what an agent-controlled
// byte string is allowed to become in the ledger:
//
//  1. size-capped before anything else touches it (maxMarkerLineBytes);
//  2. must be a JSON object with a known "event" name (cfg.Events);
//  3. only fields in cfg.CarryFields are considered, and cfg.ForbidFields
//     is then applied as a second, unconditional filter over that
//     surviving set — so even a misconfigured profile that accidentally
//     carries a content field can never leak it (belt-and-suspenders,
//     docs/OPENCLAW.md "The privacy line, stated plainly");
//  4. every surviving JSON string value is passed through pipeline.Redact
//     before being wrapped as redact.Redacted — the ONLY string type a
//     schema.Event.Data map may contain (P3, invariant 2);
//  5. non-string JSON scalars (bool, number, null) are carried as their
//     safe Go/CBOR-encodable type; nested objects/arrays are rejected
//     outright rather than silently flattened or dropped, keeping the
//     shape of what a marker can carry small and reviewable.
//
// A hostile or malformed marker (extra fields, forbidden content fields,
// oversized, non-JSON, unknown event name, nested shapes) is always
// rejected or stripped — parseMarkerLine can never fabricate a kernel-class
// event or let content through (P1, P7).
func parseMarkerLine(line []byte, cfg profile.Markers, pipeline *redact.Pipeline, mc markerContext) (schema.Event, error) {
	if len(line) > maxMarkerLineBytes {
		return schema.Event{}, fmt.Errorf("%w: %d bytes", ErrMarkerLineTooLarge, len(line))
	}
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return schema.Event{}, ErrMarkerNotJSONObject
	}

	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return schema.Event{}, fmt.Errorf("%w: %v", ErrMarkerNotJSONObject, err)
	}
	// A JSON array/string/number/bool/null all decode into a
	// map[string]any target as a type error above EXCEPT they don't always
	// — json.Unmarshal into map[string]any correctly errors for non-object
	// top-level values, so reaching here already guarantees an object.
	if dec.More() {
		// Trailing garbage after the first JSON value on the line.
		return schema.Event{}, fmt.Errorf("%w: trailing data after JSON value", ErrMarkerNotJSONObject)
	}

	eventNameRaw, ok := raw[eventFieldName]
	if !ok {
		return schema.Event{}, ErrMarkerMissingEvent
	}
	eventName, ok := eventNameRaw.(string)
	if !ok || eventName == "" {
		return schema.Event{}, ErrMarkerMissingEvent
	}
	if !stringInSlice(cfg.Events, eventName) {
		return schema.Event{}, fmt.Errorf("%w: %q", ErrMarkerUnknownEvent, eventName)
	}

	forbidden := toSet(cfg.ForbidFields)

	data := make(map[string]any, len(cfg.CarryFields))
	for _, field := range cfg.CarryFields {
		if field == eventFieldName {
			continue
		}
		if forbidden[field] {
			continue // belt-and-suspenders: never carried, no matter what
		}
		v, present := raw[field]
		if !present {
			continue
		}
		safe, err := toSafeMarkerValue(v, pipeline)
		if err != nil {
			return schema.Event{}, fmt.Errorf("field %q: %w", field, err)
		}
		if safe == nil {
			continue // present-but-null: drop rather than carry a typed nil
		}
		data[field] = safe
	}

	return schema.NewMarker(mc.Session, mc.Seg, mc.Idx, mc.TsMono, mc.TsWall, mc.Pid, eventName, data), nil
}

// toSafeMarkerValue converts one already-allowlisted JSON field value into
// a value legal inside schema.Event.Data: JSON strings are redacted
// (becoming redact.Redacted, never a plain string); booleans and
// json.Number pass through as their concrete Go type (bool / json.Number is
// rejected in favor of an explicit numeric conversion below so cborcanon
// never has to guess a wire width); null is skipped by the caller
// (present-but-null fields are dropped, not carried as a typed nil);
// objects and arrays are rejected (ErrMarkerFieldShape) rather than
// silently flattened.
func toSafeMarkerValue(v any, pipeline *redact.Pipeline) (any, error) {
	switch t := v.(type) {
	case string:
		return pipeline.Redact(t), nil
	case bool:
		return t, nil
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return uint64(i), nil
		}
		f, err := t.Float64()
		if err != nil {
			return nil, fmt.Errorf("%w: unparseable number %q", ErrMarkerFieldShape, t.String())
		}
		// schema/cborcanon forbid floats entirely (docs/TRUST.md §1: "no
		// floating point"); a marker cannot smuggle one through either.
		_ = f
		return nil, fmt.Errorf("%w: floating-point marker field values are not permitted", ErrMarkerFieldShape)
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrMarkerFieldShape, v)
	}
}

func stringInSlice(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}
