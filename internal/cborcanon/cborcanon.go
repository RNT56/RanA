// Package cborcanon implements RanA's deterministic CBOR encoding (RFC 8949
// Core Deterministic Encoding, docs/TRUST.md §1) on top of fxamacker/cbor.
//
// Determinism is the whole game: two encoders must produce byte-identical
// output for the same event, because that output is what gets hashed into
// the leaf (docs/TRUST.md §2) and ultimately signed. This package enforces,
// by construction, two of RanA's most load-bearing invariants:
//
//   - No floating point ever reaches the chain (timestamps are integer ns).
//   - No raw, unredacted string ever reaches an event's Data payload — only
//     redact.Redacted values (or typed enum constants) are accepted there.
package cborcanon

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"

	"github.com/fxamacker/cbor/v2"

	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// ErrRawString is returned by EncodeEvent when a plain Go string value is
// found inside an event's Data payload. Only redact.Redacted (or values of
// a named string-kind type, i.e. typed enum constants such as
// schema.PathSource) are permitted there — see docs/REDACTION.md and P3.
var ErrRawString = errors.New("cborcanon: raw string value in event data (must be redact.Redacted)")

// ErrFloat is returned when a float32/float64 value (including NaN/Inf) is
// found anywhere in the value being encoded. RanA's canonical encoding never
// carries floating point (docs/TRUST.md §1): timestamps are integer
// nanoseconds and there is no other legitimate use.
var ErrFloat = errors.New("cborcanon: floating point value is not permitted in canonical encoding")

// ErrUnencodable is returned for Go kinds CBOR cannot represent
// deterministically or at all (chan, func, unsafe pointer, complex).
var ErrUnencodable = errors.New("cborcanon: value kind cannot be canonically encoded")

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic("cborcanon: failed to build canonical encode mode: " + err.Error())
	}
	encMode = em

	dopts := cbor.DecOptions{
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
	}
	dm, err := dopts.DecMode()
	if err != nil {
		panic("cborcanon: failed to build strict decode mode: " + err.Error())
	}
	decMode = dm
}

// redactedType is the reflect.Type of redact.Redacted, used to recognize
// values that are exempt from the raw-string ban.
var redactedType = reflect.TypeOf(redact.Redacted(""))

// exemptEnumTypes is the closed, explicit allowlist of named string-kind
// types (besides redact.Redacted itself) that may appear as a value inside
// an event's Data payload. These are schema.go's fixed, frozen program
// vocabularies (enum labels drawn from a small closed constant set, never
// operator- or agent-controlled content) — NOT a blanket "any named string
// type" exemption. That distinction is the entire point of this list: P3
// must not be bypassable by wrapping arbitrary captured data (e.g. a raw
// secret) in some unrelated locally-defined string-kind type such as
// `type EvilString string`. Any new schema enum type must be added here
// explicitly, deliberately, and only if it is genuinely a closed-vocabulary
// label, never free-form captured text.
var exemptEnumTypes = map[reflect.Type]bool{
	reflect.TypeOf(schema.PathSource("")): true,
	reflect.TypeOf(schema.EventType("")):  true,
	reflect.TypeOf(schema.Origin("")):     true,
	reflect.TypeOf(schema.State("")):      true,
	reflect.TypeOf(schema.GapReason("")):  true,
}

// Encode canonically encodes v per RFC 8949 Core Deterministic Encoding:
// bytewise-sorted map keys, shortest-form integers, definite lengths, no
// floating point anywhere, no channels/functions/unsafe kinds.
//
// Encode does NOT enforce the event-data raw-string rule — use EncodeEvent
// for schema.Event values, which additionally rejects plain strings inside
// the Data payload (ErrRawString).
func Encode(v any) ([]byte, error) {
	if err := checkEncodable(reflect.ValueOf(v)); err != nil {
		return nil, err
	}
	return encMode.Marshal(v)
}

// checkEncodable walks a value tree and rejects float kinds and
// unencodable kinds (chan, func, unsafe pointer, complex) before we ever
// hand the value to the CBOR encoder. It does not reject strings — that
// rule is specific to event Data payloads and lives in checkEventData.
func checkEncodable(v reflect.Value) error {
	if !v.IsValid() {
		return nil // untyped nil is fine (encodes to CBOR null)
	}

	switch v.Kind() {
	case reflect.Float32, reflect.Float64:
		return ErrFloat
	case reflect.Chan, reflect.Func, reflect.UnsafePointer, reflect.Complex64, reflect.Complex128:
		return fmt.Errorf("%w: %s", ErrUnencodable, v.Kind())
	case reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return checkEncodable(v.Elem())
	case reflect.Ptr:
		if v.IsNil() {
			return nil
		}
		return checkEncodable(v.Elem())
	case reflect.Slice, reflect.Array:
		// []byte / [N]byte are leaves as far as CBOR is concerned.
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return nil
		}
		for i := 0; i < v.Len(); i++ {
			if err := checkEncodable(v.Index(i)); err != nil {
				return err
			}
		}
		return nil
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if err := checkEncodable(iter.Key()); err != nil {
				return err
			}
			if err := checkEncodable(iter.Value()); err != nil {
				return err
			}
		}
		return nil
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			if err := checkEncodable(v.Field(i)); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

// Decode strictly decodes canonical (or at least well-formed) CBOR into v.
// Unknown fields are rejected when v is (or contains) a struct type;
// indefinite-length items and duplicate map keys are rejected.
func Decode(b []byte, v any) error {
	return decMode.Unmarshal(b, v)
}

// IsCanonical reports whether b is already exactly the canonical encoding
// of the value it represents: it decodes b, re-encodes the result, and
// compares bytes. This is the technique verify uses (docs/TRUST.md §8 step
// 2 hashes provided bytes directly; IsCanonical is the local sanity check
// used when RanA itself produced the bytes, e.g. in the chain-mutation test
// suite and writer self-checks).
func IsCanonical(b []byte) (bool, error) {
	var v any
	if err := decMode.Unmarshal(b, &v); err != nil {
		return false, err
	}
	reenc, err := Encode(v)
	if err != nil {
		return false, err
	}
	return bytes.Equal(b, reenc), nil
}

// eventEnvelope mirrors schema.Event with explicit cbor struct tags giving
// the frozen, bytewise-sortable field names from docs/TRUST.md §1 /
// CONTRACTS §internal/schema:
//
//	v,type,session,seg,idx,ts_mono,ts_wall,pid,origin,state,data
//
// SortCoreDeterministic sorts map/struct-as-map keys bytewise at encode
// time regardless of struct field order, so declaration order here is for
// readability only.
type eventEnvelope struct {
	V       uint8          `cbor:"v"`
	Type    string         `cbor:"type"`
	Session string         `cbor:"session"`
	Seg     uint64         `cbor:"seg"`
	Idx     uint64         `cbor:"idx"`
	TsMono  uint64         `cbor:"ts_mono"`
	TsWall  uint64         `cbor:"ts_wall"`
	Pid     uint32         `cbor:"pid"`
	Origin  string         `cbor:"origin"`
	State   string         `cbor:"state"`
	Data    map[string]any `cbor:"data"`
}

// EncodeEvent canonically encodes a schema.Event. Every string value found
// anywhere inside ev.Data (including nested maps and slices) MUST be a
// redact.Redacted or a named string-kind type (e.g. schema.PathSource) —
// a plain Go string returns ErrRawString. This is P3 enforced by
// construction: a raw secret cannot reach a leaf hash through this path.
func EncodeEvent(ev schema.Event) ([]byte, error) {
	if err := checkEventData(reflect.ValueOf(ev.Data)); err != nil {
		return nil, err
	}

	env := eventEnvelope{
		V:       ev.V,
		Type:    string(ev.Type),
		Session: ev.Session,
		Seg:     ev.Seg,
		Idx:     ev.Idx,
		TsMono:  ev.TsMono,
		TsWall:  ev.TsWall,
		Pid:     ev.Pid,
		Origin:  string(ev.Origin),
		State:   string(ev.State),
		Data:    ev.Data,
	}

	if err := checkEncodable(reflect.ValueOf(env)); err != nil {
		return nil, err
	}

	return encMode.Marshal(env)
}

// checkEventData walks an event's Data payload and rejects any plain Go
// string it finds. redact.Redacted values pass (they are a distinct named
// type, not kind-string-as-string); the small, explicit allowlist in
// exemptEnumTypes (schema's fixed enum vocabularies, e.g. schema.PathSource)
// also passes. Every other string-kind value is rejected — INCLUDING named
// types this package has never heard of — because P3 must hold by
// construction: a raw secret cannot be smuggled past this check merely by
// wrapping it in some arbitrary caller-defined string-kind type (e.g.
// `type EvilString string`). Only kind-string values that are exactly
// redact.Redacted or a member of exemptEnumTypes are captured data made
// safe; anything else is captured data that hasn't been redacted.
func checkEventData(v reflect.Value) error {
	if !v.IsValid() {
		return nil
	}
	switch v.Kind() {
	case reflect.String:
		if v.Type() == redactedType {
			return nil
		}
		if exemptEnumTypes[v.Type()] {
			return nil
		}
		return ErrRawString
	case reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return checkEventData(v.Elem())
	case reflect.Ptr:
		if v.IsNil() {
			return nil
		}
		return checkEventData(v.Elem())
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return nil // []byte / [N]byte
		}
		for i := 0; i < v.Len(); i++ {
			if err := checkEventData(v.Index(i)); err != nil {
				return err
			}
		}
		return nil
	case reflect.Map:
		// Map KEYS are structural (field names, not captured operator- or
		// agent-controlled content) and are exempt from the raw-string
		// ban; only values are checked. This mirrors the top-level Data
		// map itself, whose string keys ("path", "argv", ...) are Go field
		// names, not data.
		iter := v.MapRange()
		for iter.Next() {
			if err := checkEventData(iter.Value()); err != nil {
				return err
			}
		}
		return nil
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			if err := checkEventData(v.Field(i)); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}
