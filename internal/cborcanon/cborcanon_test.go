package cborcanon_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"testing"
	"testing/quick"

	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// --- golden hex vectors (RFC 8949 Appendix A examples + one full event) ---

func TestEncode_GoldenVectors(t *testing.T) {
	tests := []struct {
		name string
		in   any
		hex  string
	}{
		{"uint 0", uint64(0), "00"},
		{"uint 1", uint64(1), "01"},
		{"uint 10", uint64(10), "0a"},
		{"uint 23", uint64(23), "17"},
		{"uint 24", uint64(24), "1818"},
		{"uint 25", uint64(25), "1819"},
		{"uint 100", uint64(100), "1864"},
		{"uint 1000", uint64(1000), "1903e8"},
		{"uint 1000000", uint64(1000000), "1a000f4240"},
		{"negative -1", int64(-1), "20"},
		{"negative -10", int64(-10), "29"},
		{"negative -100", int64(-100), "3863"},
		{"bool false", false, "f4"},
		{"bool true", true, "f5"},
		{"nil", nil, "f6"},
		{"empty bstr", []byte{}, "40"},
		{"bstr 01020304", []byte{0x01, 0x02, 0x03, 0x04}, "4401020304"},
		{"empty tstr", "", "60"},
		{"tstr a", "a", "6161"},
		{"tstr IETF", "IETF", "6449455446"},
		{"empty array", []any{}, "80"},
		{"array 1,2,3", []any{uint64(1), uint64(2), uint64(3)}, "83010203"},
		{
			"map sorted bytewise",
			map[string]any{"b": uint64(2), "a": uint64(1)},
			"a2616101616202", // {"a":1,"b":2} — bytewise-sorted keys
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cborcanon.Encode(tt.in)
			if err != nil {
				t.Fatalf("Encode(%#v) error: %v", tt.in, err)
			}
			want, err := hex.DecodeString(tt.hex)
			if err != nil {
				t.Fatalf("bad test hex: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Encode(%#v) = %x, want %x", tt.in, got, want)
			}
		})
	}
}

func TestEncode_FullEventGolden(t *testing.T) {
	ev := schema.Event{
		V:       1,
		Type:    schema.EventTypeSessionStart,
		Session: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Seg:     0,
		Idx:     0,
		TsMono:  1000,
		TsWall:  2000,
		Pid:     42,
		Origin:  schema.OriginSVC,
		State:   schema.StateObserved,
		Data: map[string]any{
			"profile": redact.Literal("generic"),
		},
	}
	got, err := cborcanon.EncodeEvent(ev)
	if err != nil {
		t.Fatalf("EncodeEvent error: %v", err)
	}
	// Also assert canonical bytewise key ordering explicitly via
	// IsCanonical, independent of the pinned hex below.
	ok, err := cborcanon.IsCanonical(got)
	if err != nil {
		t.Fatalf("IsCanonical error: %v", err)
	}
	if !ok {
		t.Fatalf("full event encoding is not canonical")
	}

	// Golden byte-exact regression: any encoder drift (field set, key
	// order, integer width) is caught by this pinned hex.
	want := "ab617601636964780063706964182a63736567006464617461a16770726f66696c656767656e6572696364747970656d73657373696f6e2e7374617274657374617465686f62736572766564666f726967696e637376636773657373696f6e781a303141525a334e44454b545356345252464651363947354641566774735f6d6f6e6f1903e86774735f77616c6c1907d0"
	gotHex := hex.EncodeToString(got)
	if gotHex != want {
		t.Fatalf("golden event encoding mismatch:\ngot:  %s\nwant: %s", gotHex, want)
	}
}

// --- IsCanonical ---

func TestIsCanonical(t *testing.T) {
	canon, err := cborcanon.Encode(map[string]any{"a": uint64(1), "b": uint64(2)})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := cborcanon.IsCanonical(canon)
	if err != nil || !ok {
		t.Fatalf("expected canonical, got ok=%v err=%v", ok, err)
	}

	// A non-canonical encoding: map with keys out of bytewise order.
	// {"b":2,"a":1} in raw CBOR bytes (major type 5, 2 pairs, unsorted).
	nonCanon, err := hex.DecodeString("a2616202616101")
	if err != nil {
		t.Fatal(err)
	}
	ok, err = cborcanon.IsCanonical(nonCanon)
	if err != nil {
		t.Fatalf("IsCanonical should not error on well-formed non-canonical input: %v", err)
	}
	if ok {
		t.Fatalf("expected non-canonical input to be reported as non-canonical")
	}
}

func TestIsCanonical_Malformed(t *testing.T) {
	_, err := cborcanon.IsCanonical([]byte{0xff, 0xff, 0xff})
	if err == nil {
		t.Fatalf("expected error decoding malformed bytes")
	}
}

// --- float rejection ---

func TestEncode_RejectsFloats(t *testing.T) {
	cases := []any{
		float64(1.5),
		float32(1.5),
		map[string]any{"x": float64(1.0)},
		[]any{float64(2.0)},
		struct{ F float64 }{F: 1.0},
	}
	for _, c := range cases {
		_, err := cborcanon.Encode(c)
		if err == nil {
			t.Fatalf("Encode(%#v) expected float-rejection error, got nil", c)
		}
	}
	// NaN/Inf too, even though they're floats caught by the same rule.
	_, err := cborcanon.Encode(math.NaN())
	if err == nil {
		t.Fatalf("expected error encoding NaN")
	}
}

// --- ErrRawString / EncodeEvent enforcement ---

func TestEncodeEvent_RejectsRawStringInData(t *testing.T) {
	ev := schema.Event{
		V:       1,
		Type:    schema.EventTypeSessionStart,
		Session: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Origin:  schema.OriginSVC,
		State:   schema.StateObserved,
		Data: map[string]any{
			"profile": "generic", // plain string — must be rejected
		},
	}
	_, err := cborcanon.EncodeEvent(ev)
	if !errors.Is(err, cborcanon.ErrRawString) {
		t.Fatalf("expected ErrRawString, got %v", err)
	}
}

func TestEncodeEvent_RejectsRawStringNestedInData(t *testing.T) {
	ev := schema.Event{
		V:       1,
		Type:    schema.EventTypeSessionStart,
		Session: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Origin:  schema.OriginSVC,
		State:   schema.StateObserved,
		Data: map[string]any{
			"host": map[string]any{
				"os": "linux", // nested raw string — must also be rejected
			},
		},
	}
	_, err := cborcanon.EncodeEvent(ev)
	if !errors.Is(err, cborcanon.ErrRawString) {
		t.Fatalf("expected ErrRawString for nested raw string, got %v", err)
	}
}

func TestEncodeEvent_RejectsRawStringInSlice(t *testing.T) {
	ev := schema.Event{
		V:       1,
		Type:    schema.EventTypeProcExec,
		Session: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Origin:  schema.OriginKernel,
		State:   schema.StateObserved,
		Data: map[string]any{
			"argv": []any{"raw", "strings"}, // plain strings inside a slice
		},
	}
	_, err := cborcanon.EncodeEvent(ev)
	if !errors.Is(err, cborcanon.ErrRawString) {
		t.Fatalf("expected ErrRawString for raw strings in slice, got %v", err)
	}
}

func TestEncodeEvent_AcceptsRedactedAndLiteral(t *testing.T) {
	ev := schema.Event{
		V:       1,
		Type:    schema.EventTypeSessionStart,
		Session: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Origin:  schema.OriginSVC,
		State:   schema.StateObserved,
		Data: map[string]any{
			"profile": redact.Literal("generic"),
			"argv":    []redact.Redacted{redact.Literal("run"), redact.Literal("--flag")},
		},
	}
	b, err := cborcanon.EncodeEvent(ev)
	if err != nil {
		t.Fatalf("EncodeEvent with Redacted values should succeed, got: %v", err)
	}
	if len(b) == 0 {
		t.Fatalf("expected non-empty output")
	}
}

// arbitraryStringType stands in for any locally-defined named string-kind
// type that is NOT part of schema's frozen enum vocabulary and NOT
// redact.Redacted — e.g. a type a future contributor defines by accident or
// habit ("type Foo string") in some other package and passes into Data
// without redacting. P3 requires this be rejected exactly like a plain
// string: named-string-kind is not, by itself, a redaction guarantee.
type arbitraryStringType string

func TestEncodeEvent_RejectsArbitraryNamedStringType(t *testing.T) {
	ev := schema.Event{
		V:       1,
		Type:    schema.EventTypeSessionStart,
		Session: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Origin:  schema.OriginSVC,
		State:   schema.StateObserved,
		Data: map[string]any{
			"profile": arbitraryStringType("not-a-redacted-value"), // wrong string type; must be rejected regardless of content
		},
	}
	b, err := cborcanon.EncodeEvent(ev)
	if !errors.Is(err, cborcanon.ErrRawString) {
		t.Fatalf("expected ErrRawString rejecting an arbitrary named string-kind type, got err=%v b=%x", err, b)
	}
}

func TestEncodeEvent_RejectsArbitraryNamedStringTypeNestedInSlice(t *testing.T) {
	ev := schema.Event{
		V:       1,
		Type:    schema.EventTypeProcExec,
		Session: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Origin:  schema.OriginKernel,
		State:   schema.StateObserved,
		Data: map[string]any{
			"argv": []any{arbitraryStringType("sk-liveSECRETVALUE1234567890")},
		},
	}
	_, err := cborcanon.EncodeEvent(ev)
	if !errors.Is(err, cborcanon.ErrRawString) {
		t.Fatalf("expected ErrRawString for arbitrary named string type nested in slice, got %v", err)
	}
}

func TestEncodeEvent_AcceptsTypedEnumConstants(t *testing.T) {
	ev := schema.Event{
		V:       1,
		Type:    schema.EventTypeFsWriteOpen,
		Session: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Origin:  schema.OriginKernel,
		State:   schema.StateObserved,
		Data: map[string]any{
			"path":        redact.Literal("/tmp/x"),
			"path_source": schema.PathSourceResolved, // typed enum constant, not plain string
			"flags":       uint64(0),
			"mode":        uint64(0),
		},
	}
	_, err := cborcanon.EncodeEvent(ev)
	if err != nil {
		t.Fatalf("EncodeEvent with typed enum constant should succeed: %v", err)
	}
}

// --- timestamps are uint64 ns ---

func TestEncodeEvent_TimestampsAreUnsigned(t *testing.T) {
	ev := schema.Event{
		V:       1,
		Type:    schema.EventTypeSessionStart,
		Session: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		TsMono:  123456789,
		TsWall:  987654321,
		Origin:  schema.OriginSVC,
		State:   schema.StateObserved,
		Data:    map[string]any{},
	}
	b, err := cborcanon.EncodeEvent(ev)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := cborcanon.Decode(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["ts_mono"].(uint64); !ok {
		t.Fatalf("ts_mono not decoded as uint64: %T %v", m["ts_mono"], m["ts_mono"])
	}
	if _, ok := m["ts_wall"].(uint64); !ok {
		t.Fatalf("ts_wall not decoded as uint64: %T %v", m["ts_wall"], m["ts_wall"])
	}
}

// --- Decode strictness (unknown fields rejected for struct-typed targets) ---

type strictTarget struct {
	A uint64 `cbor:"a"`
	B uint64 `cbor:"b"`
}

func TestDecode_RejectsUnknownFieldsForStructs(t *testing.T) {
	b, err := cborcanon.Encode(map[string]any{"a": uint64(1), "b": uint64(2), "c": uint64(3)})
	if err != nil {
		t.Fatal(err)
	}
	var target strictTarget
	if err := cborcanon.Decode(b, &target); err == nil {
		t.Fatalf("expected error decoding unknown field 'c' into struct without that field")
	}
}

func TestDecode_AllowsKnownFields(t *testing.T) {
	b, err := cborcanon.Encode(map[string]any{"a": uint64(1), "b": uint64(2)})
	if err != nil {
		t.Fatal(err)
	}
	var target strictTarget
	if err := cborcanon.Decode(b, &target); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.A != 1 || target.B != 2 {
		t.Fatalf("got %+v", target)
	}
}

// --- round-trip property tests ---

func TestRoundTrip_Property(t *testing.T) {
	f := func(a uint64, b int32, s bool, blob []byte) bool {
		in := map[string]any{
			"u": a,
			"i": int64(b),
			"b": s,
			"x": blob,
		}
		enc, err := cborcanon.Encode(in)
		if err != nil {
			return false
		}
		var out map[string]any
		if err := cborcanon.Decode(enc, &out); err != nil {
			return false
		}
		enc2, err := cborcanon.Encode(out)
		if err != nil {
			return false
		}
		return bytes.Equal(enc, enc2)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}

func TestRoundTrip_Idempotent(t *testing.T) {
	in := map[string]any{
		"nested": map[string]any{
			"deep": []any{uint64(1), uint64(2), []byte{0xaa, 0xbb}},
		},
		"z": uint64(0),
		"a": uint64(0),
	}
	b1, err := cborcanon.Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	var mid map[string]any
	if err := cborcanon.Decode(b1, &mid); err != nil {
		t.Fatal(err)
	}
	b2, err := cborcanon.Encode(mid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("round trip not byte-identical:\n%x\n%x", b1, b2)
	}
	ok, err := cborcanon.IsCanonical(b1)
	if err != nil || !ok {
		t.Fatalf("expected canonical: ok=%v err=%v", ok, err)
	}
}

// --- rejects chan/func ---

func TestEncode_RejectsUnencodableKinds(t *testing.T) {
	cases := []any{
		make(chan int),
		func() {},
	}
	for _, c := range cases {
		if _, err := cborcanon.Encode(c); err == nil {
			t.Fatalf("Encode(%#v) expected error, got nil", c)
		}
	}
}

// --- fuzz ---

func FuzzDecodeEncode(f *testing.F) {
	seed, _ := cborcanon.Encode(map[string]any{"a": uint64(1), "b": []byte{1, 2, 3}})
	f.Add(seed)
	f.Add([]byte{0x00})
	f.Add([]byte{0xa1, 0x61, 0x61, 0x01})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		var v any
		err := cborcanon.Decode(data, &v)
		if err != nil {
			return // garbage input rejected is fine; must not panic
		}
		// If it decoded, re-encoding it must not panic either.
		_, _ = cborcanon.Encode(v)
	})
}
