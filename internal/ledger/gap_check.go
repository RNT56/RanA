package ledger

import (
	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/schema"
)

// gapCountsFromEvents tallies a segment's `gap` events by reason, decoding
// each event from its authoritative canonical bytes (the exact bytes hashed
// into its leaf) — never from the mutable, unhashed events.type mirror
// column. The result must equal the segment header's gap_summary
// (docs/TRUST.md §4, P5: "losses are loud"). Decoding into map[string]any
// (rather than a struct) deliberately sidesteps cborcanon's strict
// unknown-field rejection so any event type decodes here.
func gapCountsFromEvents(evs [][]byte) (map[string]uint64, error) {
	out := map[string]uint64{}
	for _, enc := range evs {
		var env map[string]any
		if err := cborcanon.Decode(enc, &env); err != nil {
			return nil, err
		}
		t, _ := env["type"].(string)
		if t != string(schema.EventTypeGap) {
			continue
		}
		reason, _ := mapGet(env["data"], "reason").(string)
		out[reason]++
	}
	return out, nil
}

// mapGet reads key from a CBOR-decoded map value that may be either
// map[string]any (top level) or map[interface{}]interface{} (nested, the
// fxamacker default when no DefaultMapType is set).
func mapGet(m any, key string) any {
	switch mm := m.(type) {
	case map[string]any:
		return mm[key]
	case map[interface{}]interface{}:
		return mm[key]
	default:
		return nil
	}
}

// gapTotal sums the counts across all reasons.
func gapTotal(m map[string]uint64) uint64 {
	var n uint64
	for _, v := range m {
		n += v
	}
	return n
}

// gapCountsEqual compares two gap tallies, treating a nil map, an empty map,
// and a map with only zero-valued entries as all equal (the writer only ever
// records non-zero counts, so this normalizes header representations).
func gapCountsEqual(a, b map[string]uint64) bool {
	nonZero := func(m map[string]uint64) map[string]uint64 {
		out := map[string]uint64{}
		for k, v := range m {
			if v != 0 {
				out[k] = v
			}
		}
		return out
	}
	x, y := nonZero(a), nonZero(b)
	if len(x) != len(y) {
		return false
	}
	for k, v := range x {
		if y[k] != v {
			return false
		}
	}
	return true
}
