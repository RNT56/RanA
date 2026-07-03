package ledger

import (
	"encoding/json"
	"fmt"
)

// copyGapCounts returns a defensive copy of m so mutation of the writer's
// in-memory accumulator after sealing can never retroactively change a
// header already handed to chain.SegHash.
func copyGapCounts(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// marshalGapSummary encodes a segment's gap-reason counts for the
// segments.gap column. This is a storage convenience (JSON, human
// legible in ad hoc inspection) distinct from the canonical CBOR
// gap_summary embedded in the segment header bytes that are actually
// hashed/signed — the header BLOB column is the load-bearing copy.
func marshalGapSummary(m map[string]uint64) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("ledger: marshaling gap summary: %w", err)
	}
	return b, nil
}
