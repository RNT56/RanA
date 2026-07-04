package exportverify

import "testing"

// FuzzVerifyExportFiles drives arbitrary bytes into every artifact slot of the
// independent verifier. The property is total safety: the verifier must return
// a Result (OK / BROKEN / INCOMPLETE) for ANY input and never panic — a
// hostile .ranaproof must not be able to crash the WASM/browser or CLI
// verifier. This is the continuous-fuzz guard for the integer-overflow-safe
// uvarint/length parsing (splitCheckpointRecord, readUvarintPrefixedRecords)
// that adversarial unit tests pin at specific boundaries.
func FuzzVerifyExportFiles(f *testing.F) {
	// Seeds: empty, minimal-JSON manifest, and a few bytes in each slot.
	f.Add([]byte("{}"), []byte{}, []byte{}, []byte{})
	f.Add([]byte(`{"format_version":1}`), []byte{0x00}, []byte{0xff, 0xff}, []byte{0x81})
	f.Add([]byte{}, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, manifest, events, segments, checkpoints []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("VerifyExportFiles panicked on fuzz input: %v", r)
			}
		}()
		// A pubkey.pem slot is included but left empty; the verifier must
		// handle a missing/empty key as INCOMPLETE, not a panic.
		_ = VerifyExportFiles(map[string][]byte{
			FileManifest:   manifest,
			FileEvents:     events,
			FileSegments:   segments,
			FileCheckpoint: checkpoints,
		})
	})
}
