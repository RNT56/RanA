package chain

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// HeadReport is a single line of the head mirror (docs/TRUST.md §5, plan
// D27): at each checkpoint, the session service reports
// (session_id, seg_range.last, chain_head) to ranad, which appends it to
// a root-owned, append-only heads.log. Reports mirrored before a same-uid
// compromise are pinned beyond the compromised uid's reach; `rana verify
// --mirror` cross-checks the live ledger's checkpoints against this file.
type HeadReport struct {
	SessionID string   `json:"session_id"`
	SegLast   uint64   `json:"seg_last"`
	ChainHead [32]byte `json:"chain_head"`
	CkptHash  [32]byte `json:"ckpt_hash"`
	At        uint64   `json:"at"` // ns, wall clock at time of report
}

// AppendHead appends r to path as a single line of JSON, opening with
// O_APPEND so the write can never truncate existing content (CONTRACTS
// §internal/chain: "O_APPEND single-line JSON; never truncates" — this is
// the property D27's custody guarantee depends on: reports written before
// a compromise must remain even if the writer is later subverted). Creates
// path (and nothing else — parent directories must already exist) if it
// does not exist yet.
func AppendHead(path string, r HeadReport) error {
	line, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("chain: marshaling head report: %w", err)
	}
	line = append(line, '\n')

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("chain: opening %s for append: %w", path, err)
	}
	defer f.Close()

	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("chain: appending head report to %s: %w", path, err)
	}
	return f.Close()
}

// ReadHeads reads every HeadReport line from path, in file order.
//
// A missing file is not an error — it reads as zero reports, since a
// fresh install has no mirror yet.
//
// Corruption tolerance: if the LAST line in the file is not valid,
// complete JSON, it is treated as a torn write (the process died mid
// AppendHead) and silently skipped rather than failing the whole read —
// consistent with "losses are loud but honest, not fatal" (P5) applied to
// the mirror's own durability. Any malformed line that is NOT the last
// line is a harder error: it cannot be explained by an in-progress write
// and indicates the mirror itself may be corrupted, which callers (rana
// verify --mirror) need to know about rather than silently skip.
func ReadHeads(path string) ([]HeadReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("chain: reading %s: %w", path, err)
	}

	lines := splitNonEmptyLines(raw)
	if len(lines) == 0 {
		return nil, nil
	}

	reports := make([]HeadReport, 0, len(lines))
	for i, line := range lines {
		var r HeadReport
		if err := json.Unmarshal(line, &r); err != nil {
			if i == len(lines)-1 {
				// Torn last line: tolerate it (skip), per corruption-tolerant
				// read contract.
				break
			}
			return nil, fmt.Errorf("chain: %s: malformed head report on line %d: %w", path, i+1, err)
		}
		reports = append(reports, r)
	}

	return reports, nil
}

// splitNonEmptyLines splits raw on '\n', dropping a trailing empty segment
// (the normal case: file ends with a newline) but preserving a genuinely
// non-newline-terminated final segment (the torn-write case ReadHeads must
// detect and skip).
func splitNonEmptyLines(raw []byte) [][]byte {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var lines [][]byte
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		lines = append(lines, cp)
	}
	// bufio.Scanner's default split function (ScanLines) already returns a
	// final non-newline-terminated segment as its own token, which is
	// exactly the torn-write case we want to see as the "last line".
	return lines
}
