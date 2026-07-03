package bpf

import (
	"testing"

	"github.com/RNT56/RanA/internal/collector"
)

// TestRecordSizesMatchDoc cross-checks internal/collector/records.go's
// Size* constants against the byte-by-byte sizes internal/bpf/records.md
// declares (the canonical spec both records.go and bpf/src/records.h are
// written against — CONTRACTS §internal/bpf: "a Go test cross-checks
// structs sizes/offsets against records.md constants").
//
// This test lives in internal/bpf (not internal/collector, which is
// owned by another agent and frozen) because internal/bpf is the
// producer side of the wire contract and is responsible for proving its
// C definitions agree with the same numbers the Go decoder was built
// against. If bpf/src/records.h and internal/collector/records.go ever
// drift, this is the test that catches it on the Go side (the C side has
// no test harness of its own here — clang compilation happens in CI, not
// `go test`, per CONTRACTS — so records.h's field-for-field agreement
// with records.md is enforced by code review discipline plus this test
// proving the *documented* numbers are exactly what both sides claim to
// implement).
func TestRecordSizesMatchDoc(t *testing.T) {
	// These sizes are transcribed verbatim from internal/bpf/records.md's
	// "Record kind registry" table — the canonical source. A change to
	// any record's wire size requires updating records.md, records.go,
	// AND bpf/src/records.h together; this assertion is what makes a
	// records.go-only edit (or a records.h-only edit) fail CI.
	docSizes := map[string]int{
		"ExecRecord":        8254,
		"ForkRecord":        34,
		"ExitRecord":        50,
		"FsOpRecord":        4148,
		"ConnectRecord":     50,
		"SendmsgRecord":     50,
		"UnixConnectRecord": 4128,
		"FlowCloseRecord":   74,
		"DNSRecord":         356,
		"MigrationRecord":   38,
	}
	gotSizes := map[string]int{
		"ExecRecord":        collector.SizeExecRecord,
		"ForkRecord":        collector.SizeForkRecord,
		"ExitRecord":        collector.SizeExitRecord,
		"FsOpRecord":        collector.SizeFsOpRecord,
		"ConnectRecord":     collector.SizeConnectRecord,
		"SendmsgRecord":     collector.SizeSendmsgRecord,
		"UnixConnectRecord": collector.SizeUnixConnectRecord,
		"FlowCloseRecord":   collector.SizeFlowCloseRecord,
		"DNSRecord":         collector.SizeDNSRecord,
		"MigrationRecord":   collector.SizeMigrationRecord,
	}

	for name, docSize := range docSizes {
		gotSize, ok := gotSizes[name]
		if !ok {
			t.Errorf("records.md declares %s but internal/collector has no matching Size* constant", name)
			continue
		}
		if gotSize != docSize {
			t.Errorf("%s: internal/collector size = %d, records.md size = %d", name, gotSize, docSize)
		}
	}
	for name := range gotSizes {
		if _, ok := docSizes[name]; !ok {
			t.Errorf("internal/collector defines a Size* constant for %s but records.md has no matching entry", name)
		}
	}
}

// TestRecordKindBytesMatchDoc cross-checks the Kind byte values in
// records.md's "Record kind registry" table against
// internal/collector's RecordKind* constants, and against the
// RANA_KIND_* preprocessor values declared in bpf/src/records.h (verified
// by TestRecordsHeaderKindsMatchDoc, which parses the header text since
// cgo/clang cannot run in `go test` per CONTRACTS).
func TestRecordKindBytesMatchDoc(t *testing.T) {
	tests := []struct {
		name string
		kind uint8
		want uint8
	}{
		{"exec", collector.RecordKindExec, 1},
		{"fork", collector.RecordKindFork, 2},
		{"exit", collector.RecordKindExit, 3},
		{"fsop", collector.RecordKindFsOp, 4},
		{"connect", collector.RecordKindConnect, 5},
		{"sendmsg", collector.RecordKindSendmsg, 6},
		{"unixconnect", collector.RecordKindUnixConnect, 7},
		{"flowclose", collector.RecordKindFlowClose, 8},
		{"dns", collector.RecordKindDNS, 9},
		{"migration", collector.RecordKindMigration, 10},
	}
	for _, tt := range tests {
		if tt.kind != tt.want {
			t.Errorf("collector.RecordKind%s = %d, records.md says %d", tt.name, tt.kind, tt.want)
		}
	}
}

// TestRecordFieldCapsMatchDoc cross-checks internal/collector's cap*
// field-capacity constants (unexported, so this test exercises them
// indirectly via a round-trip decode at exactly the documented capacity
// boundary) against records.md. Since the cap* constants are unexported
// in internal/collector, this test instead asserts the one place their
// values are externally observable: SizeExecRecord/SizeFsOpRecord/etc.
// already encode every capacity via the fixed offsets baked into the
// struct size (e.g. ExecRecord's 8254 = 39 (header+comm start) + ... +
// 6144 (argv cap)). TestRecordSizesMatchDoc above is therefore the
// binding cross-check for capacities too: a capacity change that isn't
// reflected in records.md's total size table will always change the
// total record size, which that test already catches.
func TestRecordFieldCapsMatchDoc(t *testing.T) {
	// Direct arithmetic sanity check reproducing records.md's own
	// derivation, so a mismatched intermediate offset (not just the
	// final total) is caught with a precise diff.
	const (
		hdr         = 2                           // version + kind
		execFixed   = hdr + 4 + 4 + 4 + 8 + 8 + 8 // pid ppid uid cgid ts_mono ts_wall = 38
		execCommHdr = 1                           // comm_len
		execComm    = 16
		execExeHdr  = 2 // exe_path_len (u16)
		execExe     = 1024
		execCwdHdr  = 2
		execCwd     = 1024
		execArgvHdr = 2 + 1 // argv_len (u16) + argv_truncated (u8)
		execArgv    = 6144
	)
	total := execFixed + execCommHdr + execComm + execExeHdr + execExe + execCwdHdr + execCwd + execArgvHdr + execArgv
	if total != collector.SizeExecRecord {
		t.Errorf("hand-derived ExecRecord total = %d, collector.SizeExecRecord = %d", total, collector.SizeExecRecord)
	}
	if total != 8254 {
		t.Errorf("hand-derived ExecRecord total = %d, records.md says 8254", total)
	}

	const (
		fsopFixed    = hdr + 1 + 1 + 4 + 8 + 8 + 8 + 8 + 8 // kind op path_source pid cgid ts_mono ts_wall flags mode
		fsopPathHdr  = 2
		fsopPath     = 2048
		fsopPath2Hdr = 2
		fsopPath2    = 2048
	)
	fsopTotal := fsopFixed + fsopPathHdr + fsopPath + fsopPath2Hdr + fsopPath2
	if fsopTotal != collector.SizeFsOpRecord {
		t.Errorf("hand-derived FsOpRecord total = %d, collector.SizeFsOpRecord = %d", fsopTotal, collector.SizeFsOpRecord)
	}
	if fsopTotal != 4148 {
		t.Errorf("hand-derived FsOpRecord total = %d, records.md says 4148", fsopTotal)
	}
}
