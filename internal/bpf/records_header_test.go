package bpf

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// This file cross-checks bpf/src/records.h (the C mirror of records.md)
// against records.md and internal/collector/records.go by parsing the
// header text directly — clang cannot run inside `go test` per
// CONTRACTS §internal/bpf ("do NOT attempt clang compilation as part of
// `go test`"), so this is a textual, not a compiled, cross-check. It
// still catches the failure mode that matters: someone editing
// records.h's kind/version/capacity constants without updating
// records.md or records.go in lockstep.

func readRecordsHeader(t *testing.T) string {
	t.Helper()
	// internal/bpf -> ../../bpf/src/records.h
	path := filepath.Join("..", "..", "bpf", "src", "records.h")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading bpf/src/records.h: %v", err)
	}
	return string(b)
}

// TestRecordsHeaderVersionMatchesDoc asserts RANA_RECORD_VERSION in the C
// header equals the version records.md and records.go declare (1, "all
// kinds below are version 1").
func TestRecordsHeaderVersionMatchesDoc(t *testing.T) {
	src := readRecordsHeader(t)
	re := regexp.MustCompile(`#define\s+RANA_RECORD_VERSION\s+(\d+)`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("RANA_RECORD_VERSION not found in records.h")
	}
	got, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parsing RANA_RECORD_VERSION: %v", err)
	}
	if got != 1 {
		t.Errorf("records.h RANA_RECORD_VERSION = %d, records.md says version 1 for all kinds", got)
	}
}

// TestRecordsHeaderKindsMatchDoc asserts every RANA_KIND_* constant in
// records.h matches records.md's "Record kind registry" table exactly.
func TestRecordsHeaderKindsMatchDoc(t *testing.T) {
	src := readRecordsHeader(t)
	want := map[string]int{
		"RANA_KIND_EXEC":        1,
		"RANA_KIND_FORK":        2,
		"RANA_KIND_EXIT":        3,
		"RANA_KIND_FSOP":        4,
		"RANA_KIND_CONNECT":     5,
		"RANA_KIND_SENDMSG":     6,
		"RANA_KIND_UNIXCONNECT": 7,
		"RANA_KIND_FLOWCLOSE":   8,
		"RANA_KIND_DNS":         9,
		"RANA_KIND_MIGRATION":   10,
	}
	for name, wantVal := range want {
		re := regexp.MustCompile(`#define\s+` + regexp.QuoteMeta(name) + `\s+(\d+)`)
		m := re.FindStringSubmatch(src)
		if m == nil {
			t.Errorf("%s not found in records.h", name)
			continue
		}
		got, err := strconv.Atoi(m[1])
		if err != nil {
			t.Errorf("parsing %s: %v", name, err)
			continue
		}
		if got != wantVal {
			t.Errorf("records.h %s = %d, records.md says %d", name, got, wantVal)
		}
	}
}

// TestRecordsHeaderCapsMatchDoc asserts every RANA_CAP_* constant in
// records.h matches the field capacities records.md declares (and that
// internal/collector's unexported cap* constants were written against,
// per that package's doc comment).
func TestRecordsHeaderCapsMatchDoc(t *testing.T) {
	src := readRecordsHeader(t)
	want := map[string]int{
		"RANA_CAP_EXEC_COMM":        16,
		"RANA_CAP_EXEC_EXEPATH":     1024,
		"RANA_CAP_EXEC_CWD":         1024,
		"RANA_CAP_EXEC_ARGV":        6144,
		"RANA_CAP_FSOP_PATH":        2048,
		"RANA_CAP_FSOP_PATH2":       2048,
		"RANA_CAP_UNIXCONNECT_PATH": 4096,
		"RANA_CAP_DNS_QNAME":        255,
		"RANA_CAP_DNS_ANSWERS":      4,
	}
	for name, wantVal := range want {
		re := regexp.MustCompile(`#define\s+` + regexp.QuoteMeta(name) + `\s+(\d+)`)
		m := re.FindStringSubmatch(src)
		if m == nil {
			t.Errorf("%s not found in records.h", name)
			continue
		}
		got, err := strconv.Atoi(m[1])
		if err != nil {
			t.Errorf("parsing %s: %v", name, err)
			continue
		}
		if got != wantVal {
			t.Errorf("records.h %s = %d, records.md/collector says %d", name, got, wantVal)
		}
	}
}

// TestRecordsHeaderFsOpAndPathSourceMatchDoc cross-checks the FsOp
// sub-type and PathSource enum values against records.md §4 and
// internal/collector's FsOp/PathSourceKind constants.
func TestRecordsHeaderFsOpAndPathSourceMatchDoc(t *testing.T) {
	src := readRecordsHeader(t)
	want := map[string]int{
		"RANA_FSOP_WRITE_OPEN":      1,
		"RANA_FSOP_UNLINK":          2,
		"RANA_FSOP_RENAME":          3,
		"RANA_FSOP_MKDIR":           4,
		"RANA_FSOP_CHMOD":           5,
		"RANA_FSOP_TRUNCATE":        6,
		"RANA_PATH_SOURCE_RESOLVED": 0,
		"RANA_PATH_SOURCE_CLAIMED":  1,
	}
	for name, wantVal := range want {
		re := regexp.MustCompile(`#define\s+` + regexp.QuoteMeta(name) + `\s+(\d+)`)
		m := re.FindStringSubmatch(src)
		if m == nil {
			t.Errorf("%s not found in records.h", name)
			continue
		}
		got, err := strconv.Atoi(m[1])
		if err != nil {
			t.Errorf("parsing %s: %v", name, err)
			continue
		}
		if got != wantVal {
			t.Errorf("records.h %s = %d, records.md says %d", name, got, wantVal)
		}
	}
}

// TestRecordsHeaderStructsExist is a minimal smoke check that every
// record struct records.md documents has a matching declaration in
// records.h, by name. This does not validate field-by-field offsets
// (that requires a real compiler, deliberately out of scope for `go
// test` per CONTRACTS) but does catch a struct being renamed or dropped
// without the Go side noticing.
func TestRecordsHeaderStructsExist(t *testing.T) {
	src := readRecordsHeader(t)
	structs := []string{
		"struct rana_exec_record",
		"struct rana_fork_record",
		"struct rana_exit_record",
		"struct rana_fsop_record",
		"struct rana_connect_record",
		"struct rana_unix_connect_record",
		"struct rana_flow_close_record",
		"struct rana_dns_record",
		"struct rana_migration_record",
	}
	for _, s := range structs {
		if !regexp.MustCompile(regexp.QuoteMeta(s) + `\s*\{`).MatchString(src) {
			t.Errorf("records.h missing expected declaration: %s", s)
		}
	}
}
