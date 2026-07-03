package session

import (
	"bytes"
	"errors"
	"strings"
)

// ErrCgroupEventsMissingPopulated is returned by isCgroupPopulated when the
// input does not contain a "populated" field, i.e. it is not a
// well-formed cgroup.events file.
var ErrCgroupEventsMissingPopulated = errors.New("session: cgroup.events missing populated field")

// isCgroupPopulated parses a cgroup.events file's contents (the Linux
// kernel's cgroup v2 "populated 0|1" / "frozen 0|1" format) and reports
// whether the "populated" field reads 1 (the cgroup has member
// processes). This is pure parsing logic with no syscalls, kept portable
// so it is fully unit-testable on darwin; the linux-only inotify plumbing
// that reads the real file lives in cgroup_watch_linux.go.
func isCgroupPopulated(data []byte) (bool, error) {
	for _, line := range bytes.Split(data, []byte("\n")) {
		fields := strings.Fields(string(line))
		if len(fields) != 2 || fields[0] != "populated" {
			continue
		}
		return fields[1] == "1", nil
	}
	return false, ErrCgroupEventsMissingPopulated
}
