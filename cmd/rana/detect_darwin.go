//go:build darwin

package main

import (
	"os/exec"
	"strconv"
	"strings"
)

// listRunningProcesses (darwin) shells out to `ps -axo pid=,comm=,args=` —
// there is no /proc on macOS, and reading another process's environment
// would require entitlements RanA does not have (and would violate P3 even
// if it could: this only ever reads comm/args, never environment). Each
// output line is "<pid> <comm> <args...>"; args is the full command line,
// split on whitespace for a best-effort argv approximation (a convenience
// match, not exact argv reconstruction — quoted arguments with embedded
// spaces are not perfectly recoverable from `ps` output, which is
// acceptable for [match]'s "convenience, not attribution" role,
// docs/PROFILES.md).
func listRunningProcesses() ([]runningProcess, error) {
	out, err := exec.Command("ps", "-axo", "pid=,comm=,args=").Output()
	if err != nil {
		return nil, err
	}

	var procs []runningProcess
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		comm := fields[1]
		var argv []string
		if len(fields) > 2 {
			argv = fields[2:]
		} else {
			argv = []string{comm}
		}
		procs = append(procs, runningProcess{Pid: pid, ExePath: comm, Argv: argv})
	}
	return procs, nil
}
