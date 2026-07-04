//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// listRunningProcesses (Linux) enumerates /proc/<pid>/{comm,cmdline} for
// every numeric pid directory. It reads exactly two files per process —
// comm (the kernel-truth executable basename) and cmdline (the NUL-joined
// argv) — and NEVER /proc/<pid>/environ, per P3 ("envp/environ MUST NOT be
// read anywhere"). A process that has exited or is unreadable (permission,
// race with exit) between the readdir and the read is silently skipped:
// this is a best-effort convenience scan, not a security boundary, and a
// racy /proc is expected, not exceptional.
func listRunningProcesses() ([]runningProcess, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var out []runningProcess
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue // not a pid directory
		}

		commBytes, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue // exited/unreadable — skip
		}
		comm := strings.TrimSuffix(string(commBytes), "\n")

		cmdlineBytes, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		var argv []string
		if err == nil && len(cmdlineBytes) > 0 {
			for _, part := range strings.Split(strings.TrimRight(string(cmdlineBytes), "\x00"), "\x00") {
				if part != "" {
					argv = append(argv, part)
				}
			}
		}

		exePath := comm
		if len(argv) > 0 && argv[0] != "" {
			// argv[0] is a closer approximation of the invoked path
			// (comm is truncated to 15 bytes by the kernel); Match only
			// needs filepath.Base of whichever we pass, so prefer argv[0]
			// when present.
			exePath = argv[0]
		}

		out = append(out, runningProcess{Pid: pid, ExePath: exePath, Argv: argv})
	}
	return out, nil
}
