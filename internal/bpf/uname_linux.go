//go:build linux

package bpf

import "golang.org/x/sys/unix"

// unameRelease returns the running kernel's release string (e.g.
// "5.15.0-102-generic"), as ParseKernelRelease expects, via the uname(2)
// syscall. Linux-only: darwin has no equivalent kernel-release concept
// relevant to RanA's tier probing (the macOS host never runs eBPF; only
// the Linux guest does, per docs/ARCHITECTURE.md §6).
func unameRelease() (string, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "", err
	}
	return charsToString(uts.Release[:]), nil
}

// charsToString converts a NUL-padded [N]byte (or [N]int8, depending on
// arch) uname field into a Go string, stopping at the first NUL.
func charsToString(b []byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}
