//go:build !linux

package main

import (
	"fmt"
	"os"
)

// main is the non-linux entry point. ranad is a Linux-only privileged
// collector daemon (it loads eBPF, which does not exist on any other
// platform) — on macOS the equivalent process runs inside the Linux guest
// VM (docs/MACOS.md; docs/ARCHITECTURE.md §6), not on the host. This stub
// exists purely so `go build ./cmd/ranad` (and the darwin dev loop more
// generally) stays green; it is never the binary a user actually runs on
// macOS.
func main() {
	fmt.Fprintln(os.Stderr, "ranad runs inside the Linux guest on macOS (see docs/MACOS.md)")
	os.Exit(2)
}
