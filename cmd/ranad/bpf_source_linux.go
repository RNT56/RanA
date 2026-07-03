//go:build linux

package main

import "errors"

// ErrBPFNotGenerated is returned by newRecordSource until `go generate
// ./internal/bpf` has run in this checkout (it produces the
// *_bpfel.go/*_bpfeb.go files and flips on the `rana_bpf_generated` build
// tag that internal/bpf/loader_attach.go requires — CONTRACTS
// §internal/bpf). Without that generation step there is no
// linux-buildable ringbuf.Reader-backed RecordSource to construct: the
// concrete attach symbols (ranaExecObjects, loadRanaExecObjects, ...)
// simply do not exist in this tree. Returning this error (rather than a
// RecordSource that silently yields nothing) keeps ranad's honest-failure
// posture: a daemon that cannot observe anything must say so loudly at
// startup, not pretend to be recording (P5's spirit applied to "not
// generated yet" the same way it applies to ring-buffer drops).
var ErrBPFNotGenerated = errors.New("ranad: eBPF objects not generated in this build (run `go generate ./internal/bpf` — see internal/bpf/loader_attach.go)")

// newRecordSource constructs the real, linux-only RecordSource. Once
// internal/bpf's generated bindings exist in a checkout (built with
// `-tags rana_bpf_generated`, per CONTRACTS), this function is where a
// ringbuf.Reader-backed implementation gets wired in, using
// bpf.DetectKernelTier + a to-be-added bpf.Loader attach/Read surface. For
// now it returns ErrBPFNotGenerated so `GOOS=linux go build ./cmd/ranad`
// stays green and the daemon fails loudly and immediately at startup
// rather than silently recording nothing.
func newRecordSource() (RecordSource, func(), error) {
	return nil, func() {}, ErrBPFNotGenerated
}
