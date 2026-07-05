//go:build linux && !rana_bpf_generated

package main

import "errors"

// ErrBPFNotGenerated is returned by newRecordSource until `go generate
// ./internal/bpf` has run in this checkout (it produces the
// *_bpfel.go/*_bpfeb.go files and flips on the `rana_bpf_generated` build
// tag that internal/bpf/loader_attach.go requires — CONTRACTS
// §internal/bpf). Without that generation step there is no
// linux-buildable ringbuf.Reader-backed RecordSource to construct: the
// concrete attach symbols (loadRanaExec, ...) simply do not exist in this
// tree. Returning this error (rather than a RecordSource that silently
// yields nothing) keeps ranad's honest-failure posture: a daemon that
// cannot observe anything must say so loudly at startup, not pretend to be
// recording (P5's spirit applied to "not generated yet" the same way it
// applies to ring-buffer drops).
var ErrBPFNotGenerated = errors.New("ranad: eBPF objects not generated in this build (run `go generate ./internal/bpf`, build with -tags rana_bpf_generated — see internal/bpf/loader_attach.go)")

// newRecordSource constructs the real, linux-only RecordSource plus the
// SessionRegistrar that arms/disarms kernel capture. This ungenerated
// variant returns ErrBPFNotGenerated so `GOOS=linux go build ./cmd/ranad`
// stays green and the daemon fails loudly and immediately at startup rather
// than silently recording nothing. The generated variant
// (bpf_source_generated_linux.go, built with -tags rana_bpf_generated)
// wraps bpf.NewLoader's ring buffer and loader.
func newRecordSource() (RecordSource, SessionRegistrar, func(), error) {
	return nil, nil, func() {}, ErrBPFNotGenerated
}
