//go:build linux && rana_bpf_generated

package bpf

// loader_attach.go wires the generic pin/reattach plumbing in loader.go
// to the concrete bpf2go-generated objects (gen.go's ranaExec/ranaNet/
// ranaFs/ranaDns/ranaEscape groups). It is gated behind the
// `rana_bpf_generated` build tag IN ADDITION to linux, because it
// references types (ranaExecObjects, loadRanaExecObjects, ...) that only
// exist after `go generate ./internal/bpf` has run and produced the
// *_bpfel.go/*_bpfeb.go files bpf2go writes alongside gen.go. Until that
// generation step runs (a Linux+clang CI job, never `go test`, per
// CONTRACTS §internal/bpf), this file is excluded from every build —
// including `GOOS=linux go build ./internal/bpf` — so the rest of the
// package (loader.go's pin/reattach plumbing, loader_tier.go, the
// invariant/cross-check tests) stays buildable and testable without a
// generation step ever having happened in this checkout.
//
// CI's `make gen` step additionally passes `-tags rana_bpf_generated` (or
// runs go generate first, which doesn't require the tag at all — this
// tag exists purely so a *stale* checkout — generated files present but
// the tag not threaded through some build invocation — fails loudly
// instead of silently linking against half-present symbols) when building
// cmd/ranad for real.
//
// Once generated, the four program groups attach as follows, per D7's
// hook set and docs/ARCHITECTURE.md §2:
//
//	ranaExec:   tp_btf/sched_process_exec, tp_btf/sched_process_fork,
//	            tp_btf/sched_process_exit          -> link.AttachTracing
//	ranaNet:    cgroup/connect4, cgroup/connect6, cgroup/sendmsg4,
//	            cgroup/sendmsg6                    -> link.AttachCgroup
//	            fentry/unix_stream_connect,
//	            fentry/inet_sock_set_state         -> link.AttachTracing
//	ranaFs:     fentry/security_file_open,
//	            fentry/security_path_unlink,
//	            fentry/security_path_rename,
//	            fentry/security_path_mkdir,
//	            fentry/vfs_truncate                -> link.AttachTracing
//	ranaDns:    cgroup_skb/egress                  -> link.AttachCgroup
//	ranaEscape: raw_tp/cgroup_attach_task           -> link.AttachRawTracepoint
//
// Every attach records its link.Link into Loader.links so Close() can
// detach cleanly; every program and every shared map (rana_sessions,
// rana_session_pids, rana_events, rana_sensitive_prefixes,
// rana_sensitive_inodes) is pinned via loader.go's pinProgram/pinMap
// under the ReattachPlan-computed ToLoad set, and anything ReattachPlan
// reports Stale is unpinned — giving idempotent re-attach across ranad
// restarts without manual bpffs cleanup.
//
// NewLoader's caller (cmd/ranad's main, outside this package's dependency
// graph) is responsible for turning the DaemonRestartGap this file
// produces on every construction into a schema.Event via schema.NewGap
// and persisting it through internal/ledger — this package's dependency
// graph is internal/bpf -> internal/collector only (CONTRACTS package
// graph), so it never imports internal/ledger or internal/schema's event
// constructors directly; it hands back a portable GapDescriptor
// (loader_tier.go) instead.
