// This file is the package's code-generation entry point: comments and
// bpf2go directives only, no code. It deliberately carries NO build
// constraint: `go generate` applies build constraints when scanning for
// directives, so tagging this file `//go:build ignore` (the
// obvious-looking choice for a "generation-only" file) makes
// `go generate ./internal/bpf` silently find nothing and succeed having
// generated nothing. That exact failure mode shipped once — the
// multi-kernel harness compiled against never-generated bindings and
// died with `undefined: loadRanaExec` — so the tag must stay absent, and
// ebpf-kernels.yml additionally asserts the *_bpfel.go files exist after
// generating (defense in depth).
//
// CI (not `go test`) runs `go generate ./internal/bpf`, which shells out
// to `bpf2go`, which shells out to `clang -target bpf`. clang is NOT
// invoked as part of any `go test` or `go build` in this repository — see
// CONTRACTS §internal/bpf: "Compile-check happens in CI (documented in
// Makefile `gen`); do NOT attempt clang compilation as part of `go test`."
//
// Regenerate with (from repo root, on a machine with clang + BTF-capable
// headers, typically only in CI or a Linux dev box):
//
//	go generate ./internal/bpf
//
// This produces (and overwrites) the *_bpfel.go / *_bpfeb.go and matching
// .o-embedding files bpf2go generates, one pair of Go files per program
// group below, embedded as CO-RE objects — no clang is required at
// runtime after generation; the loader (loader.go) only needs the
// generated Go+embedded-object pairs and github.com/cilium/ebpf.

package bpf

// NOTE: -cflags deliberately does NOT hardcode -D__TARGET_ARCH_x86 (or any
// other __TARGET_ARCH_*): bpf2go's -target amd64,arm64 compiles this source
// once per architecture and defines the matching __TARGET_ARCH_* macro
// (bpf_tracing.h's PT_REGS_* / BPF_PROG argument-extraction macros switch on
// it) for each compile automatically. Hardcoding -D__TARGET_ARCH_x86 in a
// shared -cflags string would silently force x86 register-argument shape
// onto the arm64 build too, corrupting every fentry/BPF_PROG argument read
// (task_struct*, dentry*, etc.) on arm64 — do not reintroduce it.
//
// The two hardcoded /usr/include/<multiarch>-linux-gnu dirs cover
// Debian/Ubuntu's multiarch split: <linux/types.h> includes <asm/types.h>,
// which lives in the per-arch dir that clang's bpf target does not search
// by default. Both dirs are listed unconditionally — clang silently
// ignores -I dirs that don't exist, and the asm-generic content behind
// them is identical for everything these programs use (real struct
// layouts come from CO-RE relocation at load, never from these headers).

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu" -target amd64,arm64 -type rana_exec_record -type rana_fork_record -type rana_exit_record ranaExec ../../bpf/src/rana_exec.c -- -I../../bpf/src

// ranaNet also carries rana_socket_connect (SEC("lsm/socket_connect")),
// the io_uring-coverage LSM hook added for Tier-2 (loader_tier.go's
// WantedPrograms gates its attachment to TierEnhanced+); no new -type flag
// is needed since it reuses rana_connect_record already listed below.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu" -target amd64,arm64 -type rana_connect_record -type rana_unix_connect_record -type rana_flow_close_record ranaNet ../../bpf/src/rana_net.c -- -I../../bpf/src

// ranaFs also carries rana_path_link (SEC("fentry/security_path_link")),
// the hardlink-watchlist re-pin hook added for Tier-2; no new -type flag
// is needed since it writes to rana_sensitive_inodes (already declared in
// common.h) and emits no ring-buffer record of its own.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu" -target amd64,arm64 -type rana_fsop_record ranaFs ../../bpf/src/rana_fs.c -- -I../../bpf/src

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu" -target amd64,arm64 -type rana_dns_record ranaDns ../../bpf/src/rana_dns.c -- -I../../bpf/src

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu" -target amd64,arm64 -type rana_migration_record ranaEscape ../../bpf/src/rana_escape.c -- -I../../bpf/src
