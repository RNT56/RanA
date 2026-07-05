//go:build linux && rana_bpf_generated

package bpf

// loader_attach.go wires the generic pin/reattach plumbing in loader.go
// to the concrete bpf2go-generated objects (gen.go's ranaExec/ranaNet/
// ranaFs/ranaDns/ranaEscape groups). It is gated behind the
// `rana_bpf_generated` build tag IN ADDITION to linux, because it
// references the loadRanaExec/... spec loaders that only exist after
// `go generate ./internal/bpf` has run and produced the *_bpfel.go files
// bpf2go writes alongside gen.go. Until that generation step runs (a
// Linux+clang step, never `go test`, per CONTRACTS §internal/bpf), this
// file is excluded from every build so the rest of the package stays
// buildable and testable without a generation step ever having happened
// in this checkout.
//
// The five program groups attach per D7's hook set and
// docs/ARCHITECTURE.md §2:
//
//	ranaExec:   tp_btf/sched_process_{exec,fork,exit}  -> link.AttachTracing
//	ranaNet:    cgroup/{connect4,connect6,sendmsg4,sendmsg6}
//	                                                    -> link.AttachCgroup
//	            fentry/unix_stream_connect,
//	            tp_btf/inet_sock_set_state              -> link.AttachTracing
//	            lsm/socket_connect (TierEnhanced+)      -> link.AttachLSM
//	ranaFs:     fentry/security_{file_open,path_unlink,path_rename,
//	            path_mkdir,path_link} + fentry/vfs_truncate
//	                                                    -> link.AttachTracing
//	ranaDns:    cgroup_skb/egress                       -> link.AttachCgroup
//	ranaEscape: raw_tp/cgroup_attach_task               -> link.AttachRawTracepoint
//
// Every group's ELF independently declares the common.h maps; the first
// group loaded (ranaExec) owns the real ones, and every subsequent group
// is loaded with MapReplacements so all programs share one rana_events
// ring buffer and one session-filter map — without this each group would
// get a private, disjoint copy and the collector would only ever see
// exec events.
//
// P2: everything here is attach-and-observe. No program in the set can
// block, modify, or veto anything (the lsm/socket_connect hook returns 0
// unconditionally; CI greps the compiled programs for write/override
// helpers).
//
// NewLoader's caller (cmd/ranad's main, the kernel harness) is
// responsible for turning the GapDescriptor this file produces on
// restart into a schema.Event — this package never imports the ledger
// (CONTRACTS package graph).

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// AttachOptions configures NewLoader.
type AttachOptions struct {
	// CgroupRoot is the cgroup-v2 unified hierarchy mount the
	// cgroup-scoped programs (connect4/6, sendmsg4/6, cgroup_skb egress)
	// attach at. Attaching at the root observes every descendant cgroup;
	// the in-kernel rana_sessions filter keeps non-session noise out of
	// the ring buffer (P6). Defaults to /sys/fs/cgroup.
	CgroupRoot string
}

// sharedMapNames are the common.h maps shared across every program group
// via MapReplacements. rana_scratch_map is included: it is per-CPU
// transient scratch, but sharing it costs nothing and keeps "one map
// name, one map" true system-wide.
var sharedMapNames = []string{
	"rana_sessions", "rana_session_pids", "rana_events",
	"rana_sensitive_prefixes", "rana_sensitive_inodes", "rana_scratch_map",
}

// durablePinMapNames are the maps pinned under /sys/fs/bpf/rana/map for
// reattach across ranad restarts (loader_attach.go's package comment;
// scratch is deliberately not durable).
var durablePinMapNames = []string{
	"rana_sessions", "rana_session_pids", "rana_events",
	"rana_sensitive_prefixes", "rana_sensitive_inodes",
}

// NewLoader loads every generated CO-RE object group, shares the common
// maps across them, attaches the WantedPrograms for the detected kernel
// tier, pins programs and durable maps for idempotent reattach, and
// opens the rana_events ring buffer reader.
//
// The returned GapDescriptor is non-nil when a previous ranad left pins
// behind (a restart, not a fresh start): the caller must persist it as a
// first-class gap event (P5). The optional lsm/socket_connect hook
// degrading (kernel without an active BPF LSM) is NOT an error — it is
// surfaced via Loader.LSMDegraded and must be reported, not swallowed.
func NewLoader(opts AttachOptions) (*Loader, *GapDescriptor, error) {
	cgroupRoot := opts.CgroupRoot
	if cgroupRoot == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	if _, err := os.Stat(cgroupRoot); err != nil {
		return nil, nil, fmt.Errorf("bpf: cgroup-v2 root %s: %w", cgroupRoot, err)
	}

	tier, err := DetectKernelTier()
	if err != nil {
		return nil, nil, err
	}
	if tier < TierBaseline {
		return nil, nil, fmt.Errorf("bpf: kernel below the 5.15 floor (tier %v) — ranad refuses to start", tier)
	}
	if err := ensureBPFFSRoot(); err != nil {
		return nil, nil, err
	}

	prevPinned, err := pinnedProgramNames()
	if err != nil {
		return nil, nil, fmt.Errorf("bpf: listing previous pins: %w", err)
	}

	l := &Loader{tier: tier, prevPinned: prevPinned}
	ok := false
	defer func() {
		if !ok {
			_ = l.Close()
		}
	}()

	// --- Load the five groups; ranaExec first owns the shared maps. ---
	execSpec, err := loadRanaExec()
	if err != nil {
		return nil, nil, fmt.Errorf("bpf: loading exec spec: %w", err)
	}
	execColl, err := ebpf.NewCollection(execSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("bpf: creating exec collection: %w", err)
	}
	l.closers = append(l.closers, execColl.Close)

	shared := make(map[string]*ebpf.Map, len(sharedMapNames))
	for _, name := range sharedMapNames {
		m, okm := execColl.Maps[name]
		if !okm {
			return nil, nil, fmt.Errorf("bpf: exec collection is missing shared map %s", name)
		}
		shared[name] = m
	}
	l.sessions = shared["rana_sessions"]
	l.sessionPids = shared["rana_session_pids"]
	l.events = shared["rana_events"]
	l.sensPrefixes = shared["rana_sensitive_prefixes"]
	l.sensInodes = shared["rana_sensitive_inodes"]

	wantLSM := tier.Features().LSMSocketConnect
	netColl, lsmDegraded, err := loadNetGroup(shared, wantLSM)
	if err != nil {
		return nil, nil, err
	}
	l.closers = append(l.closers, netColl.Close)
	l.lsmDegraded = lsmDegraded

	fsColl, err := loadSharing(loadRanaFs, shared, "fs")
	if err != nil {
		return nil, nil, err
	}
	l.closers = append(l.closers, fsColl.Close)

	dnsColl, err := loadSharing(loadRanaDns, shared, "dns")
	if err != nil {
		return nil, nil, err
	}
	l.closers = append(l.closers, dnsColl.Close)

	escColl, err := loadSharing(loadRanaEscape, shared, "escape")
	if err != nil {
		return nil, nil, err
	}
	l.closers = append(l.closers, escColl.Close)

	progs := map[string]*ebpf.Program{}
	for _, coll := range []*ebpf.Collection{execColl, netColl, fsColl, dnsColl, escColl} {
		for name, p := range coll.Programs {
			progs[name] = p
		}
	}

	// --- Attach. Everything WantedPrograms lists is mandatory except
	// the LSM hook, whose absence was already recorded above. ---
	for _, name := range WantedPrograms(tier) {
		p, okp := progs[name]
		if !okp {
			if name == "rana_socket_connect" && l.lsmDegraded != "" {
				continue // pruned at load; degradation already surfaced
			}
			return nil, nil, fmt.Errorf("bpf: wanted program %s not present in any loaded collection", name)
		}
		lk, aerr := attachOne(name, p, cgroupRoot)
		if aerr != nil {
			if name == "rana_socket_connect" {
				// Loadable but not attachable (BPF LSM compiled in but
				// not active on the lsm= cmdline). Optional coverage —
				// degrade loudly, don't fail the whole collector.
				l.lsmDegraded = fmt.Sprintf("lsm/socket_connect attach failed: %v", aerr)
				continue
			}
			return nil, nil, fmt.Errorf("bpf: attaching %s: %w", name, aerr)
		}
		l.links = append(l.links, lk)
	}

	// --- Pin programs + durable maps for idempotent reattach. ---
	plan := ReattachPlan(prevPinned, WantedPrograms(tier))
	unpinStale(plan.Stale)
	for name, p := range progs {
		if err := pinProgram(p, name); err != nil {
			return nil, nil, fmt.Errorf("bpf: pinning program %s: %w", name, err)
		}
	}
	for _, name := range durablePinMapNames {
		if err := pinMap(shared[name], name); err != nil {
			return nil, nil, fmt.Errorf("bpf: pinning map %s: %w", name, err)
		}
	}

	// --- Ring buffer reader. ---
	rd, err := ringbuf.NewReader(l.events)
	if err != nil {
		return nil, nil, fmt.Errorf("bpf: opening ring buffer reader: %w", err)
	}
	l.reader = rd

	// A previous ranad's pins mean recording stopped and resumed: that
	// window is a gap the caller must persist (P5). Timestamps are left
	// zero — the loader does not know when the previous process died,
	// and it never guesses (DaemonRestartGap doc).
	var gap *GapDescriptor
	if len(prevPinned) > 0 {
		g := DaemonRestartGap(0, 0)
		gap = &g
	}

	ok = true
	return l, gap, nil
}

// loadSharing loads one generated spec with the shared common.h maps
// substituted in (filtered to the maps that group's ELF actually
// declares, since MapReplacements rejects unused replacements).
func loadSharing(loadSpec func() (*ebpf.CollectionSpec, error), shared map[string]*ebpf.Map, what string) (*ebpf.Collection, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, fmt.Errorf("bpf: loading %s spec: %w", what, err)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: filterReplacements(spec, shared),
	})
	if err != nil {
		return nil, fmt.Errorf("bpf: creating %s collection: %w", what, err)
	}
	return coll, nil
}

// loadNetGroup loads the net group, pruning the optional lsm/socket_connect
// program when the tier doesn't want it — and, if the kernel refuses to
// load it even when wanted (CONFIG_BPF_LSM absent), retrying pruned and
// reporting the degradation instead of failing the whole group.
func loadNetGroup(shared map[string]*ebpf.Map, wantLSM bool) (coll *ebpf.Collection, lsmDegraded string, err error) {
	load := func(includeLSM bool) (*ebpf.Collection, error) {
		spec, serr := loadRanaNet()
		if serr != nil {
			return nil, fmt.Errorf("bpf: loading net spec: %w", serr)
		}
		if !includeLSM {
			delete(spec.Programs, "rana_socket_connect")
		}
		c, cerr := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			MapReplacements: filterReplacements(spec, shared),
		})
		if cerr != nil {
			return nil, cerr
		}
		return c, nil
	}

	if !wantLSM {
		c, cerr := load(false)
		if cerr != nil {
			return nil, "", fmt.Errorf("bpf: creating net collection: %w", cerr)
		}
		return c, "", nil
	}
	c, cerr := load(true)
	if cerr == nil {
		return c, "", nil
	}
	// Retry without the LSM hook: on kernels without CONFIG_BPF_LSM the
	// verifier rejects the lsm program at load, which must degrade the
	// optional hook — loudly — not kill the baseline hook set.
	c2, c2err := load(false)
	if c2err != nil {
		return nil, "", fmt.Errorf("bpf: creating net collection (with and without lsm hook): %w", errors.Join(cerr, c2err))
	}
	return c2, fmt.Sprintf("lsm/socket_connect load failed (BPF LSM unavailable?): %v", cerr), nil
}

// filterReplacements returns the subset of shared maps the given spec
// actually declares (MapReplacements errors on unused entries).
func filterReplacements(spec *ebpf.CollectionSpec, shared map[string]*ebpf.Map) map[string]*ebpf.Map {
	repl := make(map[string]*ebpf.Map, len(shared))
	for name, m := range shared {
		if _, ok := spec.Maps[name]; ok {
			repl[name] = m
		}
	}
	return repl
}

// attachOne attaches a single named program with the mechanism its hook
// type requires (the package comment's table).
func attachOne(name string, p *ebpf.Program, cgroupRoot string) (link.Link, error) {
	switch name {
	// tp_btf + fentry hooks share the tracing attach path; the program
	// spec carries the concrete attach type from its SEC() name.
	case "rana_on_exec", "rana_on_fork", "rana_on_exit",
		"rana_unix_connect", "rana_flow_close",
		"rana_file_open", "rana_path_unlink", "rana_path_rename",
		"rana_path_mkdir", "rana_vfs_truncate", "rana_path_link":
		return link.AttachTracing(link.TracingOptions{Program: p})

	case "rana_connect4":
		return link.AttachCgroup(link.CgroupOptions{Path: cgroupRoot, Attach: ebpf.AttachCGroupInet4Connect, Program: p})
	case "rana_connect6":
		return link.AttachCgroup(link.CgroupOptions{Path: cgroupRoot, Attach: ebpf.AttachCGroupInet6Connect, Program: p})
	case "rana_sendmsg4":
		return link.AttachCgroup(link.CgroupOptions{Path: cgroupRoot, Attach: ebpf.AttachCGroupUDP4Sendmsg, Program: p})
	case "rana_sendmsg6":
		return link.AttachCgroup(link.CgroupOptions{Path: cgroupRoot, Attach: ebpf.AttachCGroupUDP6Sendmsg, Program: p})
	case "rana_dns_egress":
		return link.AttachCgroup(link.CgroupOptions{Path: cgroupRoot, Attach: ebpf.AttachCGroupInetEgress, Program: p})

	case "rana_cgroup_attach_task":
		return link.AttachRawTracepoint(link.RawTracepointOptions{Name: "cgroup_attach_task", Program: p})

	case "rana_socket_connect":
		return link.AttachLSM(link.LSMOptions{Program: p})
	}
	return nil, fmt.Errorf("bpf: no attach rule for program %q", name)
}
