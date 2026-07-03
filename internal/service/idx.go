package service

import "sync"

// idxAllocator hands out a monotonically increasing per-session Idx for
// every event svc itself originates (session.start/end, marker.*,
// fs.settle, alert.*). schema.Event.Idx is documented as "monotonic per
// session" (CONTRACTS §internal/schema), but in the shipped architecture
// TWO independent processes assign Idx values into the same session's
// stream: ranad's internal/collector.Enricher assigns Idx to kernel-origin
// events, and svc must assign Idx to every event it originates itself —
// there is no cross-process shared counter (see this package's final
// report for the contract gap this raises: internal/ledger neither
// enforces nor reads Idx for chain-integrity purposes — see
// docs/TRUST.md §6 and internal/ledger/verify.go, which key
// segment/session identity off rowid and [first_rowid,last_rowid], never
// off Idx — so a same-session Idx collision between the two processes is a
// display/ordering quality issue for the UI, never a chain-integrity or
// security issue). svc's allocator is deliberately kept in its own
// namespace (see NewIdxAllocator's doc) to minimize (not guarantee-zero)
// collision surface with ranad's counter without invalidating either
// side's "monotonic within its own writes" property.
type idxAllocator struct {
	mu   sync.Mutex
	next map[string]uint64
}

// svcIdxBase is the starting value for svc's own per-session Idx sequence.
// Kernel-origin sessions typically emit far fewer than this many events
// before svc's own session.start/session.end/marker/alert/digest events
// begin appearing, so starting svc's counter at a high base measurably
// reduces (never eliminates — there is no authoritative cross-process
// sequence without a protocol change) the chance of a same-value Idx
// collision with ranad's independently-zero-based counter for the same
// session, which would otherwise be near-certain (both start at 0).
const svcIdxBase = 1 << 40

func newIdxAllocator() *idxAllocator {
	return &idxAllocator{next: make(map[string]uint64)}
}

// next returns the next Idx for session, allocating from svcIdxBase on
// first use.
func (a *idxAllocator) allocate(session string) uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.next[session]
	if !ok {
		v = svcIdxBase
	}
	a.next[session] = v + 1
	return v
}
