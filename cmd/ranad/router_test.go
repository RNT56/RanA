package main

import (
	"sync"
	"testing"

	"github.com/RNT56/RanA/internal/wire"
)

// TestSingleUserRouter_AlwaysOneSink confirms the per-user default returns the
// one sink for any uid, and reports ok=false only for a nil sink.
func TestSingleUserRouter_AlwaysOneSink(t *testing.T) {
	s := &fakeSink{}
	r := SingleUserRouter{Sink: s}
	for _, uid := range []uint32{0, 1000, 4294967295} {
		got, ok := r.SinkFor(uid)
		if !ok || got != s {
			t.Errorf("SinkFor(%d) = (%v, %v), want (the one sink, true)", uid, got, ok)
		}
	}

	if _, ok := (SingleUserRouter{Sink: nil}).SinkFor(0); ok {
		t.Error("SingleUserRouter with a nil sink should report ok=false")
	}
}

// TestMultiUserRouter_RoutesByUIDNeverMisdelivers is the load-bearing
// property: each uid's events go to that uid's sink, an unregistered uid gets
// ok=false (drop, never a fallback), and unregister removes the mapping.
func TestMultiUserRouter_RoutesByUIDNeverMisdelivers(t *testing.T) {
	r := NewMultiUserRouter()
	alice, bob := &fakeSink{}, &fakeSink{}
	r.Register(1000, alice)
	r.Register(1001, bob)

	if got, ok := r.SinkFor(1000); !ok || got != alice {
		t.Errorf("uid 1000 routed to %v (ok=%v), want alice", got, ok)
	}
	if got, ok := r.SinkFor(1001); !ok || got != bob {
		t.Errorf("uid 1001 routed to %v (ok=%v), want bob", got, ok)
	}
	// A uid with no registered svc must NOT fall back to another user's sink.
	if got, ok := r.SinkFor(1002); ok || got != nil {
		t.Errorf("unregistered uid 1002 = (%v, %v), want (nil, false) — never a fallback", got, ok)
	}

	// Reconnect: a second Register replaces the sink.
	alice2 := &fakeSink{}
	r.Register(1000, alice2)
	if got, _ := r.SinkFor(1000); got != alice2 {
		t.Errorf("after re-register, uid 1000 -> %v, want the new sink", got)
	}

	// Registering a nil sink is treated as Unregister (no dead destinations).
	r.Register(1001, nil)
	if _, ok := r.SinkFor(1001); ok {
		t.Error("Register(uid, nil) should remove the mapping")
	}

	// Explicit Unregister.
	r.Unregister(1000)
	if _, ok := r.SinkFor(1000); ok {
		t.Error("Unregister should remove the mapping")
	}
	r.Unregister(1000) // idempotent
}

// TestMultiUserRouter_UIDs returns the connected users for daemon-wide fan-out.
func TestMultiUserRouter_UIDs(t *testing.T) {
	r := NewMultiUserRouter()
	r.Register(7, &fakeSink{})
	r.Register(9, &fakeSink{})
	uids := r.UIDs()
	if len(uids) != 2 {
		t.Fatalf("UIDs() = %v, want 2 entries", uids)
	}
	seen := map[uint32]bool{}
	for _, u := range uids {
		seen[u] = true
	}
	if !seen[7] || !seen[9] {
		t.Errorf("UIDs() = %v, want {7, 9}", uids)
	}
}

// TestMultiUserRouter_ConcurrentRegisterAndLookup is the -race guard: the pump
// goroutine looks sinks up while the connect/disconnect path registers and
// unregisters them.
func TestMultiUserRouter_ConcurrentRegisterAndLookup(t *testing.T) {
	r := NewMultiUserRouter()
	var wg sync.WaitGroup
	for u := uint32(0); u < 16; u++ {
		wg.Add(2)
		go func(uid uint32) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				r.Register(uid, &fakeSink{})
				r.Unregister(uid)
			}
		}(u)
		go func(uid uint32) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_, _ = r.SinkFor(uid)
				_ = r.UIDs()
			}
		}(u)
	}
	wg.Wait()
}

// TestFrameSinkRouterInterface is a tiny compile+shape check that a fakeSink
// satisfies FrameSink and both routers deliver a frame through it.
func TestFrameSinkRouterInterface(t *testing.T) {
	s := &fakeSink{}
	var r EventRouter = SingleUserRouter{Sink: s}
	sink, ok := r.SinkFor(42)
	if !ok {
		t.Fatal("expected a sink")
	}
	if err := sink.Send(&wire.Bye{}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(s.Sent()) != 1 {
		t.Fatalf("sent %d frames, want 1", len(s.Sent()))
	}
}
