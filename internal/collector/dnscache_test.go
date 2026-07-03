package collector

import (
	"testing"
	"time"
)

func newTestDNSCache(clk Clock) *DNSCache {
	return NewDNSCache(clk)
}

func TestDNSCacheJoinFindsRecentAnswer(t *testing.T) {
	clk := newFakeClock()
	c := newTestDNSCache(clk)

	addr := v4Mapped(93, 184, 216, 34)
	c.Observe("example.com", []([16]byte){addr}, 300, clk.Now())

	got, ok := c.Join(addr, clk.Now(), 5*time.Second)
	if !ok {
		t.Fatal("Join: expected a hit for recently observed address")
	}
	if got != "example.com" {
		t.Errorf("Join qname = %q, want example.com", got)
	}
}

func TestDNSCacheJoinMissForUnknownAddr(t *testing.T) {
	clk := newFakeClock()
	c := newTestDNSCache(clk)
	addr := v4Mapped(1, 1, 1, 1)
	_, ok := c.Join(addr, clk.Now(), 5*time.Second)
	if ok {
		t.Fatal("Join: expected miss for an address never observed")
	}
}

func TestDNSCacheJoinRespectsWindow(t *testing.T) {
	clk := newFakeClock()
	c := newTestDNSCache(clk)
	addr := v4Mapped(8, 8, 8, 8)
	c.Observe("dns.google", []([16]byte){addr}, 300, clk.Now())

	clk.Advance(10 * time.Second)
	_, ok := c.Join(addr, clk.Now(), 5*time.Second)
	if ok {
		t.Fatal("Join: expected miss once the join window has elapsed")
	}

	// Within the window it should still hit.
	clk2 := newFakeClock()
	c2 := newTestDNSCache(clk2)
	c2.Observe("dns.google", []([16]byte){addr}, 300, clk2.Now())
	clk2.Advance(3 * time.Second)
	if _, ok := c2.Join(addr, clk2.Now(), 5*time.Second); !ok {
		t.Fatal("Join: expected hit within the join window")
	}
}

func TestDNSCacheExpiresByTTL(t *testing.T) {
	clk := newFakeClock()
	c := newTestDNSCache(clk)
	addr := v4Mapped(2, 2, 2, 2)
	// TTL of 2 seconds; even though the join window below is generous,
	// the cache entry itself should expire at TTL and stop answering.
	c.Observe("short-lived.example", []([16]byte){addr}, 2, clk.Now())

	clk.Advance(3 * time.Second)
	_, ok := c.Join(addr, clk.Now(), time.Hour)
	if ok {
		t.Fatal("Join: expected miss after TTL expiry even with a huge join window")
	}
}

func TestDNSCacheMultipleAnswersAllJoinable(t *testing.T) {
	clk := newFakeClock()
	c := newTestDNSCache(clk)
	a1 := v4Mapped(93, 184, 216, 34)
	a2 := v4Mapped(93, 184, 216, 35)
	c.Observe("example.com", []([16]byte){a1, a2}, 300, clk.Now())

	for _, addr := range []([16]byte){a1, a2} {
		got, ok := c.Join(addr, clk.Now(), 5*time.Second)
		if !ok || got != "example.com" {
			t.Errorf("Join(%v) = (%q, %v), want (example.com, true)", addr, got, ok)
		}
	}
}

func TestDNSCacheLaterAnswerOverridesEarlierForSameAddr(t *testing.T) {
	clk := newFakeClock()
	c := newTestDNSCache(clk)
	addr := v4Mapped(1, 2, 3, 4)
	c.Observe("old.example", []([16]byte){addr}, 300, clk.Now())
	clk.Advance(time.Second)
	c.Observe("new.example", []([16]byte){addr}, 300, clk.Now())

	got, ok := c.Join(addr, clk.Now(), 5*time.Second)
	if !ok || got != "new.example" {
		t.Errorf("Join = (%q, %v), want (new.example, true) — most recent answer should win", got, ok)
	}
}

func TestDNSCacheGC(t *testing.T) {
	clk := newFakeClock()
	c := newTestDNSCache(clk)
	addr := v4Mapped(9, 9, 9, 9)
	c.Observe("gc-me.example", []([16]byte){addr}, 1, clk.Now())

	clk.Advance(2 * time.Second)
	c.GC(clk.Now())

	if n := c.Len(); n != 0 {
		t.Errorf("Len() after GC = %d, want 0", n)
	}
}

func TestDNSCacheGCKeepsLiveEntries(t *testing.T) {
	clk := newFakeClock()
	c := newTestDNSCache(clk)
	addr := v4Mapped(9, 9, 9, 8)
	c.Observe("still-alive.example", []([16]byte){addr}, 3600, clk.Now())

	clk.Advance(time.Second)
	c.GC(clk.Now())

	if n := c.Len(); n != 1 {
		t.Errorf("Len() after GC = %d, want 1 (entry still within TTL)", n)
	}
}
