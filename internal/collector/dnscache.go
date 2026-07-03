package collector

import (
	"sync"
	"time"
)

// dnsEntry is one cached qname observation for a single resolved address.
type dnsEntry struct {
	qname     string
	observed  time.Time
	expiresAt time.Time // observed + TTL
}

// DNSCache is a userspace qname<->IP TTL cache (plan §4.3: "net.dns ...
// joined to subsequent connects by (addr, window)"). ranad's DNS observer
// calls Observe on every net.dns record; the Enricher calls Join when
// building a net.connect event so its daddr can be annotated with the
// qname that resolved to it, if one was seen recently enough.
//
// DNSCache is safe for concurrent use.
type DNSCache struct {
	mu    sync.Mutex
	clock Clock
	byIP  map[[16]byte]dnsEntry
}

// NewDNSCache constructs an empty DNSCache using clk for TTL/window
// arithmetic (injectable for deterministic tests).
func NewDNSCache(clk Clock) *DNSCache {
	return &DNSCache{
		clock: clk,
		byIP:  make(map[[16]byte]dnsEntry),
	}
}

// Observe records a DNS answer set: qname resolved to each address in
// answers, with the given TTL (seconds), observed at now. A later call for
// the same address overwrites the earlier entry (the most recent DNS
// answer wins the join for that address, matching how a resolver's answer
// would actually be used by the OS resolver cache).
func (c *DNSCache) Observe(qname string, answers [][16]byte, ttlSeconds uint32, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	expires := now.Add(time.Duration(ttlSeconds) * time.Second)
	for _, addr := range answers {
		c.byIP[addr] = dnsEntry{
			qname:     qname,
			observed:  now,
			expiresAt: expires,
		}
	}
}

// Join looks up the most recent qname that resolved to addr, returning it
// only if the entry (a) has not expired per its DNS TTL, and (b) was
// observed within window of now (plan §4.3's "(addr, window)" join). Both
// conditions must hold — a long TTL does not excuse a stale join outside
// the window, and a short join window does not excuse serving an
// already-TTL-expired answer.
func (c *DNSCache) Join(addr [16]byte, now time.Time, window time.Duration) (qname string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, found := c.byIP[addr]
	if !found {
		return "", false
	}
	if now.After(e.expiresAt) {
		return "", false
	}
	if now.Sub(e.observed) > window {
		return "", false
	}
	return e.qname, true
}

// GC removes every entry whose TTL has expired as of now. Callers
// (typically ranad's periodic maintenance loop) invoke this to bound the
// cache's memory footprint; Join already refuses expired entries on its
// own, so GC is a cleanliness/memory concern, not a correctness one.
func (c *DNSCache) GC(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for addr, e := range c.byIP {
		if now.After(e.expiresAt) {
			delete(c.byIP, addr)
		}
	}
}

// Len reports the current number of cached (address -> qname) entries,
// primarily for tests and diagnostics.
func (c *DNSCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.byIP)
}
