package ledger

import (
	"sync"
	"time"
)

// clock abstracts wall-clock time and timer creation so the Writer's
// group-commit / seal / checkpoint timers are deterministically testable
// without real sleeps (CONTRACTS testing bar: injectable clocks
// everywhere time matters).
type clock interface {
	// Now returns the current time in nanoseconds since the Unix epoch.
	Now() uint64
	// After returns a channel that receives the current time once d
	// nanoseconds have elapsed.
	After(d time.Duration) <-chan time.Time
}

// realClock is the production clock backed by the real wall clock and
// real timers.
type realClock struct{}

func (realClock) Now() uint64 {
	return uint64(time.Now().UnixNano())
}

func (realClock) After(d time.Duration) <-chan time.Time {
	return time.After(d)
}

// fakeClock is a deterministic, manually-advanced clock for tests. All
// methods are safe for concurrent use.
type fakeClock struct {
	mu      sync.Mutex
	now     uint64
	waiters []fakeWaiter
}

type fakeWaiter struct {
	deadline uint64
	ch       chan time.Time
}

func newFakeClock(startNs uint64) *fakeClock {
	return &fakeClock{now: startNs}
}

func (f *fakeClock) Now() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves the clock forward by dNs nanoseconds, firing (closing) any
// pending After() timers whose deadline has been reached.
func (f *fakeClock) Advance(dNs uint64) {
	f.mu.Lock()
	f.now += dNs
	now := f.now
	var fired []fakeWaiter
	remaining := f.waiters[:0:0]
	for _, w := range f.waiters {
		if w.deadline <= now {
			fired = append(fired, w)
		} else {
			remaining = append(remaining, w)
		}
	}
	f.waiters = remaining
	f.mu.Unlock()

	for _, w := range fired {
		w.ch <- time.Unix(0, int64(now))
	}
}

func (f *fakeClock) After(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan time.Time, 1)
	deadline := f.now + uint64(d.Nanoseconds())
	if d <= 0 || deadline <= f.now {
		ch <- time.Unix(0, int64(f.now))
		return ch
	}
	f.waiters = append(f.waiters, fakeWaiter{deadline: deadline, ch: ch})
	return ch
}
