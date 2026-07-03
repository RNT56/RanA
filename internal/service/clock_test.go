package service

import (
	"sync"
	"time"
)

// fakeClock is a deterministic, manually-advanced Clock for tests
// (CONTRACTS testing bar: injectable clocks everywhere time matters, no
// real sleeps). Safe for concurrent use.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []fakeWaiter
}

type fakeWaiter struct {
	deadline time.Time
	ch       chan time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// waiterCount reports how many After() timers are currently armed. Tests
// driving a background goroutine (e.g. the digest worker's scan ticker) use
// this to synchronize deterministically: after Advance fires a tick, the
// goroutine runs its work and re-arms its next timer, so waiting for a timer
// to be re-armed proves the tick was fully processed before the next Advance
// — closing the fakeClock/goroutine wakeup race without a real sleep.
func (f *fakeClock) waiterCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.waiters)
}

// advanceAndSettle advances the clock by d, then blocks until a background
// ticker goroutine has re-armed its timer — i.e. finished processing the tick
// this Advance fired. It gives up after a generous deadline so a genuinely
// stuck worker fails the test loudly rather than hanging forever.
func (f *fakeClock) advanceAndSettle(d time.Duration) {
	f.Advance(d)
	deadline := time.Now().Add(2 * time.Second)
	for f.waiterCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
}

func (f *fakeClock) After(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan time.Time, 1)
	deadline := f.now.Add(d)
	if d <= 0 || !deadline.After(f.now) {
		ch <- f.now
		return ch
	}
	f.waiters = append(f.waiters, fakeWaiter{deadline: deadline, ch: ch})
	return ch
}

// Advance moves the clock forward by d, firing (and closing) any pending
// After() timers whose deadline has been reached.
func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	now := f.now
	var fired []fakeWaiter
	remaining := f.waiters[:0:0]
	for _, w := range f.waiters {
		if !w.deadline.After(now) {
			fired = append(fired, w)
		} else {
			remaining = append(remaining, w)
		}
	}
	f.waiters = remaining
	f.mu.Unlock()

	for _, w := range fired {
		w.ch <- now
	}
}
