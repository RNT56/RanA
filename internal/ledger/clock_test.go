package ledger

import (
	"testing"
	"time"
)

func TestFakeClockNowAdvance(t *testing.T) {
	fc := newFakeClock(1000)
	if got := fc.Now(); got != 1000 {
		t.Fatalf("Now() = %d, want 1000", got)
	}
	fc.Advance(50)
	if got := fc.Now(); got != 1050 {
		t.Fatalf("after Advance: Now() = %d, want 1050", got)
	}
}

func TestFakeClockAfterFiresOnAdvance(t *testing.T) {
	fc := newFakeClock(0)
	ch := fc.After(100)
	select {
	case <-ch:
		t.Fatalf("timer fired before advance")
	default:
	}
	fc.Advance(100)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timer did not fire after advance")
	}
}

func TestRealClockMonotonic(t *testing.T) {
	rc := realClock{}
	a := rc.Now()
	b := rc.Now()
	if b < a {
		t.Fatalf("realClock.Now() went backwards: %d then %d", a, b)
	}
	ch := rc.After(1)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("realClock.After never fired")
	}
}
