package alerts

import (
	"errors"
	"testing"
)

// TestFakeNotifier_RecordsCalls verifies the test double records every
// Notify call with its exact title/body, in order, and that its canned
// error (if any) is returned to the caller.
func TestFakeNotifier_RecordsCalls(t *testing.T) {
	fn := &FakeNotifier{}

	if err := fn.Notify("first title", "first body"); err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}
	if err := fn.Notify("second title", "second body"); err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}

	got := fn.Calls
	want := []NotifyCall{
		{Title: "first title", Body: "first body"},
		{Title: "second title", Body: "second body"},
	}
	if len(got) != len(want) {
		t.Fatalf("Calls = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Calls[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestFakeNotifier_ErrInjection verifies a FakeNotifier configured with Err
// returns that error from Notify without panicking, and still records the
// attempted call — matching the "best-effort, never blocks the pipeline"
// contract that real notifiers must honor.
func TestFakeNotifier_ErrInjection(t *testing.T) {
	wantErr := errors.New("boom")
	fn := &FakeNotifier{Err: wantErr}

	err := fn.Notify("t", "b")
	if !errors.Is(err, wantErr) {
		t.Fatalf("Notify err = %v, want %v", err, wantErr)
	}
	if len(fn.Calls) != 1 {
		t.Fatalf("Calls = %+v, want 1 recorded call even on error", fn.Calls)
	}
}

// TestNopNotifier_NeverErrors verifies the portable no-op Notifier used as
// a safe default never returns an error and does not panic.
func TestNopNotifier_NeverErrors(t *testing.T) {
	var n Notifier = NopNotifier{}
	if err := n.Notify("title", "body"); err != nil {
		t.Fatalf("NopNotifier.Notify returned error: %v", err)
	}
}
