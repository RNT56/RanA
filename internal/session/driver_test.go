package session

import (
	"context"
	"errors"
	"testing"
)

func TestFakeDriver_ImplementsDriver(t *testing.T) {
	var _ Driver = NewFakeDriver()
}

func TestFakeDriver_CreateScope_RecordsCall(t *testing.T) {
	fd := NewFakeDriver()
	ctx := context.Background()

	scope, err := fd.CreateScope(ctx, "rana-abc123")
	if err != nil {
		t.Fatalf("CreateScope: unexpected error: %v", err)
	}
	if scope.Name != "rana-abc123" {
		t.Errorf("scope.Name = %q, want %q", scope.Name, "rana-abc123")
	}
	if len(fd.CreatedScopes) != 1 || fd.CreatedScopes[0] != "rana-abc123" {
		t.Errorf("CreatedScopes = %v, want [rana-abc123]", fd.CreatedScopes)
	}
}

func TestFakeDriver_CreateScope_DuplicateErrors(t *testing.T) {
	fd := NewFakeDriver()
	ctx := context.Background()

	if _, err := fd.CreateScope(ctx, "dup"); err != nil {
		t.Fatalf("first CreateScope: unexpected error: %v", err)
	}
	if _, err := fd.CreateScope(ctx, "dup"); !errors.Is(err, ErrScopeExists) {
		t.Errorf("second CreateScope: got err=%v, want ErrScopeExists", err)
	}
}

func TestFakeDriver_AddProcess_RequiresExistingScope(t *testing.T) {
	fd := NewFakeDriver()
	ctx := context.Background()

	err := fd.AddProcess(ctx, "no-such-scope", 1234)
	if !errors.Is(err, ErrScopeNotFound) {
		t.Errorf("AddProcess on missing scope: got err=%v, want ErrScopeNotFound", err)
	}
}

func TestFakeDriver_AddProcess_TracksMembership(t *testing.T) {
	fd := NewFakeDriver()
	ctx := context.Background()

	if _, err := fd.CreateScope(ctx, "s1"); err != nil {
		t.Fatalf("CreateScope: %v", err)
	}
	if err := fd.AddProcess(ctx, "s1", 100); err != nil {
		t.Fatalf("AddProcess: %v", err)
	}
	if err := fd.AddProcess(ctx, "s1", 200); err != nil {
		t.Fatalf("AddProcess: %v", err)
	}

	members := fd.Members("s1")
	want := []int32{100, 200}
	if len(members) != len(want) {
		t.Fatalf("Members = %v, want %v", members, want)
	}
	for i := range want {
		if members[i] != want[i] {
			t.Fatalf("Members = %v, want %v", members, want)
		}
	}
}

func TestFakeDriver_DestroyScope_RemovesMembership(t *testing.T) {
	fd := NewFakeDriver()
	ctx := context.Background()

	if _, err := fd.CreateScope(ctx, "s1"); err != nil {
		t.Fatalf("CreateScope: %v", err)
	}
	if err := fd.AddProcess(ctx, "s1", 100); err != nil {
		t.Fatalf("AddProcess: %v", err)
	}
	if err := fd.DestroyScope(ctx, "s1"); err != nil {
		t.Fatalf("DestroyScope: %v", err)
	}
	if err := fd.AddProcess(ctx, "s1", 200); !errors.Is(err, ErrScopeNotFound) {
		t.Errorf("AddProcess after DestroyScope: got err=%v, want ErrScopeNotFound", err)
	}
}

func TestFakeDriver_DestroyScope_MissingErrors(t *testing.T) {
	fd := NewFakeDriver()
	ctx := context.Background()
	if err := fd.DestroyScope(ctx, "nope"); !errors.Is(err, ErrScopeNotFound) {
		t.Errorf("DestroyScope on missing scope: got err=%v, want ErrScopeNotFound", err)
	}
}

func TestFakeDriver_WatchEmpty_FiresWhenLastMemberRemoved(t *testing.T) {
	fd := NewFakeDriver()
	ctx := context.Background()

	if _, err := fd.CreateScope(ctx, "s1"); err != nil {
		t.Fatalf("CreateScope: %v", err)
	}
	if err := fd.AddProcess(ctx, "s1", 100); err != nil {
		t.Fatalf("AddProcess: %v", err)
	}

	ch, err := fd.WatchEmpty(ctx, "s1")
	if err != nil {
		t.Fatalf("WatchEmpty: %v", err)
	}

	select {
	case <-ch:
		t.Fatal("WatchEmpty: fired before scope became empty")
	default:
	}

	fd.RemoveProcess("s1", 100)

	select {
	case <-ch:
		// expected: channel closes/fires once scope is empty
	default:
		t.Fatal("WatchEmpty: did not fire after last member removed")
	}
}

func TestFakeDriver_WatchEmpty_MissingScopeErrors(t *testing.T) {
	fd := NewFakeDriver()
	ctx := context.Background()
	if _, err := fd.WatchEmpty(ctx, "nope"); !errors.Is(err, ErrScopeNotFound) {
		t.Errorf("WatchEmpty on missing scope: got err=%v, want ErrScopeNotFound", err)
	}
}

func TestFakeDriver_InjectedError(t *testing.T) {
	fd := NewFakeDriver()
	wantErr := errors.New("boom")
	fd.CreateScopeErr = wantErr

	ctx := context.Background()
	_, err := fd.CreateScope(ctx, "s1")
	if !errors.Is(err, wantErr) {
		t.Errorf("CreateScope with injected error: got %v, want %v", err, wantErr)
	}
}
