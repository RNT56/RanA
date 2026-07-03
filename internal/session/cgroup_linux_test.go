//go:build linux

package session

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCgroupDriver_CreateScope(t *testing.T) {
	root := t.TempDir()
	d := &CgroupDriver{Root: root}
	ctx := context.Background()

	scope, err := d.CreateScope(ctx, "rana-test1")
	if err != nil {
		t.Fatalf("CreateScope: %v", err)
	}
	if scope.Name != "rana-test1" {
		t.Errorf("scope.Name = %q, want rana-test1", scope.Name)
	}

	want := filepath.Join(root, "rana.slice", "rana-test1.scope")
	if _, err := os.Stat(want); err != nil {
		t.Errorf("expected scope dir %s to exist: %v", want, err)
	}
}

func TestCgroupDriver_CreateScope_Duplicate(t *testing.T) {
	root := t.TempDir()
	d := &CgroupDriver{Root: root}
	ctx := context.Background()

	if _, err := d.CreateScope(ctx, "dup"); err != nil {
		t.Fatalf("first CreateScope: %v", err)
	}
	if _, err := d.CreateScope(ctx, "dup"); err != ErrScopeExists {
		t.Errorf("second CreateScope: got %v, want ErrScopeExists", err)
	}
}

func TestCgroupDriver_AddProcess_WritesProcs(t *testing.T) {
	root := t.TempDir()
	d := &CgroupDriver{Root: root}
	ctx := context.Background()

	if _, err := d.CreateScope(ctx, "s1"); err != nil {
		t.Fatalf("CreateScope: %v", err)
	}
	if err := d.AddProcess(ctx, "s1", 4242); err != nil {
		t.Fatalf("AddProcess: %v", err)
	}

	procsPath := filepath.Join(root, "rana.slice", "s1.scope", "cgroup.procs")
	data, err := os.ReadFile(procsPath)
	if err != nil {
		t.Fatalf("read cgroup.procs: %v", err)
	}
	if string(data) != "4242" {
		t.Errorf("cgroup.procs = %q, want %q", string(data), "4242")
	}
}

func TestCgroupDriver_AddProcess_MissingScope(t *testing.T) {
	root := t.TempDir()
	d := &CgroupDriver{Root: root}
	ctx := context.Background()

	if err := d.AddProcess(ctx, "nope", 1); err != ErrScopeNotFound {
		t.Errorf("AddProcess on missing scope: got %v, want ErrScopeNotFound", err)
	}
}

func TestCgroupDriver_DestroyScope(t *testing.T) {
	root := t.TempDir()
	d := &CgroupDriver{Root: root}
	ctx := context.Background()

	if _, err := d.CreateScope(ctx, "s1"); err != nil {
		t.Fatalf("CreateScope: %v", err)
	}
	if err := d.DestroyScope(ctx, "s1"); err != nil {
		t.Fatalf("DestroyScope: %v", err)
	}

	scopeDir := filepath.Join(root, "rana.slice", "s1.scope")
	if _, err := os.Stat(scopeDir); !os.IsNotExist(err) {
		t.Errorf("expected scope dir removed, stat err = %v", err)
	}
}

func TestCgroupDriver_DestroyScope_Missing(t *testing.T) {
	root := t.TempDir()
	d := &CgroupDriver{Root: root}
	ctx := context.Background()

	if err := d.DestroyScope(ctx, "nope"); err != ErrScopeNotFound {
		t.Errorf("DestroyScope on missing scope: got %v, want ErrScopeNotFound", err)
	}
}

func TestCgroupDriver_WatchEmpty_AlreadyEmpty(t *testing.T) {
	root := t.TempDir()
	d := &CgroupDriver{Root: root}
	ctx := context.Background()

	if _, err := d.CreateScope(ctx, "s1"); err != nil {
		t.Fatalf("CreateScope: %v", err)
	}
	scopeDir := filepath.Join(root, "rana.slice", "s1.scope")
	eventsPath := filepath.Join(scopeDir, "cgroup.events")
	if err := os.WriteFile(eventsPath, []byte("populated 0\nfrozen 0\n"), 0644); err != nil {
		t.Fatalf("write cgroup.events: %v", err)
	}

	ch, err := d.WatchEmpty(ctx, "s1")
	if err != nil {
		t.Fatalf("WatchEmpty: %v", err)
	}
	select {
	case <-ch:
		// expected: already empty, closes immediately
	case <-time.After(2 * time.Second):
		t.Fatal("WatchEmpty: channel did not close for an already-empty scope")
	}
}

func TestCgroupDriver_WatchEmpty_FiresOnTransition(t *testing.T) {
	root := t.TempDir()
	d := &CgroupDriver{Root: root}
	ctx := context.Background()

	if _, err := d.CreateScope(ctx, "s1"); err != nil {
		t.Fatalf("CreateScope: %v", err)
	}
	scopeDir := filepath.Join(root, "rana.slice", "s1.scope")
	eventsPath := filepath.Join(scopeDir, "cgroup.events")
	if err := os.WriteFile(eventsPath, []byte("populated 1\nfrozen 0\n"), 0644); err != nil {
		t.Fatalf("write cgroup.events: %v", err)
	}

	ch, err := d.WatchEmpty(ctx, "s1")
	if err != nil {
		t.Fatalf("WatchEmpty: %v", err)
	}

	select {
	case <-ch:
		t.Fatal("WatchEmpty: fired before transition to empty")
	case <-time.After(100 * time.Millisecond):
	}

	if err := os.WriteFile(eventsPath, []byte("populated 0\nfrozen 0\n"), 0644); err != nil {
		t.Fatalf("write cgroup.events: %v", err)
	}

	select {
	case <-ch:
		// expected
	case <-time.After(5 * time.Second):
		t.Fatal("WatchEmpty: did not fire after transition to empty")
	}
}

func TestCgroupDriver_WatchEmpty_MissingScope(t *testing.T) {
	root := t.TempDir()
	d := &CgroupDriver{Root: root}
	ctx := context.Background()

	if _, err := d.WatchEmpty(ctx, "nope"); err != ErrScopeNotFound {
		t.Errorf("WatchEmpty on missing scope: got %v, want ErrScopeNotFound", err)
	}
}
