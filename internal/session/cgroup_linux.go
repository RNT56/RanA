//go:build linux

package session

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// cgroupRoot is the standard cgroup v2 mount point. It is a var (not a
// const) so tests running on a real Linux host can point it at a tmpdir
// that mimics the layout, without touching the real host cgroup tree.
var cgroupRoot = "/sys/fs/cgroup"

// CgroupDriver is the raw-cgroupfs fallback Driver (plan §6.1,
// docs/ARCHITECTURE.md §3): used when systemd/D-Bus is unavailable
// (containers, minimal distros, cgroup-namespaced environments). It
// creates rana.slice/rana-<id>.scope directly via mkdir + cgroup.procs
// writes. It does not write cgroup.subtree_control: RanA's cgid
// attribution needs no controller enabled at all (see CreateScope), so
// there is nothing for this driver to opt in on the bare hierarchy.
//
// CgroupDriver performs no privilege elevation itself; it requires the
// caller (ranad / rana, typically root for cgroup management) to already
// have write access to cgroupRoot.
type CgroupDriver struct {
	// Root overrides the cgroup v2 mount point; defaults to
	// cgroupRoot ("/sys/fs/cgroup") when empty. Tests set this to a
	// t.TempDir()-backed directory tree that mimics cgroupfs.
	Root string
}

var _ Driver = (*CgroupDriver)(nil)

func (d *CgroupDriver) root() string {
	if d.Root != "" {
		return d.Root
	}
	return cgroupRoot
}

func (d *CgroupDriver) slicePath() string {
	return filepath.Join(d.root(), SliceName())
}

func (d *CgroupDriver) scopePath(name string) string {
	return filepath.Join(d.slicePath(), name+".scope")
}

// CreateScope implements Driver: mkdir rana.slice (if absent), then mkdir
// the leaf scope directory. It intentionally does not touch
// cgroup.subtree_control: cgid attribution needs no controller enabled at
// all — cgroup id filtering works on the bare hierarchy. Operators who
// want memory/pids accounting on the slice can enable controllers
// themselves; RanA does not require it and does not write that file.
func (d *CgroupDriver) CreateScope(ctx context.Context, name string) (Scope, error) {
	if err := ctx.Err(); err != nil {
		return Scope{}, err
	}

	slice := d.slicePath()
	if err := os.MkdirAll(slice, 0755); err != nil {
		return Scope{}, fmt.Errorf("session: create slice dir %s: %w", slice, err)
	}

	scope := d.scopePath(name)
	if _, err := os.Stat(scope); err == nil {
		return Scope{}, ErrScopeExists
	} else if !os.IsNotExist(err) {
		return Scope{}, fmt.Errorf("session: stat scope dir %s: %w", scope, err)
	}

	if err := os.Mkdir(scope, 0755); err != nil {
		if os.IsExist(err) {
			return Scope{}, ErrScopeExists
		}
		return Scope{}, fmt.Errorf("session: create scope dir %s: %w", scope, err)
	}

	return Scope{Name: name}, nil
}

// AddProcess implements Driver: writes pid to the scope's cgroup.procs,
// which the kernel treats as "migrate this pid into this cgroup" (and by
// extension every future descendant, per docs/ARCHITECTURE.md §1).
func (d *CgroupDriver) AddProcess(ctx context.Context, scopeName string, pid int32) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	scope := d.scopePath(scopeName)
	if _, err := os.Stat(scope); os.IsNotExist(err) {
		return ErrScopeNotFound
	} else if err != nil {
		return fmt.Errorf("session: stat scope dir %s: %w", scope, err)
	}

	procsPath := filepath.Join(scope, "cgroup.procs")
	if err := os.WriteFile(procsPath, []byte(strconv.FormatInt(int64(pid), 10)), 0644); err != nil {
		return fmt.Errorf("session: write %s: %w", procsPath, err)
	}
	return nil
}

// DestroyScope implements Driver: removes the (assumed-empty) scope
// directory. The kernel refuses rmdir on a cgroup that still has member
// processes, so callers should only call this after WatchEmpty fires.
func (d *CgroupDriver) DestroyScope(ctx context.Context, scopeName string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	scope := d.scopePath(scopeName)
	if err := os.Remove(scope); err != nil {
		if os.IsNotExist(err) {
			return ErrScopeNotFound
		}
		return fmt.Errorf("session: remove scope dir %s: %w", scope, err)
	}
	return nil
}

// WatchEmpty implements Driver via inotify on the scope's cgroup.events
// file (see cgroup_watch_linux.go for the inotify plumbing), reporting
// once the kernel-maintained "populated" field transitions to 0.
func (d *CgroupDriver) WatchEmpty(ctx context.Context, scopeName string) (<-chan struct{}, error) {
	scope := d.scopePath(scopeName)
	eventsPath := filepath.Join(scope, "cgroup.events")
	if _, err := os.Stat(eventsPath); os.IsNotExist(err) {
		return nil, ErrScopeNotFound
	} else if err != nil {
		return nil, fmt.Errorf("session: stat %s: %w", eventsPath, err)
	}

	return watchCgroupEmpty(ctx, eventsPath)
}
