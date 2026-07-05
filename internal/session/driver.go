package session

import (
	"context"
	"errors"
)

// ErrScopeExists is returned by Driver.CreateScope when a scope with the
// given name already exists.
var ErrScopeExists = errors.New("session: scope already exists")

// ErrScopeNotFound is returned by Driver methods that operate on a scope
// name the driver does not know about.
var ErrScopeNotFound = errors.New("session: scope not found")

// Scope identifies a created cgroup v2 leaf: RanA's one-cgroup-per-session
// attribution primitive (docs/ARCHITECTURE.md §1). Name is the bare
// scope name (e.g. "rana-01ARZ3NDEKTSV4RRFFQ69G5FAV"), without a leading
// slice path or trailing ".scope" suffix — drivers append platform-specific
// decoration as needed.
type Scope struct {
	// Name is the session-scoped identifier, normally "rana-<sessionID>".
	Name string
	// Cgid is the cgroup v2 id of the created leaf: the kernel's kn->id,
	// which on cgroup v2 equals the scope directory's inode number (the
	// value bpf_get_current_cgroup_id / rana_task_cgid report in-kernel,
	// confirmed equal by the multi-kernel harness). It is what svc hands
	// ranad via wire.SessionStart to arm capture. 0 on platforms/drivers
	// that do not resolve it (never Linux cgroupfs/systemd, which do).
	Cgid uint64
}

// Driver abstracts the mechanism that places processes into a session's
// cgroup leaf: a systemd transient scope via D-Bus when systemd is present,
// or a raw cgroupfs mkdir+write fallback otherwise
// (docs/ARCHITECTURE.md §3). It is intentionally minimal and platform-
// agnostic so the linux-only implementations are thin shims over this
// contract, and so the rest of RanA (and tests) can depend on the
// interface rather than a concrete cgroup mechanism.
//
// All methods take a context for cancellation/timeout; drivers that talk to
// D-Bus or the filesystem should respect ctx cancellation where practical.
type Driver interface {
	// CreateScope creates a new, empty session scope. It returns
	// ErrScopeExists if a scope with this name already exists.
	CreateScope(ctx context.Context, name string) (Scope, error)

	// AddProcess places pid into the named scope (a `--pid N` migration,
	// or seeding the scope with the freshly exec'd child of `rana run`).
	// It returns ErrScopeNotFound if the scope does not exist.
	AddProcess(ctx context.Context, scopeName string, pid int32) error

	// DestroyScope removes bookkeeping for a scope once it is empty. It
	// returns ErrScopeNotFound if the scope does not exist. Drivers are
	// not required to forcibly evict remaining members; callers should
	// only destroy scopes they know to be empty (see WatchEmpty).
	DestroyScope(ctx context.Context, scopeName string) error

	// WatchEmpty returns a channel that is closed once the named scope
	// transitions to having zero member processes (cgroup.events
	// "populated 0" on Linux). It returns ErrScopeNotFound if the scope
	// does not exist at call time.
	WatchEmpty(ctx context.Context, scopeName string) (<-chan struct{}, error)
}
