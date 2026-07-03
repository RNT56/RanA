package session

import (
	"context"
	"sync"
)

// FakeDriver is an in-memory Driver implementation for tests. It never
// touches the filesystem, D-Bus, or any OS cgroup mechanism, so it is safe
// to use on any platform, including in darwin unit tests that exercise
// callers of the Driver interface (CONTRACTS §internal/session: "portable
// Driver interface + fake driver").
//
// FakeDriver is safe for concurrent use.
type FakeDriver struct {
	mu sync.Mutex

	// CreatedScopes records the names passed to CreateScope, in call
	// order, including names that were later destroyed. Useful for
	// asserting call sequences in tests.
	CreatedScopes []string

	scopes map[string]*fakeScope

	// CreateScopeErr, when non-nil, is returned by every call to
	// CreateScope instead of the normal result — for testing caller
	// error handling.
	CreateScopeErr error
}

type fakeScope struct {
	members  []int32
	watchers []chan struct{}
}

// NewFakeDriver returns a ready-to-use FakeDriver with no scopes.
func NewFakeDriver() *FakeDriver {
	return &FakeDriver{scopes: make(map[string]*fakeScope)}
}

// CreateScope implements Driver.
func (f *FakeDriver) CreateScope(ctx context.Context, name string) (Scope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.CreateScopeErr != nil {
		return Scope{}, f.CreateScopeErr
	}
	if _, ok := f.scopes[name]; ok {
		return Scope{}, ErrScopeExists
	}
	f.scopes[name] = &fakeScope{}
	f.CreatedScopes = append(f.CreatedScopes, name)
	return Scope{Name: name}, nil
}

// AddProcess implements Driver.
func (f *FakeDriver) AddProcess(ctx context.Context, scopeName string, pid int32) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	sc, ok := f.scopes[scopeName]
	if !ok {
		return ErrScopeNotFound
	}
	sc.members = append(sc.members, pid)
	return nil
}

// DestroyScope implements Driver.
func (f *FakeDriver) DestroyScope(ctx context.Context, scopeName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.scopes[scopeName]; !ok {
		return ErrScopeNotFound
	}
	delete(f.scopes, scopeName)
	return nil
}

// WatchEmpty implements Driver.
func (f *FakeDriver) WatchEmpty(ctx context.Context, scopeName string) (<-chan struct{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	sc, ok := f.scopes[scopeName]
	if !ok {
		return nil, ErrScopeNotFound
	}
	ch := make(chan struct{})
	if len(sc.members) == 0 {
		close(ch)
		return ch, nil
	}
	sc.watchers = append(sc.watchers, ch)
	return ch, nil
}

// Members returns the current pid membership of scopeName, in the order
// they were added, for test assertions. Returns nil for an unknown scope.
func (f *FakeDriver) Members(scopeName string) []int32 {
	f.mu.Lock()
	defer f.mu.Unlock()

	sc, ok := f.scopes[scopeName]
	if !ok {
		return nil
	}
	out := make([]int32, len(sc.members))
	copy(out, sc.members)
	return out
}

// RemoveProcess removes pid from scopeName's membership (simulating the
// process exiting or migrating out) and fires any pending WatchEmpty
// channels if the scope becomes empty as a result. It is a no-op if the
// scope or pid is not found.
func (f *FakeDriver) RemoveProcess(scopeName string, pid int32) {
	f.mu.Lock()
	defer f.mu.Unlock()

	sc, ok := f.scopes[scopeName]
	if !ok {
		return
	}
	for i, m := range sc.members {
		if m == pid {
			sc.members = append(sc.members[:i], sc.members[i+1:]...)
			break
		}
	}
	if len(sc.members) == 0 {
		for _, ch := range sc.watchers {
			close(ch)
		}
		sc.watchers = nil
	}
}
