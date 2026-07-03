//go:build linux

package session

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// watchCgroupEmpty watches path (a cgroup.events file) via inotify and
// returns a channel that closes the moment "populated" reads 0 — either
// because the file already reads 0 at watch time, or because a subsequent
// IN_MODIFY wakes us and re-read shows 0.
//
// The returned channel is closed exactly once. The watcher goroutine exits
// after firing, on ctx cancellation, or on an unrecoverable read error (in
// which case the channel is also closed, so callers do not block forever
// on a broken watch — losing scope-empty detection is a liveness
// degradation, not a correctness one: the ledger and chain are unaffected,
// P2/P4).
func watchCgroupEmpty(ctx context.Context, path string) (<-chan struct{}, error) {
	initial, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("session: read %s: %w", path, err)
	}
	populated, err := isCgroupPopulated(initial)
	if err != nil {
		return nil, err
	}

	done := make(chan struct{})
	if !populated {
		close(done)
		return done, nil
	}

	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("session: inotify_init1: %w", err)
	}
	wd, err := unix.InotifyAddWatch(fd, path, unix.IN_MODIFY)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("session: inotify_add_watch %s: %w", path, err)
	}

	go func() {
		defer func() {
			unix.InotifyRmWatch(fd, uint32(wd))
			unix.Close(fd)
		}()

		buf := make([]byte, 4096)
		for {
			select {
			case <-ctx.Done():
				close(done)
				return
			default:
			}

			n, err := unix.Read(fd, buf)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				close(done)
				return
			}
			if n <= 0 {
				continue
			}

			data, err := os.ReadFile(path)
			if err != nil {
				close(done)
				return
			}
			populated, err := isCgroupPopulated(data)
			if err != nil {
				continue
			}
			if !populated {
				close(done)
				return
			}
		}
	}()

	return done, nil
}
