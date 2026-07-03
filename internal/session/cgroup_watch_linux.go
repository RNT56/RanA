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
//
// ctx cancellation must interrupt a blocking read promptly: a cgroup that
// never transitions again (e.g. its scope-empty event already fired, or
// the caller gave up waiting) would otherwise leave unix.Read(fd, buf)
// parked forever, leaking the goroutine and the inotify fd/watch for the
// life of the process — a real resource leak in a long-lived daemon that
// starts and cancels many watches over its lifetime. The watch fd is
// polled alongside a self-pipe that ctx cancellation closes, so the read
// syscall itself is only ever attempted when data is actually ready.
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

	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("session: inotify_init1: %w", err)
	}
	wd, err := unix.InotifyAddWatch(fd, path, unix.IN_MODIFY)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("session: inotify_add_watch %s: %w", path, err)
	}

	// Self-pipe: ctx.Done() closes the write end (via wakeR/wakeW below) so
	// the poll() call below wakes up immediately on cancellation instead of
	// only ever waking up on the next inotify event, which may never come.
	wakeR, wakeW, err := os.Pipe()
	if err != nil {
		unix.InotifyRmWatch(fd, uint32(wd))
		unix.Close(fd)
		return nil, fmt.Errorf("session: creating wake pipe: %w", err)
	}

	go func() {
		<-ctx.Done()
		wakeW.Close()
	}()

	go func() {
		defer func() {
			unix.InotifyRmWatch(fd, uint32(wd))
			unix.Close(fd)
			wakeR.Close()
		}()

		wakeFd := int(wakeR.Fd())
		buf := make([]byte, 4096)
		for {
			if ctx.Err() != nil {
				close(done)
				return
			}

			pfds := []unix.PollFd{
				{Fd: int32(fd), Events: unix.POLLIN},
				{Fd: int32(wakeFd), Events: unix.POLLIN},
			}
			_, err := unix.Poll(pfds, -1)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				close(done)
				return
			}
			if ctx.Err() != nil {
				close(done)
				return
			}
			if pfds[1].Revents != 0 {
				// Wake pipe closed by ctx cancellation.
				close(done)
				return
			}
			if pfds[0].Revents == 0 {
				continue
			}

			n, err := unix.Read(fd, buf)
			if err != nil {
				if err == unix.EAGAIN || err == unix.EINTR {
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
