package wire

import (
	"net"
	"os"
	"syscall"
	"testing"
)

// unixSocketpair creates a real, connected AF_UNIX/SOCK_STREAM socketpair
// (kernel-backed, unlike net.Pipe which has no peer credentials at all) and
// wraps both ends as *net.UnixConn via net.FileConn. Using socketpair(2)
// instead of a listening socket on a filesystem path sidesteps macOS's
// short sun_path limit under deep t.TempDir() trees, while still exercising
// the exact same LOCAL_PEERCRED/SO_PEERCRED path a real ranad<->svc
// connection would.
func unixSocketpair(t *testing.T) (a, b *net.UnixConn) {
	t.Helper()

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("syscall.Socketpair: %v", err)
	}

	f0 := os.NewFile(uintptr(fds[0]), "wire-test-socketpair-0")
	f1 := os.NewFile(uintptr(fds[1]), "wire-test-socketpair-1")
	defer f0.Close()
	defer f1.Close()

	c0, err := net.FileConn(f0)
	if err != nil {
		t.Fatalf("net.FileConn(fds[0]): %v", err)
	}
	c1, err := net.FileConn(f1)
	if err != nil {
		c0.Close()
		t.Fatalf("net.FileConn(fds[1]): %v", err)
	}

	uc0, ok := c0.(*net.UnixConn)
	if !ok {
		t.Fatalf("expected *net.UnixConn, got %T", c0)
	}
	uc1, ok := c1.(*net.UnixConn)
	if !ok {
		t.Fatalf("expected *net.UnixConn, got %T", c1)
	}

	t.Cleanup(func() {
		uc0.Close()
		uc1.Close()
	})
	return uc0, uc1
}

// TestPeerCred_RealSocketpair exercises PeerCred end-to-end over a genuine
// kernel unix domain socketpair (CONTRACTS §internal/wire: "test the darwin
// path with a real unix socketpair"). Both ends are this same test process,
// so the peer uid must equal our own — that is the strongest self-contained
// assertion available without spawning a second process. This runs on both
// linux (SO_PEERCRED) and darwin (LOCAL_PEERCRED/Xucred) via the platform-
// specific implementations selected at build time.
func TestPeerCred_RealSocketpair(t *testing.T) {
	a, b := unixSocketpair(t)

	wantUID := uint32(os.Getuid())

	uidFromA, err := PeerCred(a)
	if err != nil {
		t.Fatalf("PeerCred(a): %v", err)
	}
	if uidFromA != wantUID {
		t.Fatalf("PeerCred(a) uid = %d, want %d (self-connect, same process)", uidFromA, wantUID)
	}

	uidFromB, err := PeerCred(b)
	if err != nil {
		t.Fatalf("PeerCred(b): %v", err)
	}
	if uidFromB != wantUID {
		t.Fatalf("PeerCred(b) uid = %d, want %d (self-connect, same process)", uidFromB, wantUID)
	}
}

// TestPeerCred_NilConn documents behavior for the one connection value every
// platform implementation must reject identically: a nil *net.UnixConn must
// return a named error, never panic.
func TestPeerCred_NilConn(t *testing.T) {
	_, err := PeerCred(nil)
	if err == nil {
		t.Fatal("expected error for nil *net.UnixConn, got nil")
	}
}
