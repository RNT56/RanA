//go:build linux && rana_bpf_generated && bpf_harness

package bpf

// harness_linux_test.go is the real-kernel end-to-end harness: it loads
// the generated CO-RE objects through the production NewLoader path,
// attaches every wanted program, registers a fresh cgroup as a session,
// runs a child process inside it, and asserts the kernel-truth events
// (proc.exec, fs write-open, fs sensitive-read) arrive on the ring
// buffer with correct attribution — and that nothing outside the session
// leaks in (the in-kernel filter, P6).
//
// It runs ONLY where all three build tags are set AND RANA_BPF_TESTS=1
// AND euid==0 — i.e. inside the ebpf-kernels.yml VM matrix (kernels
// 5.15/6.1/6.6/bpf-next), never on a developer laptop or the pure-Go CI
// lane. This is the gate that makes "the collector works" a tested claim
// instead of an assumed one: compile-check (ci.yml) proves codegen;
// THIS proves the verifier accepts every program, every attach point
// exists on each supported kernel, and events flow end-to-end.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/RNT56/RanA/internal/collector"
)

// requireHarnessEnv skips unless this is the real-kernel harness
// environment (explicit opt-in + root). Never runs implicitly.
func requireHarnessEnv(t *testing.T) {
	t.Helper()
	if os.Getenv("RANA_BPF_TESTS") != "1" {
		t.Skip("RANA_BPF_TESTS != 1 — kernel harness not requested")
	}
	if os.Geteuid() != 0 {
		t.Skip("kernel harness requires root (run inside the ebpf-kernels VM)")
	}
}

// makeSessionCgroup creates a fresh cgroup-v2 leaf and returns its path
// and cgid (on cgroup v2 the cgroup id IS the inode number of the cgroup
// directory — the same kn_id rana_task_cgid reads in-kernel).
func makeSessionCgroup(t *testing.T) (path string, cgid uint64) {
	t.Helper()
	path = filepath.Join("/sys/fs/cgroup", "rana-harness-"+t.Name())
	if err := os.Mkdir(path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatalf("creating session cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat session cgroup: %v", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat sys is %T, want *syscall.Stat_t", fi.Sys())
	}
	return path, st.Ino
}

// runInCgroup runs argv inside the given cgroup, entering it at clone
// time (CgroupFD + CLONE_INTO_CGROUP) so even the exec event itself is
// attributed to the session — exactly how rana run places real agents.
func runInCgroup(t *testing.T, cgroupPath string, argv ...string) {
	t.Helper()
	fd, err := syscall.Open(cgroupPath, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("opening cgroup dir: %v", err)
	}
	defer syscall.Close(fd)

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running %v in cgroup: %v (output: %s)", argv, err, out)
	}
}

// drainEvents reads ring-buffer records until deadline, handing each raw
// sample to fn. Returns when fn says done or the deadline passes.
func drainEvents(t *testing.T, rd *ringbuf.Reader, timeout time.Duration, fn func(raw []byte) (done bool)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rd.SetDeadline(time.Now().Add(200 * time.Millisecond))
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			t.Fatalf("ring buffer read: %v", err)
		}
		if fn(rec.RawSample) {
			return
		}
	}
}

// mustNewLoader constructs the loader, failing with the FULL verifier
// log on a load rejection. The VerifierError must be unwrapped with
// errors.As first: fmt.Errorf wrappers don't forward fmt.Formatter, so
// %+v on the wrapped chain still truncates — and the truncated tail is
// exactly where the rejected instruction's context lives.
func mustNewLoader(t *testing.T) (*Loader, *GapDescriptor) {
	t.Helper()
	loader, gap, err := NewLoader(AttachOptions{})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("NewLoader: %v\n--- full verifier log ---\n%+v", err, verr)
		}
		t.Fatalf("NewLoader: %v", err)
	}
	return loader, gap
}

// TestKernelHarness_EndToEnd is the flagship real-kernel test: load,
// attach, record a session, verify kernel-truth attribution.
func TestKernelHarness_EndToEnd(t *testing.T) {
	requireHarnessEnv(t)

	loader, gap := mustNewLoader(t)
	defer loader.Close()
	t.Logf("attached at tier %v; restart gap: %v; lsm degraded: %q",
		loader.Tier(), gap != nil, loader.LSMDegraded())

	cgPath, cgid := makeSessionCgroup(t)
	if err := loader.RegisterSession(cgid); err != nil {
		t.Fatalf("RegisterSession(%d): %v", cgid, err)
	}
	defer loader.UnregisterSession(cgid)

	// A watchlisted "credential" file for the D9 sensitive-read leg. On
	// the ROOT mount deliberately: the in-kernel resolve walk follows
	// d_parent within one mount (mount-relative paths — LIMITS.md), so a
	// tmpfs /tmp file would resolve as /rana-harness-secret and the
	// exact-length prefix lookup would miss. Registering and creating on
	// the root fs keeps this test about capture, not mount semantics.
	secret := "/rana-harness-secret"
	if err := os.WriteFile(secret, []byte("not-a-real-secret\n"), 0o600); err != nil {
		t.Fatalf("writing watchlisted file: %v", err)
	}
	defer os.Remove(secret)
	if err := loader.AddSensitivePrefix(secret, 42); err != nil {
		t.Fatalf("AddSensitivePrefix: %v", err)
	}

	// The recorded workload: one exec (sh), a write-open, and a read of
	// the watchlisted path.
	outFile := "/tmp/rana-harness-out"
	defer os.Remove(outFile)
	runInCgroup(t, cgPath, "/bin/sh", "-c",
		"echo recorded > "+outFile+" && cat "+secret+" > /dev/null")

	var (
		sawExec          bool
		sawWriteOpen     bool
		sawSensitiveRead bool
		execComm         string
	)
	drainEvents(t, loader.Events(), 5*time.Second, func(raw []byte) bool {
		if len(raw) < 2 {
			t.Fatalf("runt record: % x", raw)
		}
		switch raw[1] {
		case collector.RecordKindExec:
			rec, derr := collector.DecodeExecRecord(raw)
			if derr != nil {
				t.Fatalf("DecodeExecRecord: %v", derr)
			}
			if rec.Cgid != cgid {
				t.Errorf("exec event leaked from cgid %d (session filter broken, want only %d)", rec.Cgid, cgid)
			}
			if rec.Comm == "sh" {
				sawExec = true
				execComm = rec.Comm
				if !strings.HasSuffix(rec.ExePath, "sh") {
					t.Errorf("exec exe_path = %q, want a resolved …/sh path", rec.ExePath)
				}
			}
		case collector.RecordKindFsOp:
			rec, derr := collector.DecodeFsOpRecord(raw)
			if derr != nil {
				t.Fatalf("DecodeFsOpRecord: %v", derr)
			}
			if rec.Cgid != cgid {
				t.Errorf("fsop event leaked from cgid %d (want only %d)", rec.Cgid, cgid)
			}
			switch {
			case rec.Op == collector.FsOpWriteOpen && strings.HasSuffix(rec.Path, "rana-harness-out"):
				sawWriteOpen = true
				if rec.PathSource != collector.PathSourceKindResolved {
					t.Errorf("write-open path_source = %v, want resolved (kernel dentry walk)", rec.PathSource)
				}
			case rec.Op == collector.FsOpSensitiveRead && strings.HasSuffix(rec.Path, "rana-harness-secret"):
				sawSensitiveRead = true
				if rec.Mode != 42 {
					t.Errorf("sensitive-read rule id = %d, want 42", rec.Mode)
				}
			}
		}
		return sawExec && sawWriteOpen && sawSensitiveRead
	})

	if !sawExec {
		t.Error("no proc.exec event for the in-session sh (kernel-truth exec capture failed)")
	}
	if !sawWriteOpen {
		t.Error("no fs write-open event for the in-session file write")
	}
	if !sawSensitiveRead {
		t.Error("no fs sensitive-read event for the watchlisted path (D9 trifecta precursor dead on this kernel)")
	}
	t.Logf("end-to-end OK: exec(%s) + write-open + sensitive-read, all attributed to cgid %d", execComm, cgid)
}

// TestKernelHarness_OutOfSessionSilence proves the in-kernel filter: a
// process OUTSIDE any registered session must produce zero events (P6 —
// non-session noise never reaches the ring buffer; also the privacy
// posture: RanA records sessions, not the host).
func TestKernelHarness_OutOfSessionSilence(t *testing.T) {
	requireHarnessEnv(t)

	loader, _ := mustNewLoader(t)
	defer loader.Close()

	// No session registered. Run a workload in a fresh cgroup anyway.
	cgPath, _ := makeSessionCgroup(t)
	runInCgroup(t, cgPath, "/bin/sh", "-c", "echo unrecorded > /tmp/rana-harness-noise && rm -f /tmp/rana-harness-noise")

	leaked := 0
	drainEvents(t, loader.Events(), 1500*time.Millisecond, func(raw []byte) bool {
		leaked++
		return false
	})
	if leaked > 0 {
		t.Errorf("%d events reached the ring buffer with no session registered (in-kernel filter is not filtering)", leaked)
	}
}

// TestKernelHarness_ReattachIdempotent proves a second NewLoader over the
// pins the first left behind (a ranad restart) constructs cleanly and
// reports the restart as a gap descriptor (P5: losses are loud).
func TestKernelHarness_ReattachIdempotent(t *testing.T) {
	requireHarnessEnv(t)

	l1, _ := mustNewLoader(t)
	if err := l1.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	l2, gap := mustNewLoader(t)
	defer l2.Close()
	if gap == nil {
		t.Error("second NewLoader reported no restart gap despite pins from the first (P5: the window between the two must be loud)")
	} else if gap.Reason != GapReasonDaemonRestart {
		t.Errorf("gap reason = %v, want daemon_restart", gap.Reason)
	}
}
