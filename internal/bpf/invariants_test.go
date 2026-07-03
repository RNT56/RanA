package bpf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoBlockingOrWriteHelpers is the CI-critical P2 invariant grep
// (CLAUDE.md invariant 4: "Observe-mode hooks have no bpf_probe_write,
// no return-value override, no blocking helper"; CONTRACTS §internal/bpf:
// "NONE of the C may use bpf_probe_write_user, bpf_send_signal, or
// bpf_override_return"). It fails the build if any forbidden symbol
// appears anywhere in bpf/src/*.c or bpf/src/*.h — observation must stay
// inert (P2): "If ranad dies, agents keep running" and "no code in
// observe mode may block, delay meaningfully, modify, or proxy a
// syscall".
func TestNoBlockingOrWriteHelpers(t *testing.T) {
	forbidden := []string{
		"bpf_probe_write_user",
		"bpf_send_signal",
		"bpf_override_return",
	}

	root := filepath.Join("..", "..", "bpf", "src")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading %s: %v", root, err)
	}

	found := false
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".c") && !strings.HasSuffix(name, ".h") {
			continue
		}
		found = true
		path := filepath.Join(root, name)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		src := string(b)
		for _, sym := range forbidden {
			if strings.Contains(src, sym) {
				t.Errorf("P2 VIOLATION: %s contains forbidden helper %q — observe mode must never block, delay, modify, or proxy a syscall", path, sym)
			}
		}
	}

	if !found {
		t.Fatalf("no .c/.h files found under %s — invariant grep has nothing to check (this test would silently pass on an empty tree, which defeats its purpose)", root)
	}
}

// TestNoEnvpOrEnvironRead is CLAUDE.md invariant 1 ("No path reads envp
// or /proc/<pid>/environ") applied to the C sources: envp must never be
// read anywhere in this project (P3).
func TestNoEnvpOrEnvironRead(t *testing.T) {
	forbidden := []string{
		"/proc/self/environ",
		"bpf_get_current_envp", // not a real helper, but guards against a
		// hypothetical future mistake reading env via a made-up name.
	}

	root := filepath.Join("..", "..", "bpf", "src")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading %s: %v", root, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".c") && !strings.HasSuffix(name, ".h") {
			continue
		}
		path := filepath.Join(root, name)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		src := string(b)
		for _, sym := range forbidden {
			if strings.Contains(src, sym) {
				t.Errorf("P3 VIOLATION: %s references %q — envp/environ must never be read anywhere", path, sym)
			}
		}
		// "environ" as a bare substring would also flag legitimate
		// words (none expected here), so additionally guard the
		// specific field access pattern task->mm->env_start/env_end,
		// which is the shape an accidental envp read would take in
		// this codebase (argv reads bprm->mm->arg_start/arg_end
		// deliberately; env_start/env_end must never appear).
		if strings.Contains(src, "env_start") || strings.Contains(src, "env_end") {
			t.Errorf("P3 VIOLATION: %s references env_start/env_end (envp bounds) — envp must never be read", path)
		}
	}
}
