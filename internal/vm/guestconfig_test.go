package vm

import (
	"testing"
)

func TestBuildKernelCmdlineGolden(t *testing.T) {
	cfg := GuestConfig{
		DataVolumePath: "/Users/alice/Library/Application Support/rana/data.img",
		Mounts: []Mount{
			{Tag: "work", HostRoot: "/Users/alice/proj"},
		},
		VsockCID: 3,
		GuestUID: 1000,
	}

	got := cfg.KernelCmdline()
	want := "console=hvc0 root=/dev/vda rw init=/sbin/rana-init panic=1"
	if got != want {
		t.Fatalf("KernelCmdline() = %q, want %q", got, want)
	}
}

func TestBuildKernelCmdlineIsDeterministic(t *testing.T) {
	cfg := GuestConfig{
		DataVolumePath: "/x/data.img",
		VsockCID:       3,
		GuestUID:       1000,
	}
	a := cfg.KernelCmdline()
	b := cfg.KernelCmdline()
	if a != b {
		t.Fatalf("KernelCmdline() not deterministic: %q vs %q", a, b)
	}
}

func TestVirtiofsTagsGolden(t *testing.T) {
	cfg := GuestConfig{
		DataVolumePath: "/x/data.img",
		Mounts: []Mount{
			{Tag: "zzz", HostRoot: "/Users/alice/z"},
			{Tag: "aaa", HostRoot: "/Users/alice/a"},
			{Tag: "work", HostRoot: "/Users/alice/proj"},
		},
		VsockCID: 3,
		GuestUID: 1000,
	}

	got := cfg.VirtiofsTags()
	want := []VirtiofsTag{
		{Tag: "aaa", HostRoot: "/Users/alice/a", GuestMountPath: "/mnt/host/aaa"},
		{Tag: "work", HostRoot: "/Users/alice/proj", GuestMountPath: "/mnt/host/work"},
		{Tag: "zzz", HostRoot: "/Users/alice/z", GuestMountPath: "/mnt/host/zzz"},
	}
	if len(got) != len(want) {
		t.Fatalf("VirtiofsTags() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("VirtiofsTags()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestVirtiofsTagsEmptyMounts(t *testing.T) {
	cfg := GuestConfig{DataVolumePath: "/x/data.img", VsockCID: 3, GuestUID: 1000}
	got := cfg.VirtiofsTags()
	if len(got) != 0 {
		t.Fatalf("VirtiofsTags() on empty mounts = %+v, want empty", got)
	}
}

func TestGuestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     GuestConfig
		wantErr bool
	}{
		{
			name: "valid minimal",
			cfg: GuestConfig{
				DataVolumePath: "/x/data.img",
				VsockCID:       3,
				GuestUID:       1000,
			},
			wantErr: false,
		},
		{
			name: "missing data volume path",
			cfg: GuestConfig{
				VsockCID: 3,
				GuestUID: 1000,
			},
			wantErr: true,
		},
		{
			name: "zero vsock cid",
			cfg: GuestConfig{
				DataVolumePath: "/x/data.img",
				VsockCID:       0,
				GuestUID:       1000,
			},
			wantErr: true,
		},
		{
			name: "duplicate mount tag",
			cfg: GuestConfig{
				DataVolumePath: "/x/data.img",
				VsockCID:       3,
				GuestUID:       1000,
				Mounts: []Mount{
					{Tag: "work", HostRoot: "/a"},
					{Tag: "work", HostRoot: "/b"},
				},
			},
			wantErr: true,
		},
		{
			name: "guest uid zero (root) rejected",
			cfg: GuestConfig{
				DataVolumePath: "/x/data.img",
				VsockCID:       3,
				GuestUID:       0,
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("Validate() = nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestGuestConfigDefaultGuestUIDIsPinned1000(t *testing.T) {
	// docs/ARCHITECTURE.md §6.2 / plan D15: "Guest agent uid pinned
	// 1000".
	if DefaultGuestUID != 1000 {
		t.Fatalf("DefaultGuestUID = %d, want 1000", DefaultGuestUID)
	}
}
