# RanA macOS guest image (Buildroot external tree)

On macOS, RanA records what runs **inside a Linux guest VM** and nothing else
(D2/D15, `docs/MACOS.md`). This directory builds that guest image. It is the
*same* capture stack as Linux, running inside a Buildroot-built Linux guest —
not a second implementation.

> **Builds on a Linux host or CI only.** Buildroot itself needs a Linux build
> host (its toolchain, kernel build, and rootfs assembly are Linux-native).
> `make guest` at the repo root no-ops with a message on darwin and delegates
> here (`make -C guest`) on Linux/CI. See the root `Makefile`.

---

## The three layers (D15, `docs/MACOS.md §1`, `docs/ARCHITECTURE.md §6`)

RanA's guest is **layered** so real agents can actually *run*, not merely be
recorded:

1. **Base layer** — this Buildroot image. A minimal Linux with a BTF-enabled
   kernel (the D7 eBPF hooks need CO-RE/BTF), virtiofs, overlayfs, cgroup2,
   and vsock; a tiny initramfs; and `ranad` + the guest-side `rana` service
   baked in. Target **≤60MB**, reproducible, checksum-pinned, and **embedded
   in the host `rana` binary** via `go:embed`. Built here.

2. **Runtime layer** — Node.js LTS + git + a POSIX toolchain: what OpenClaw
   and Claude Code (both Node apps) need to run. Target **≤150MB**,
   reproducible, **fetched once with a signature check** to
   `~/Library/Application Support/rana/`. Built by `runtime/build.sh` (it
   fetches a pinned Node.js LTS linux-arm64 tarball and verifies its published
   SHA256 before laying it onto the layer). Not embedded — too large, and it
   updates on a different cadence than the base image.

3. **Data volume** — a persistent, host-file-backed ext4 image for guest-side
   installs (agent code, Linux `node_modules`; host `node_modules` contain
   Mach-O native addons that cannot run in a Linux guest). Created at runtime
   by `internal/vm`, not built here.

The **ledger is written on the host**, never in the guest — a fully
compromised guest can suppress its own *future* events but cannot rewrite
host-persisted history (the trust property in `LIMITS.md §1.5`).

---

## Layout

```
guest/
├── README.md                       # this file
├── Makefile                        # docker-less Buildroot invocation (Linux/CI)
├── configs/
│   └── rana_guest_defconfig        # Buildroot defconfig: aarch64 virt, minimal
├── board/rana/
│   └── kernel.fragment             # extra kernel CONFIG the D7 hooks need
└── runtime/
    └── build.sh                    # fetch+verify Node LTS -> runtime layer
```

`configs/rana_guest_defconfig` sets `BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES`
to `board/rana/kernel.fragment`, so Buildroot merges those options into the
kernel `.config`.

---

## Building the base layer (Linux host / CI)

Buildroot is fetched as a pinned tarball (version + SHA256 pinned in
`Makefile`) and invoked out-of-tree with this directory as
`BR2_EXTERNAL`:

```sh
make -C guest all        # or, from the repo root on Linux: make guest
```

Outputs land in `guest/output/images/` (kernel `Image`, `rootfs`,
initramfs). The root `make gen`/release pipeline embeds the pinned base image
into the host binary.

## Building the runtime layer

```sh
sh guest/runtime/build.sh    # fetches + verifies Node LTS, assembles the layer
```

The script marks its single network step clearly and **fails closed** on a
checksum mismatch — an unverified toolchain never lands on the layer.

---

## Reproducibility (D23/G8)

The image must be byte-reproducible so two machines produce the same checksum
(gate G8):

- **Pin everything**: Buildroot version + hash, kernel version + fragment,
  Node.js version + published SHA256. No "latest".
- **`SOURCE_DATE_EPOCH`** is exported by the `Makefile` to pin timestamps in
  the rootfs/initramfs.
- Buildroot's own reproducible-build options
  (`BR2_REPRODUCIBLE=y`) are set in the defconfig.
- The runtime tarball is content-addressed by its SHA256; the layer assembly
  is deterministic (sorted `tar`, fixed uid/gid/mtime).

The base-image checksum is pinned in code (the embedded-image resolver in
`internal/vm` compares against it); a mismatch is a hard failure, not a
warning.

---

## Notes / honest limits

- virtiofs delivers no inotify for host-side changes and has weaker lock
  semantics; the guest never uses virtiofs as rootfs (avoids the documented
  uid/gid rootfs breakage). See `docs/MACOS.md §4` / `LIMITS.md §5`.
- Guest agent uid is pinned to 1000; a mount-time normalization maps
  ownership so tools behave.
- Project toolchains beyond the runtime layer (compilers, interpreters) are
  user-provisioned in-guest (`rana vm shell`).
