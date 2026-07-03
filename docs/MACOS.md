# macOS — How RanA Records on a Mac

The short version: **macOS records what runs inside RanA's Linux guest VM, and nothing else.** Apple gates native process recording (Endpoint Security) behind case-by-case entitlements that are closed to open-source distribution, so there is no native macOS collector — a natively-running agent produces zero events, and RanA tells you that instead of showing a partial timeline. The guest is not a degraded port: it is the *same* capture stack as Linux, byte for byte (`docs/ARCHITECTURE.md §6`).

Requirements: macOS ≥ 13 (Ventura), Apple Silicon primary (Intel best-effort). VM save/restore (instant warm starts) needs macOS ≥ 14.

---

## 1. The pieces

| Piece | What it is | Where it lives |
|---|---|---|
| **Base layer** | Buildroot Linux: BTF kernel, virtiofs, overlayfs, `ranad` + guest service. ≤60MB, reproducible, checksum-pinned. | Embedded in the `rana` binary. |
| **Runtime layer** | Node.js LTS + git + POSIX toolchain — what OpenClaw and Claude Code (both Node apps) need to *run*. ≤150MB, reproducible. | Fetched once, signature-checked, to `~/Library/Application Support/rana/`. |
| **Data volume** | Persistent ext4 disk image for guest-side installs (agent code, `node_modules`). | `~/Library/Application Support/rana/`. |
| **Projections** | Each granted host dir → one virtiofs tag, mounted `/mnt/host/<name>` in-guest; paths translated back in the timeline. | Configured per session/adopt. |
| **Port-forward** | vsock↔TCP proxy re-exposing adopted services' guest ports (e.g. gateway :18789) on host localhost. | Runs inside host `rana`. |
| **Ledger** | Written **on the host**, never in the guest — a fully-compromised guest can suppress its own future events but cannot rewrite persisted history. | Host, user-owned. |

Why host-installed agents can't just be projected in: your `node_modules` contain **Mach-O native addons** — macOS binaries that cannot execute in a Linux guest. `rana adopt` therefore installs the agent's Linux build onto the data volume (a one-time guest-side `npm install`), while your *config and workspace* stay on the host, projected via virtiofs.

## 2. Entitlements & code signing

Virtualization.framework requires the `com.apple.security.virtualization` entitlement on a **signed** binary.

- **Release builds** are Developer-ID signed and notarized with the entitlement — nothing for you to do.
- **Source builds** must be self-signed once:

```sh
cat > vz.entitlements <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.security.virtualization</key><true/>
</dict></plist>
EOF
codesign --entitlements vz.entitlements -s - ./rana   # ad-hoc signature is sufficient locally
```

(This is the CGO exception of D3/P9: the macOS host binary links vz; Linux binaries stay pure-Go static.)

## 3. Boot behavior

- **Cold boot:** ≤10s (gate G3), paid on first run and on macOS 13 every run.
- **Warm start (macOS ≥14):** `SaveMachineStateToURL`/restore keeps a warm pool; `rana run` feels instant.
- `rana vm status | start | stop | reset` manages the lifecycle; `reset` discards the data volume (your host files are never inside it).

## 4. Honest limits (also in `LIMITS.md §5`)

- Native macOS agents: **not recorded, at all.** The guest is the recording boundary.
- Native-app automation (AppleScript, iMessage, GUI): invisible from inside the guest; RanA cannot record those effects.
- virtiofs seams: no inotify for host-side changes (in-guest file-watchers won't fire on them); weaker lock semantics — OpenClaw's own state DB lives on the data volume for this reason.
- Toolchains: the runtime layer covers Node agents; your project's compilers/interpreters are yours to install in-guest, or a coding agent in the guest can edit and fetch but not build. (`rana vm` currently exposes `status | start | stop | reset`; there is no interactive-shell subcommand yet — in-guest installs go through the data volume and a session's own tooling, not a separate `rana vm` entry point.)
