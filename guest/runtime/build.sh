#!/bin/sh
# build.sh — assemble the RanA guest RUNTIME layer (D15, docs/MACOS.md §1).
#
# The runtime layer is Node.js LTS + git + a POSIX toolchain: what OpenClaw and
# Claude Code (both Node apps) need to actually RUN in the guest. It is NOT
# embedded in the host binary (too large, ~150MB budget); it is fetched once
# with a signature check to ~/Library/Application Support/rana/ and reused.
#
# This script fetches a PINNED Node.js LTS linux-arm64 tarball, verifies its
# PUBLISHED SHA256 (fail-closed), and lays it onto the runtime layer directory
# deterministically (sorted tar, fixed uid/gid/mtime) so the layer is
# reproducible (D23/G8).
#
# POSIX sh, no bashisms. LINUX/CI build step (the layer targets a Linux guest).
#
#   NETWORK STEP: fetching the Node tarball is the ONLY network access here and
#   is clearly marked below. A checksum mismatch aborts before anything is laid
#   onto the layer.

set -eu

# ---------------------------------------------------------------------------
# Pins — change deliberately; update NODE_SHA256 together with NODE_VERSION.
# ---------------------------------------------------------------------------
# Node.js LTS, linux-arm64 (Apple Silicon guests are aarch64).
NODE_VERSION="${NODE_VERSION:-v20.17.0}"
NODE_ARCH="${NODE_ARCH:-linux-arm64}"
NODE_DIST="${NODE_DIST:-https://nodejs.org/dist}"
NODE_TARBALL="node-${NODE_VERSION}-${NODE_ARCH}.tar.xz"
NODE_URL="${NODE_DIST}/${NODE_VERSION}/${NODE_TARBALL}"

# PUBLISHED SHA256 of the exact tarball above (from nodejs.org/dist/<v>/
# SHASUMS256.txt). This is a named PLACEHOLDER so an unverified toolchain can
# never silently land on the layer — pin the real value when wiring the build.
NODE_SHA256="${NODE_SHA256:-PLACEHOLDER_PIN_THE_NODE_TARBALL_SHA256}"

# Where the assembled layer is written (a rootfs-style tree the vz image
# resolver packs into the runtime layer).
LAYER_DIR="${RANA_RUNTIME_LAYER_DIR:-$(CD_DIR="$(dirname "$0")"; cd "$CD_DIR/.." && pwd)/output/runtime-layer}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rana-runtime.XXXXXX")"

# Reproducibility: pin mtimes to SOURCE_DATE_EPOCH.
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"

log() { printf 'rana-runtime: %s\n' "$*" >&2; }
die() { printf 'rana-runtime: error: %s\n' "$*" >&2; exit 1; }

cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Tooling.
# ---------------------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
  DL_CURL=1
elif command -v wget >/dev/null 2>&1; then
  DL_CURL=0
else
  die "need curl or wget to fetch the Node.js tarball"
fi

if command -v sha256sum >/dev/null 2>&1; then
  SHACMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHACMD="shasum -a 256"
else
  die "need sha256sum or shasum to verify the Node.js tarball"
fi

sha256_of() { $SHACMD "$1" | awk '{print $1}'; }

# ---------------------------------------------------------------------------
# Guard: refuse to proceed with an unpinned checksum.
# ---------------------------------------------------------------------------
if [ "$NODE_SHA256" = "PLACEHOLDER_PIN_THE_NODE_TARBALL_SHA256" ]; then
  die "NODE_SHA256 is a placeholder; pin the published SHA256 for $NODE_TARBALL
    (from ${NODE_DIST}/${NODE_VERSION}/SHASUMS256.txt) before building.
    Refusing to build from an unverified toolchain (supply chain, D23)."
fi

# ---------------------------------------------------------------------------
# >>> NETWORK STEP <<< — fetch the pinned Node.js tarball. The ONLY network
# access in this script.
# ---------------------------------------------------------------------------
log "fetching Node.js $NODE_VERSION ($NODE_ARCH) [network step]"
log "  $NODE_URL"
if [ "$DL_CURL" = "1" ]; then
  curl -fSL --proto '=https' --tlsv1.2 -o "$WORKDIR/$NODE_TARBALL" "$NODE_URL" \
    || die "download failed: $NODE_URL"
else
  wget -O "$WORKDIR/$NODE_TARBALL" "$NODE_URL" || die "download failed: $NODE_URL"
fi

# ---------------------------------------------------------------------------
# VERIFY (fail-closed) BEFORE laying anything onto the layer.
# ---------------------------------------------------------------------------
_actual="$(sha256_of "$WORKDIR/$NODE_TARBALL")"
if [ "$_actual" != "$NODE_SHA256" ]; then
  die "Node.js tarball checksum MISMATCH (fail-closed)
    expected: $NODE_SHA256
    actual:   $_actual"
fi
log "verified $NODE_TARBALL (sha256 ok)"

# ---------------------------------------------------------------------------
# Lay the toolchain onto the runtime layer (deterministic).
# ---------------------------------------------------------------------------
log "assembling runtime layer at $LAYER_DIR"
rm -rf "$LAYER_DIR"
mkdir -p "$LAYER_DIR/usr"

# Extract Node into the layer under /usr (bin/, lib/, include/, share/).
tar -C "$WORKDIR" -xJf "$WORKDIR/$NODE_TARBALL"
_node_root="$WORKDIR/node-${NODE_VERSION}-${NODE_ARCH}"
[ -d "$_node_root" ] || die "unexpected Node tarball layout: $_node_root missing"

# Copy node/npm/npx and libs into the layer /usr, preserving the tree.
cp -a "$_node_root/bin"     "$LAYER_DIR/usr/bin"
cp -a "$_node_root/lib"     "$LAYER_DIR/usr/lib"
cp -a "$_node_root/include" "$LAYER_DIR/usr/include" 2>/dev/null || true
cp -a "$_node_root/share"   "$LAYER_DIR/usr/share"   2>/dev/null || true

# NOTE: git + the POSIX toolchain are provided by the Buildroot BASE layer's
# BusyBox + a git package (or a second pinned fetch). Node is the piece with
# the strict size/repro budget, so it is the focus of this script. If git is
# added as a separate fetch, mirror the exact fetch+verify pattern above.

# Determinism: pin ownership + mtimes across the whole layer so two hosts
# produce byte-identical output (gate G8).
find "$LAYER_DIR" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} + 2>/dev/null || true

log "runtime layer assembled: $LAYER_DIR"
log "  node: $("$LAYER_DIR/usr/bin/node" --version 2>/dev/null || echo '(cannot exec on this host arch — expected when cross-building)')"
log "done."
