#!/bin/sh
# get-rana.sh — install RanA (the flight recorder for AI agents).
#
# POSIX sh, no bashisms. Detects OS + arch, downloads the matching release
# asset AND its SHA256, VERIFIES the checksum before touching the system, and
# installs to /usr/local/bin. On Linux it also installs and enables the
# hardened ranad.service. Fail-closed: a checksum mismatch aborts before
# install. Idempotent: re-running upgrades in place.
#
# NO telemetry. NO phone-home. The only network calls are the explicit
# artifact + checksum downloads from the GitHub releases API (plan D24).
#
# Usage:
#   curl -fsSL https://get.rana.dev | sh
#   RANA_VERSION=v0.1.0 sh get-rana.sh        # pin a version
#   RANA_PREFIX=/opt/bin sh get-rana.sh       # custom install prefix
#
# After install:  rana doctor

set -eu

# ---------------------------------------------------------------------------
# Configuration (overridable via environment)
# ---------------------------------------------------------------------------
REPO="${RANA_REPO:-RNT56/RanA}"
PREFIX="${RANA_PREFIX:-/usr/local/bin}"
VERSION="${RANA_VERSION:-latest}"
GITHUB="${RANA_GITHUB:-https://github.com}"
API="${RANA_API:-https://api.github.com}"

# Where the hardened unit is installed on Linux.
SYSTEMD_UNIT_DIR="${RANA_SYSTEMD_DIR:-/etc/systemd/system}"

log()  { printf 'rana-install: %s\n' "$*" >&2; }
die()  { printf 'rana-install: error: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Tooling: need a downloader and a sha256 checker.
# ---------------------------------------------------------------------------
DL=""
if command -v curl >/dev/null 2>&1; then
  DL="curl"
elif command -v wget >/dev/null 2>&1; then
  DL="wget"
else
  die "need curl or wget to download release artifacts"
fi

# download URL OUTFILE  — fail-closed on HTTP error.
download() {
  _url="$1"; _out="$2"
  if [ "$DL" = "curl" ]; then
    curl -fSL --proto '=https' --tlsv1.2 -o "$_out" "$_url"
  else
    wget -O "$_out" "$_url"
  fi
}

# download to stdout (for the releases API JSON).
download_stdout() {
  _url="$1"
  if [ "$DL" = "curl" ]; then
    curl -fSL --proto '=https' --tlsv1.2 "$_url"
  else
    wget -O - "$_url"
  fi
}

SHACMD=""
if command -v sha256sum >/dev/null 2>&1; then
  SHACMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHACMD="shasum -a 256"
else
  die "need sha256sum or shasum to verify checksums (refusing to install unverified binaries)"
fi

# sha256_of FILE  — print the lowercase hex digest only.
sha256_of() {
  # Both sha256sum and `shasum -a 256` print "<hex>  <file>"; take field 1.
  $SHACMD "$1" | awk '{print $1}'
}

# ---------------------------------------------------------------------------
# Detect OS + arch, map to release-asset naming.
# ---------------------------------------------------------------------------
os_raw="$(uname -s)"
arch_raw="$(uname -m)"

case "$os_raw" in
  Linux)  OS="linux" ;;
  Darwin) OS="darwin" ;;
  *) die "unsupported OS: $os_raw (RanA v1 supports Linux and macOS only)" ;;
esac

case "$arch_raw" in
  x86_64|amd64)        ARCH="amd64" ;;
  aarch64|arm64)       ARCH="arm64" ;;
  *) die "unsupported arch: $arch_raw (RanA supports amd64 and arm64)" ;;
esac

log "detected $OS/$ARCH"

# ---------------------------------------------------------------------------
# Resolve the version tag.
# ---------------------------------------------------------------------------
if [ "$VERSION" = "latest" ]; then
  log "resolving latest release tag from $API/repos/$REPO/releases/latest"
  # Parse tag_name from the releases API JSON without requiring jq.
  VERSION="$(download_stdout "$API/repos/$REPO/releases/latest" \
    | grep -m1 '"tag_name"' \
    | sed -e 's/.*"tag_name"[[:space:]]*:[[:space:]]*"//' -e 's/".*//')"
  [ -n "$VERSION" ] || die "could not resolve the latest release tag"
fi
log "installing RanA $VERSION"

# ---------------------------------------------------------------------------
# Download + verify each binary. Fail-closed BEFORE install.
# ---------------------------------------------------------------------------
# Release assets are named "<cmd>-<os>-<arch>" with a shared SHA256SUMS file
# (see .github/workflows/release.yml). We fetch SHA256SUMS once and check each
# artifact against it.
BASE_URL="$GITHUB/$REPO/releases/download/$VERSION"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rana-install.XXXXXX")" || die "mktemp failed"
# Clean up the scratch dir on any exit.
trap 'rm -rf "$WORKDIR"' EXIT INT TERM

log "downloading SHA256SUMS"
download "$BASE_URL/SHA256SUMS" "$WORKDIR/SHA256SUMS" \
  || die "could not download SHA256SUMS for $VERSION"

# Which binaries to install for this OS.
#   linux : rana + ranad   (ranad is the root collector)
#   darwin: rana only       (ranad runs inside the guest VM, not on the host)
if [ "$OS" = "linux" ]; then
  BINARIES="rana ranad"
else
  BINARIES="rana"
fi

# fetch_and_verify ASSETNAME  — downloads to $WORKDIR and checks its digest
# against SHA256SUMS. Aborts (exit) on mismatch.
fetch_and_verify() {
  _asset="$1"
  log "downloading $_asset"
  download "$BASE_URL/$_asset" "$WORKDIR/$_asset" \
    || die "could not download $_asset"

  # Expected digest from SHA256SUMS (the file lists "<hex>  <asset>").
  _expected="$(grep -E "[[:space:]][*]?${_asset}\$" "$WORKDIR/SHA256SUMS" \
    | awk '{print $1}' | head -n1)"
  [ -n "$_expected" ] || die "no checksum for $_asset in SHA256SUMS (refusing to install)"

  _actual="$(sha256_of "$WORKDIR/$_asset")"
  if [ "$_expected" != "$_actual" ]; then
    die "checksum MISMATCH for $_asset
      expected: $_expected
      actual:   $_actual
    Refusing to install (fail-closed)."
  fi
  log "verified $_asset (sha256 ok)"
}

for bin in $BINARIES; do
  fetch_and_verify "${bin}-${OS}-${ARCH}"
done

# ---------------------------------------------------------------------------
# Install (only after ALL checksums verified).
# ---------------------------------------------------------------------------
# Decide whether we need sudo for the install prefix. Root never needs it; a
# non-root user needs it when the prefix (or its parent) is not writable.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if [ ! -d "$PREFIX" ] || [ ! -w "$PREFIX" ]; then
    if command -v sudo >/dev/null 2>&1; then
      SUDO="sudo"
    else
      die "no write access to $PREFIX and sudo is unavailable; set RANA_PREFIX to a writable dir"
    fi
  fi
fi

log "installing to $PREFIX (idempotent; overwrites existing)"
$SUDO mkdir -p "$PREFIX"
for bin in $BINARIES; do
  $SUDO install -m 0755 "$WORKDIR/${bin}-${OS}-${ARCH}" "$PREFIX/$bin"
  log "installed $PREFIX/$bin"
done

# ---------------------------------------------------------------------------
# Linux: install + enable the hardened ranad.service.
# ---------------------------------------------------------------------------
if [ "$OS" = "linux" ]; then
  # Prefer a unit shipped alongside this script (source checkout); otherwise
  # fetch it from the tagged release tree.
  _script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd 2>/dev/null || echo '')"
  _unit_src=""
  if [ -n "$_script_dir" ] && [ -f "$_script_dir/ranad.service" ]; then
    _unit_src="$_script_dir/ranad.service"
  else
    log "downloading ranad.service unit"
    if download "$GITHUB/$REPO/raw/$VERSION/install/ranad.service" \
        "$WORKDIR/ranad.service" 2>/dev/null; then
      _unit_src="$WORKDIR/ranad.service"
    fi
  fi

  if [ -n "$_unit_src" ] && command -v systemctl >/dev/null 2>&1; then
    # Point the unit's ExecStart at the actual install prefix if it differs
    # from the default /usr/local/bin.
    if [ "$PREFIX" != "/usr/local/bin" ]; then
      sed "s#/usr/local/bin/ranad#$PREFIX/ranad#g" "$_unit_src" > "$WORKDIR/ranad.service.patched"
      _unit_src="$WORKDIR/ranad.service.patched"
    fi
    log "installing hardened unit to $SYSTEMD_UNIT_DIR/ranad.service"
    $SUDO install -m 0644 "$_unit_src" "$SYSTEMD_UNIT_DIR/ranad.service"
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable --now ranad.service || \
      log "note: could not enable ranad.service automatically; run 'systemctl enable --now ranad' after review"
  else
    log "note: systemd not detected (or no unit available); ranad must be run/supervised manually"
  fi
fi

# ---------------------------------------------------------------------------
# Done.
# ---------------------------------------------------------------------------
log "RanA $VERSION installed."
log "next step:  rana doctor"
