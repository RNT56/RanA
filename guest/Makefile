# guest/Makefile — build the RanA macOS guest BASE layer with Buildroot.
#
# Docker-less: fetches a PINNED Buildroot tarball (version + SHA256 below) and
# invokes it out-of-tree with this directory as BR2_EXTERNAL. LINUX HOST / CI
# ONLY — Buildroot's toolchain and kernel build are Linux-native. The root
# `make guest` no-ops with a message on darwin and calls `make -C guest` here
# on Linux.
#
# Reproducible (D23/G8): SOURCE_DATE_EPOCH and KBUILD_BUILD_TIMESTAMP are
# pinned; the defconfig sets BR2_REPRODUCIBLE=y. Two hosts must produce the
# same base-image checksum.

# --- Pinned Buildroot (change deliberately; update the hash together). ------
BUILDROOT_VERSION := 2024.02.6
BUILDROOT_TARBALL := buildroot-$(BUILDROOT_VERSION).tar.gz
BUILDROOT_URL     := https://buildroot.org/downloads/$(BUILDROOT_TARBALL)
# SHA256 of the pinned tarball. VERIFY and fill this in when pinning; the
# fetch target fails closed if it does not match. (Left as a named placeholder
# so an unverified download can never silently proceed.)
BUILDROOT_SHA256  := PLACEHOLDER_PIN_THE_BUILDROOT_TARBALL_SHA256

# --- Paths. -----------------------------------------------------------------
GUEST_DIR   := $(CURDIR)
BR_SRC      := $(GUEST_DIR)/.buildroot/buildroot-$(BUILDROOT_VERSION)
OUTPUT_DIR  := $(GUEST_DIR)/output
DEFCONFIG   := rana_guest_defconfig

# --- Reproducibility knobs (honored by Buildroot + the kernel build). -------
export SOURCE_DATE_EPOCH ?= 1704067200
export KBUILD_BUILD_TIMESTAMP ?= @$(SOURCE_DATE_EPOCH)
export KBUILD_BUILD_USER ?= rana
export KBUILD_BUILD_HOST ?= reproducible

# sha256 helper (Linux: sha256sum).
SHA256SUM := sha256sum

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "guest targets (Linux host / CI only):"
	@echo "  make -C guest all       fetch Buildroot, configure, build the base image"
	@echo "  make -C guest fetch     fetch + checksum-verify the pinned Buildroot tarball"
	@echo "  make -C guest config    apply rana_guest_defconfig (BR2_EXTERNAL=this dir)"
	@echo "  make -C guest image     build the kernel + rootfs images"
	@echo "  make -C guest clean     remove the Buildroot output tree"
	@echo ""
	@echo "Buildroot $(BUILDROOT_VERSION) (pinned). Output -> $(OUTPUT_DIR)/images/"

# --- Guard: refuse to run anywhere but Linux (fail loud, not silently). -----
.PHONY: require-linux
require-linux:
	@if [ "$$(uname -s)" != "Linux" ]; then \
		echo "guest: Buildroot builds on a Linux host / CI only (uname=$$(uname -s))."; \
		echo "guest: see guest/README.md. The root 'make guest' handles this."; \
		exit 1; \
	fi

# --- fetch: download + verify the pinned Buildroot tarball (fail-closed). ---
.PHONY: fetch
fetch: require-linux
	@mkdir -p $(GUEST_DIR)/.buildroot
	@if [ ! -f "$(GUEST_DIR)/.buildroot/$(BUILDROOT_TARBALL)" ]; then \
		echo "guest: fetching $(BUILDROOT_URL)"; \
		curl -fSL --proto '=https' --tlsv1.2 \
			-o "$(GUEST_DIR)/.buildroot/$(BUILDROOT_TARBALL)" "$(BUILDROOT_URL)"; \
	fi
	@if [ "$(BUILDROOT_SHA256)" = "PLACEHOLDER_PIN_THE_BUILDROOT_TARBALL_SHA256" ]; then \
		echo "guest: ERROR — BUILDROOT_SHA256 is a placeholder; pin the real hash before building."; \
		echo "guest: (refusing to build from an unverified Buildroot tarball — supply chain, D23.)"; \
		exit 1; \
	fi
	@echo "$(BUILDROOT_SHA256)  $(GUEST_DIR)/.buildroot/$(BUILDROOT_TARBALL)" | $(SHA256SUM) -c - \
		|| { echo "guest: ERROR — Buildroot tarball checksum MISMATCH (fail-closed)."; exit 1; }
	@if [ ! -d "$(BR_SRC)" ]; then \
		echo "guest: extracting Buildroot"; \
		tar -C "$(GUEST_DIR)/.buildroot" -xzf "$(GUEST_DIR)/.buildroot/$(BUILDROOT_TARBALL)"; \
	fi

# --- config: apply the defconfig with this dir as the external tree. --------
.PHONY: config
config: fetch
	@echo "guest: applying $(DEFCONFIG) (BR2_EXTERNAL=$(GUEST_DIR))"
	$(MAKE) -C "$(BR_SRC)" \
		BR2_EXTERNAL="$(GUEST_DIR)" \
		O="$(OUTPUT_DIR)" \
		$(DEFCONFIG)

# --- image: build the kernel + rootfs. --------------------------------------
.PHONY: image
image: config
	@echo "guest: building base image (this is slow on a cold cache)"
	$(MAKE) -C "$(BR_SRC)" O="$(OUTPUT_DIR)"
	@echo "guest: images in $(OUTPUT_DIR)/images/:"
	@ls -l "$(OUTPUT_DIR)/images/" || true
	@echo "guest: base-image checksums (pin these; the vz image resolver compares):"
	@cd "$(OUTPUT_DIR)/images" && $(SHA256SUM) * 2>/dev/null || true

.PHONY: all
all: image

.PHONY: clean
clean:
	rm -rf "$(OUTPUT_DIR)"
	@echo "guest: removed $(OUTPUT_DIR) (the fetched Buildroot tree under .buildroot is kept)"

.PHONY: distclean
distclean:
	rm -rf "$(OUTPUT_DIR)" "$(GUEST_DIR)/.buildroot"
