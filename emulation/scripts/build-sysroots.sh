#!/bin/bash
# build-sysroots.sh — Build minimal sysroots for standalone binary emulation
#
# Creates /opt/sysroots/<arch>/lib/ directories containing the dynamic linker
# and core shared libraries needed to run most dynamically-linked binaries.
#
# Sources: Debian multiarch packages (libc6, libgcc-s1)
# Target architectures: arm, aarch64, mips, mipsel, i386, x86_64
#
# This script runs during the Docker image build.

set -e

SYSROOT_BASE="/opt/sysroots"
WORK_DIR="/tmp/sysroot-build"

mkdir -p "$WORK_DIR"

# ── Helper: extract .deb package contents ──

extract_deb() {
    local deb_path="$1"
    local dest_dir="$2"
    mkdir -p "$dest_dir"
    dpkg-deb -x "$deb_path" "$dest_dir"
}

# ── Helper: build sysroot for one architecture ──
# Usage: build_sysroot <arch_name> <debian_arch> <lib_dir_pattern>

build_sysroot() {
    local arch_name="$1"    # arm, aarch64, mipsel, mips, i386, x86_64
    local deb_arch="$2"     # armhf, arm64, mipsel, mips, i386, amd64
    local lib_pattern="$3"  # lib/arm-linux-gnueabihf, lib/aarch64-linux-gnu, etc.

    echo "=== Building sysroot for ${arch_name} (${deb_arch}) ==="

    local sysroot="${SYSROOT_BASE}/${arch_name}"
    local work="${WORK_DIR}/${arch_name}"
    mkdir -p "${sysroot}/lib" "${work}"

    # Download core packages
    cd "$work"
    apt-get download \
        "libc6:${deb_arch}" \
        "libgcc-s1:${deb_arch}" \
        2>/dev/null || {
            echo "WARNING: Failed to download packages for ${deb_arch}, skipping"
            return 0
        }

    # Extract all downloaded .deb files
    local extract_dir="${work}/extracted"
    for deb in ${work}/*.deb; do
        [ -f "$deb" ] && extract_deb "$deb" "$extract_dir"
    done

    # Copy shared libraries from the multiarch lib directory
    # Debian puts cross-arch libs in /lib/<triplet>/ and /usr/lib/<triplet>/
    for search_dir in \
        "${extract_dir}/${lib_pattern}" \
        "${extract_dir}/usr/${lib_pattern}" \
        "${extract_dir}/lib" \
        "${extract_dir}/usr/lib"; do

        if [ -d "$search_dir" ]; then
            # Copy .so files and symlinks
            find "$search_dir" -maxdepth 1 \( -name "*.so*" -o -name "ld-*" -o -name "ld.so*" \) \
                -exec cp -a {} "${sysroot}/lib/" \; 2>/dev/null || true
        fi
    done

    # Count what we got
    local lib_count
    lib_count=$(find "${sysroot}/lib" -name "*.so*" 2>/dev/null | wc -l)
    echo "  Installed ${lib_count} library files to ${sysroot}/lib/"

    # Verify we have a dynamic linker
    local has_linker=false
    for ld_name in ld-linux-armhf.so.3 ld-linux.so.3 ld-linux-aarch64.so.1 \
                   ld.so.1 ld-linux.so.2 ld-linux-x86-64.so.2; do
        if [ -f "${sysroot}/lib/${ld_name}" ] || [ -L "${sysroot}/lib/${ld_name}" ]; then
            has_linker=true
            echo "  Dynamic linker: ${ld_name}"
            break
        fi
    done

    if [ "$has_linker" = false ]; then
        echo "  WARNING: No dynamic linker found for ${arch_name}"
    fi

    # Clean up
    rm -rf "$work"
    echo "  Done: $(du -sh "${sysroot}" | cut -f1)"
}

# ── Main: add multiarch foreign architectures and build sysroots ──

# Enable multiarch for all target architectures
dpkg --add-architecture armhf 2>/dev/null || true
dpkg --add-architecture arm64 2>/dev/null || true
dpkg --add-architecture amd64 2>/dev/null || true
dpkg --add-architecture mipsel 2>/dev/null || true
dpkg --add-architecture mips 2>/dev/null || true
dpkg --add-architecture i386 2>/dev/null || true

# Update package lists with foreign architectures
apt-get update -qq 2>/dev/null

# Build sysroots for each architecture
# Args: <name> <debian_arch> <lib_dir_pattern>
build_sysroot "arm"     "armhf"  "lib/arm-linux-gnueabihf"
build_sysroot "aarch64" "arm64"  "lib/aarch64-linux-gnu"
build_sysroot "mipsel"  "mipsel" "lib/mipsel-linux-gnu"
build_sysroot "mips"    "mips"   "lib/mips-linux-gnu"
build_sysroot "i386"    "i386"   "lib/i386-linux-gnu"

# x86_64: always download from Debian (works on both x86_64 and ARM64 hosts)
build_sysroot "x86_64" "amd64" "lib/x86_64-linux-gnu"

# Summary
echo ""
echo "=== Sysroot Summary ==="
for dir in "${SYSROOT_BASE}"/*/; do
    name=$(basename "$dir")
    count=$(find "$dir" -name "*.so*" 2>/dev/null | wc -l)
    size=$(du -sh "$dir" 2>/dev/null | cut -f1)
    echo "  ${name}: ${count} libraries, ${size}"
done

# Clean up apt caches
rm -rf "$WORK_DIR"
apt-get clean
rm -rf /var/lib/apt/lists/*

echo "Sysroot build complete."
