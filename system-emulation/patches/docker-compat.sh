#!/bin/bash
# Patch FirmAE scripts for Docker compatibility
# Main issue: kpartx/losetup partition devices don't work in Docker containers
# Solution: Use raw ext2 images without partition tables, mount -o loop
set -e

FIRMAE_DIR="${1:-/opt/FirmAE}"
SCRIPT="$FIRMAE_DIR/scripts/makeImage.sh"

echo "[patch] Patching $SCRIPT for Docker compatibility..."

# 1. Comment out fdisk (partition table creation)
sed -i '/fdisk.*IMAGE/s/^/#Docker-compat# /' "$SCRIPT"

# 2. Comment out add_partition calls
sed -i '/DEVICE=.*add_partition/s/^/#Docker-compat# /' "$SCRIPT"

# 3. Replace mkfs on DEVICE with mkfs on IMAGE
sed -i 's|mkfs.ext2 "${DEVICE}"|mkfs.ext2 -F "${IMAGE}"|' "$SCRIPT"

# 4. Replace mount DEVICE with mount -o loop IMAGE
sed -i 's|mount "${DEVICE}" "${IMAGE_DIR}"|mount -o loop "${IMAGE}" "${IMAGE_DIR}"|' "$SCRIPT"

# 5. Comment out del_partition calls
sed -i '/del_partition/s/^/#Docker-compat# /' "$SCRIPT"

# 6. Fix e2fsck references to DEVICE — replace with IMAGE
sed -i 's/e2fsck -y ${DEVICE}/e2fsck -fy "${IMAGE}" 2>\/dev\/null || true/' "$SCRIPT"

# 7. Comment out remaining losetup lines
sed -i '/losetup.*DEVICE/s/^/#Docker-compat# /' "$SCRIPT"

# 8. Override functions in firmae.config
cat >> "$FIRMAE_DIR/firmae.config" << 'EOF'

# Docker compatibility: override partition functions and disk paths
add_partition() { echo "${1}"; }
del_partition() { true; }
# Use whole-disk instead of partition 1 (no partition table)
get_qemu_disk() {
  case "${1}" in
    armel) echo "/dev/vda" ;;
    mipseb|mipsel) echo "/dev/sda" ;;
    *) echo "/dev/sda" ;;
  esac
}
EOF

echo "[patch] Done. Patched makeImage.sh and firmae.config"
