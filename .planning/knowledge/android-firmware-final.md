# Patterns: Android Firmware Support — Final Session

> Extracted: 2026-04-01
> Campaign: .planning/campaigns/android-firmware-support.md (active)
> Source: 8 commits, 1.9GB MediaTek test firmware, live debugging

## Successful Patterns

### 1. Chroot-style symlink resolution is the correct model for firmware
- **Description:** Replaced os.path.realpath() (host-relative) with custom _resolve_within_root() that rewrites absolute symlink targets relative to the firmware root. This is equivalent to how chroot resolves paths.
- **Evidence:** /bin -> /system/bin now resolves to <root>/system/bin instead of host's /system/bin. Fixed path traversal errors and broken file explorer navigation.
- **Applies when:** ANY firmware with absolute symlinks (Android, many embedded Linux). This is a foundational fix that affects all file operations.

### 2. Filesystem signature scanning is more robust than container metadata parsing
- **Description:** Instead of implementing LP metadata parser (lpunpack), scan raw super.img for EROFS/ext4 magic bytes at 1MB-aligned boundaries. Found all 8 partitions.
- **Evidence:** 7 EROFS + 1 ext4 extracted from 9GB raw image without any Android-specific tooling beyond simg2img
- **Applies when:** Any multi-partition container where the metadata format is complex or tools aren't available.

### 3. Test each symlink path through the full API stack
- **Description:** Verified each symlink (/bin, /etc, /init, /bugreports, /d, /cache, /sdcard) through the REST API to confirm correct behavior. Some resolve (bin→directory), some are legitimately broken (bugreports→runtime path), some are files (init→binary).
- **Evidence:** Found that file_service.py's list_directory also needed the chroot resolver, not just validate_path
- **Applies when:** After any sandbox/path resolution changes. Test every path type through the API.

## Anti-patterns

### 1. os.path.realpath() is wrong for firmware analysis
- **What was done:** validate_path used os.path.realpath() to resolve and check paths
- **Failure mode:** Absolute symlinks in firmware (bin -> /system/bin) resolve against the HOST filesystem, causing "Path traversal detected" errors on perfectly valid firmware paths
- **Evidence:** Android firmware was completely unbrowsable until _resolve_within_root was implemented
- **How to avoid:** Never use os.path.realpath() on paths within extracted firmware. Always resolve relative to the extraction root. The _resolve_within_root() function is the correct pattern.

### 2. Magic byte endianness must be verified against actual files
- **What was done:** Used b"\xed\x26\xff\x3a" for Android sparse magic
- **Failure mode:** Actual on-disk bytes are b"\x3a\xff\x26\xed" — firmware classified as linux_blob, fell through to binwalk which carved 159GB of garbage
- **Evidence:** Fixed after checking with od/xxd against actual file
- **How to avoid:** ALWAYS verify magic bytes with `od -A x -t x1z -N 4 <file>` before writing detection code. Never trust documentation about byte order without verifying.

### 3. Syft alone is insufficient for Android SBOM
- **What was done:** Relied on Syft + custom scanner for SBOM generation on Android firmware
- **Failure mode:** Only 39 components found (38 Java JARs from Syft, 1 OS config). Missing: ~40+ APKs, Android version info, init services, kernel modules, SELinux policy, vendor HALs
- **Evidence:** Manual inspection found rich data in system/app/, system/priv-app/, build.prop, system/etc/init/*.rc, system/etc/selinux/
- **How to avoid:** Android needs its own SBOM strategy: APK scanning, build.prop parsing, .rc init parsing, vendor partition scanning

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Custom _resolve_within_root vs os.path.realpath | Host-relative resolution breaks firmware symlinks | Correct — foundational fix |
| Android system root detection: init + system + bin/apex | Distinguishes system partition from vendor/product | Correct — partition_2 (34 entries) chosen over partition_6 (14 entries) |
| Broken symlinks are correct for runtime paths | /data/*, /sys/*, /storage/* only exist on running device | Correct — showing as broken is accurate |
| Scan all partitions at 1MB boundaries | Avoids LP metadata parsing complexity | Correct — found all 8 partitions |
| Don't resolve symlinks for file type if target doesn't exist | bugreports -> /data/... shouldn't show as directory | Correct — broken symlinks stay as symlinks |

## Android SBOM Gaps (Planned for Next Session)

| Priority | What | How |
|---|---|---|
| 1 | APK inventory | Scan system/app/, system/priv-app/, product/app/ for APK names |
| 2 | build.prop metadata | Parse ro.build.version.*, ro.product.*, ro.board.platform |
| 3 | Multi-partition scanning | Run Syft on each extracted partition, not just system root |
| 4 | Android init services | Parse system/etc/init/*.rc for service declarations |
| 5 | Kernel modules | Scan vendor/lib/modules/ for .ko files |
| 6 | SELinux policy | Detect enforcing/permissive from system/etc/selinux/ |
| 7 | androguard | Deep APK analysis (permissions, activities, intents) |
| 8 | MediaTek-specific | CONFIG_MTK_* kernel config, scatter file analysis |
