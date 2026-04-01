# Patterns: Android Firmware Support Campaign

> Extracted: 2026-04-01
> Campaign: .planning/campaigns/android-firmware-support.md
> Postmortem: none

## Successful Patterns

### 1. Scan for filesystem signatures instead of parsing container metadata
- **Description:** Instead of implementing an LP metadata parser (which requires lpunpack), scan the raw super.img for EROFS/ext4 magic bytes at 1MB-aligned boundaries. Found all 8 partitions reliably.
- **Evidence:** 7 EROFS + 1 ext4 partitions extracted from a 9GB raw super.img
- **Applies when:** Any container format where individual partitions need extraction but the container parser isn't available. Signature scanning is more robust across format variations.

### 2. Test with real user firmware, not synthetic test cases
- **Description:** Used the user's actual 1.9GB MediaTek update ZIP throughout development. Each iteration revealed real-world issues invisible in synthetic tests.
- **Evidence:** Found sparse magic byte order bug, super.img LP container issue, Android symlink resolution issue — none would appear in unit tests
- **Applies when:** Always for firmware extraction code. Real firmware has edge cases that synthetic data cannot replicate.

### 3. Check extraction results on disk, not just return codes
- **Description:** Tools like debugfs and fsck.erofs return success even when they extract nothing. The code checks `os.listdir(dest_dir)` after extraction to verify files were actually produced.
- **Evidence:** Empty rootfs directory despite "success" status — caught by checking listdir
- **Applies when:** Any extraction pipeline. Always verify output exists, don't trust exit codes alone.

## Anti-patterns

### 1. Wrong byte order for magic bytes
- **What was done:** Checked for Android sparse magic as `b"\xed\x26\xff\x3a"` (reversed) instead of `b"\x3a\xff\x26\xed"` (as stored on disk)
- **Failure mode:** Classifier returned `linux_blob` instead of `android_sparse`, fell through to binwalk which carved 159GB of garbage
- **Evidence:** `file` command showed "Android sparse image" but classifier missed it
- **How to avoid:** Always verify magic bytes against actual file hex dump. Use `od -A x -t x1z -N 4 file` to confirm byte order before writing detection code.

### 2. Upload flow strips ZIP before classifier runs
- **What was done:** `firmware_service.py._extract_firmware_from_zip()` extracts the largest file from the ZIP and discards the rest. The Android detection in `classify_firmware()` checks for ZIP markers (META-INF, system.img) but never sees them because the ZIP was already stripped.
- **Failure mode:** Android OTA ZIP detection bypassed — only the raw super.img reaches the classifier
- **Evidence:** `classify_firmware()` received `super.img` not the original ZIP
- **How to avoid:** Either detect Android ZIPs in the upload flow BEFORE stripping, or ensure the classifier handles both the ZIP and the extracted raw images (current approach via sparse magic).

### 3. Treating super.img as a single filesystem
- **What was done:** First iteration tried debugfs/fsck.erofs on the entire 9GB super.img
- **Failure mode:** Neither tool could extract anything — super.img is a partition container, not a filesystem
- **Evidence:** Empty rootfs directory after "successful" extraction
- **How to avoid:** Check for LP metadata magic at offset 0x1000 before attempting direct filesystem extraction. If present, scan for embedded partitions.

### 4. Android /etc is often an absolute symlink
- **What was done:** `find_filesystem_root()` uses `/etc` entry count as quality signal. Android's system partition has `etc -> /system/etc` (absolute symlink) which doesn't resolve within the extracted tree.
- **Failure mode:** System partition (34 entries, real root) scored 0 etc entries. Vendor partition (14 entries) scored 101 and was selected instead.
- **Evidence:** `partition_2_erofs` has `etc -> /system/etc`, `_etc_entry_count` returns 0
- **How to avoid:** For Android, prioritize by total top-level entry count or recognize Android root markers (presence of `system/`, `vendor/`, `apex/`, `init`) rather than relying on etc count.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Signature scanning over LP metadata parsing | No lpunpack available, scanning is more robust | Correct — found all 8 partitions |
| simg2img for sparse conversion | Debian package available, well-tested | Correct — converted 2GB sparse to 9GB raw |
| EROFS before ext4 in extraction order | Most modern Android uses EROFS | Correct — 7/8 partitions were EROFS |
| Skip partitions < 1MB | vbmeta, dtbo are metadata, not filesystems | Correct — avoided false positives |
| payload-dumper-go for A/B OTA | Go binary with ARM64 support | Installed but not tested (MediaTek uses legacy format) |

## Remaining Work

1. **Root selection for Android** — `find_filesystem_root()` picks vendor over system because of absolute symlink resolution. Need Android-aware heuristic (total entries > etc count).
2. **Upload flow Android ZIP detection** — The ZIP is stripped before the classifier sees it. Should detect Android ZIPs in `_extract_firmware_from_zip()` and preserve the full ZIP for the Android pipeline.
3. **Partition naming** — Currently names are `partition_0_erofs`, `partition_1_erofs`, etc. Should try to identify which is system/vendor/product from build.prop or directory structure.
4. **A/B OTA testing** — payload-dumper-go installed but not tested with actual A/B OTA firmware.
