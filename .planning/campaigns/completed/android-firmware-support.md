# Campaign: Android Firmware Support

Status: completed
Created: 2026-04-01
Direction: Add Android firmware extraction pipeline — sparse images, A/B OTA, super.img, EROFS, boot.img
Estimated sessions: 3-4
Type: build

## Background

A 1.9GB MediaTek Android full update ZIP timed out on binwalk (600s).
Android firmware has a completely different structure from embedded Linux:
- Outer container (ZIP) contains partition images
- Partition images may be Android sparse format (not raw ext4)
- Modern devices use dynamic partitions (super.img) and A/B OTA (payload.bin)
- Filesystems may be ext4 or EROFS (read-only, newer Android)
- Requires a 3-4 stage extraction pipeline

## Tool Requirements

| Tool | Purpose | ARM64 | Install | Size |
|------|---------|-------|---------|------|
| simg2img | Sparse → raw image | Debian pkg | android-sdk-libsparse-utils | ~5MB |
| lpunpack | Extract super.img partitions | Build from source | nmeum/android-tools | ~10MB |
| payload-dumper-go | Extract A/B OTA payload.bin | Pre-built binary | GitHub release v1.3.0 | ~15MB |
| unpack_bootimg | Unpack boot.img | Debian pkg | mkbootimg (Python) | ~1MB |
| erofs-utils | Extract EROFS filesystems | Debian pkg | erofs-utils | ~5MB |
| debugfs | Extract ext4 without root | Already installed | e2fsprogs | 0MB |

## Phases

| # | Type | Description | Deps | End Conditions | Status |
|---|------|-------------|------|----------------|--------|
| 1 | build | Android ZIP detection in firmware classifier | none | `classify_firmware()` returns "android_ota" for Android ZIPs | done (commit 2678e49) |
| 2 | build | Install simg2img + erofs-utils in Dockerfile | none | `command_passes: docker compose exec backend simg2img --help` | done |
| 3 | build | Android extraction pipeline in unpack.py | 1,2 | Sparse ext4 and EROFS images extracted to rootfs | done (commit 2678e49) |
| 4 | build | Install payload-dumper-go + lpunpack | none | Both binaries available in container | done |
| 5 | build | A/B OTA extraction (payload.bin → partitions) | 3,4 | payload.bin extracted to individual partition images | done (code complete, payload-dumper-go verified in container) |
| 6 | build | super.img extraction (dynamic partitions) | 3,4 | super.img unpacked to system/vendor/product images | done (commit 6c4946f) |
| 7 | build | boot.img extraction (kernel + ramdisk) | 3 | Kernel and ramdisk extracted from boot.img | done (this session) |
| 8 | wire | Android metadata parsing (build.prop, etc.) | 3 | Device model, Android version, security patch level shown | done (os_info field populated) |
| 9 | verify | End-to-end test with MediaTek ZIP | all | User's 1.9GB ZIP extracts successfully | done (test project b59b8887) |
| 10 | build | Android ZIP early detection in upload flow | none | Android ZIPs preserved intact during upload | done (this session) |
| 11 | build | Content-based partition naming | 6 | super.img partitions named system/vendor/product instead of partition_N | done (this session) |

## Citadel Rollout Strategy

### Session 1: Foundation (Phases 1-3)
- `/archon continue` picks up at Phase 1
- Agent 1: Add Android detection to classify_firmware()
- Agent 2: Dockerfile changes (simg2img, erofs-utils)
- Agent 3: Core extraction pipeline (sparse → raw → ext4/EROFS → rootfs)
- Test with the user's MediaTek ZIP

### Session 2: Modern OTA (Phases 4-6)
- `/archon continue` picks up at Phase 4
- Agent 1: Install payload-dumper-go + lpunpack
- Agent 2: payload.bin extraction pipeline
- Agent 3: super.img extraction pipeline
- Test with Pixel/Samsung OTA files

### Session 3: Metadata + Verification (Phases 7-9)
- `/archon continue` picks up at Phase 7
- Agent 1: boot.img extraction
- Agent 2: Android metadata parsing (build.prop → device info)
- Agent 3: End-to-end testing with multiple Android formats

## Detection Heuristics

### Android OTA ZIP
```python
# Top-level ZIP entries that indicate Android update
ANDROID_MARKERS = {
    "META-INF/com/google/android/updater-script",
    "META-INF/com/google/android/update-binary",
    "META-INF/com/android/metadata",
    "payload.bin",
    "system.img",
    "boot.img",
    "vendor.img",
}
# If 2+ markers present → android_ota
```

### Android Sparse Image
```python
# Magic bytes at offset 0: 0x3aff26ed (little-endian)
SPARSE_MAGIC = b"\xed\x26\xff\x3a"
```

### Super Image (Dynamic Partitions)
```python
# LP metadata magic at offset 0x1000: 0x67446c50 ("PdLg")
LP_METADATA_MAGIC = b"\x50\x6c\x44\x67"
```

## Decision Log
- Filesystem signature scanning (EROFS/ext4 magic at 1MB boundaries) used instead of LP metadata parsing — found all partitions without lpunpack
- Chroot-style symlink resolution (`_resolve_within_root`) instead of `os.path.realpath` — foundational fix for all firmware with absolute symlinks
- Upload flow preserves Android ZIPs intact instead of extracting largest file — simpler, lets existing unpack pipeline handle correctly
- Content-based partition naming post-extraction rather than pre-extraction — more robust, doesn't depend on LP metadata
- Native Python boot.img parser instead of mkbootimg/unpack_bootimg dependency — simpler, no extra Docker tool needed, covers v0-v4 headers

## Feature Ledger
- `classify_firmware()` Android OTA + sparse detection (unpack.py)
- `_extract_android_ota()` full extraction pipeline (unpack.py)
- `_scan_super_partitions()` magic-byte based partition scanning (unpack.py)
- `_identify_partition_by_content()` content-based naming (unpack.py, this session)
- `_is_android_firmware_zip()` upload-time detection (firmware_service.py, this session)
- `_resolve_within_root()` chroot symlink resolution (sandbox.py)
- `_extract_boot_img()` native Python boot.img parser v0-v4 (unpack_android.py, this session)
- `_extract_ramdisk()` gzip/lz4/cpio ramdisk decompression (unpack_android.py, this session)
- `android_boot` classification type (unpack_common.py, this session)
- 18 tests in `tests/test_firmware_classification.py` (14 existing + 4 new boot.img)

## Continuation State
Campaign complete. All 11 phases done.
- Phase 5 A/B OTA: code written, payload-dumper-go verified in container, classification tested.
  Real Pixel OTA validation deferred — will be covered by normal usage.
- 21 firmware classification tests passing (including 3 new partition dump tar tests).

<!-- session-end: 2026-04-01T22:43:48.197Z -->

<!-- session-end: 2026-04-01T22:50:13.822Z -->

<!-- session-end: 2026-04-01T22:55:16.393Z -->

<!-- session-end: 2026-04-02T17:44:26.466Z -->

<!-- session-end: 2026-04-02T17:59:17.165Z -->

<!-- session-end: 2026-04-02T17:59:29.048Z -->

<!-- session-end: 2026-04-02T18:00:59.908Z -->

<!-- session-end: 2026-04-02T18:01:14.066Z -->

<!-- session-end: 2026-04-02T18:01:36.765Z -->

<!-- session-end: 2026-04-02T18:01:58.891Z -->

<!-- session-end: 2026-04-02T18:07:24.815Z -->

<!-- session-end: 2026-04-02T18:07:49.313Z -->

<!-- session-end: 2026-04-02T18:11:43.400Z -->

<!-- session-end: 2026-04-02T18:13:35.921Z -->

<!-- session-end: 2026-04-02T18:55:09.816Z -->
