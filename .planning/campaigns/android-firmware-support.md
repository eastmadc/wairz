# Campaign: Android Firmware Support

Status: active
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

| # | Type | Description | Deps | End Conditions |
|---|------|-------------|------|----------------|
| 1 | build | Android ZIP detection in firmware classifier | none | `classify_firmware()` returns "android_ota" for Android ZIPs |
| 2 | build | Install simg2img + erofs-utils in Dockerfile | none | `command_passes: docker compose exec backend simg2img --help` |
| 3 | build | Android extraction pipeline in unpack.py | 1,2 | Sparse ext4 and EROFS images extracted to rootfs |
| 4 | build | Install payload-dumper-go + lpunpack | none | Both binaries available in container |
| 5 | build | A/B OTA extraction (payload.bin → partitions) | 3,4 | payload.bin extracted to individual partition images |
| 6 | build | super.img extraction (dynamic partitions) | 3,4 | super.img unpacked to system/vendor/product images |
| 7 | build | boot.img extraction (kernel + ramdisk) | 3 | Kernel and ramdisk extracted from boot.img |
| 8 | wire | Android metadata parsing (build.prop, etc.) | 3 | Device model, Android version, security patch level shown |
| 9 | verify | End-to-end test with MediaTek ZIP | all | User's 1.9GB ZIP extracts successfully |

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
(to be filled during execution)

## Feature Ledger
(to be filled during execution)

## Continuation State
Current phase: not started
Next action: /do continue to begin Phase 1
