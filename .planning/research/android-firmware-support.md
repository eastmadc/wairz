# Android Firmware Analysis Support — Research Brief

**Date:** 2026-03-30
**Context:** A 1.9GB MediaTek Android full update ZIP timed out on binwalk (600s). Android ZIPs contain sparse images and partition dumps, not standard firmware blobs. Wairz currently only handles embedded Linux firmware well.

---

## 1. Android Firmware Formats (Exhaustive)

### 1.1 Distribution Formats (outer container)

| Format | Description | Detection |
|--------|-------------|-----------|
| **Full OTA ZIP** | ZIP containing partition images (system.img, boot.img, vendor.img, etc.) | ZIP with `META-INF/com/google/android/updater-script` or `system.img` at top level |
| **A/B OTA ZIP** | ZIP containing `payload.bin` (Chrome OS Update Engine format) | ZIP with `payload.bin` entry; payload starts with magic `CrAU` (4 bytes) |
| **Factory Image ZIP** | Google Pixel/Nexus style: ZIP containing `flashall.sh` + inner ZIP with images | ZIP with `flashall.sh` or `flash-all.sh` |
| **Samsung Odin** | `.tar.md5` archives with partition images | Tar file with `.md5` extension; contains `AP_`, `BL_`, `CP_`, `CSC_` images |
| **MediaTek SP Flash** | ZIP with scatter file + raw partition dumps | ZIP containing `MT*_Android_scatter.txt` or `*_scatter.txt` |
| **Qualcomm QFIL** | ZIP with `rawprogram*.xml` + partition files | ZIP containing `rawprogram0.xml` |
| **Sony SIN** | `.sin` container format | Magic bytes specific to Sony |
| **LG KDZ/DZ** | `.kdz` compressed container | KDZ header magic |
| **Huawei UPDATE.APP** | Proprietary container with partition images | `UPDATE.APP` file with Huawei header |
| **OPPO OZIP** | Encrypted ZIP variant | Starts with `OPPOENCRYPT!` |

### 1.2 Partition Image Formats (inner images)

| Format | Magic Bytes | Description |
|--------|-------------|-------------|
| **Android Sparse** | `0x3aff26ed` (LE) at offset 0 | Sparse representation of ext4/EROFS; must be converted to raw before mounting |
| **Raw ext4** | `0xEF53` at offset 0x438 (superblock magic) | Standard Linux ext4 filesystem |
| **EROFS** | `0xE0F5E1E2` at offset 0x400 (superblock magic) | Read-only filesystem, increasingly common in Android 12+ |
| **super.img** | Can be sparse or raw; contains LP metadata | Dynamic partition container (Android 10+); holds system, vendor, product, odm |
| **boot.img** | `ANDROID!` at offset 0 | Kernel + ramdisk; header versions v0-v4 |
| **vendor_boot.img** | `VNDRBOOT` at offset 0 | Vendor ramdisk + DTB (Android 11+, header v3/v4) |
| **vbmeta.img** | `AVB0` at offset 0 | Android Verified Boot metadata |
| **dtbo.img** | `0xd7b7ab1e` at offset 0 | Device Tree Blob Overlay |
| **init_boot.img** | `ANDROID!` + specific header fields | Generic ramdisk (Android 13+) |
| **lz4-compressed** | `0x04224D18` at offset 0 | LZ4 frame format; wraps sparse/raw images |
| **Brotli-compressed** | No fixed magic; `.br` extension | `.new.dat.br` compressed system diffs |

### 1.3 MediaTek-Specific

| Component | Description |
|-----------|-------------|
| **Scatter file** | `MT*_Android_scatter.txt` — partition layout map with offsets, sizes, names |
| **preloader** | First-stage bootloader; `EMMC_BOOT` header (2048-byte header + binary) |
| **lk (Little Kernel)** | Second-stage bootloader |
| **tee (Trusted Execution)** | TrustZone firmware |
| **spmfw, sspm, mcupm** | MediaTek co-processor firmware blobs |

### 1.4 Boot Image Header Versions

| Version | Android | Key Changes |
|---------|---------|-------------|
| v0 | Pre-9 | kernel + ramdisk + second-stage (legacy) |
| v1 | 9 | Adds `recovery_dtbo` |
| v2 | 10 | Adds `dtb` field |
| v3 | 11 | Removes second-stage; adds `vendor_boot` partition |
| v4 | 12+ | Boot signature; multiple vendor ramdisk fragments |

---

## 2. Tool Compatibility Matrix

### 2.1 Core Tools

| Tool | Purpose | Debian ARM64 Package | Install Method | Notes |
|------|---------|---------------------|----------------|-------|
| **simg2img** | Sparse to raw image | `android-sdk-libsparse-utils` (arm64 confirmed) | `apt install` | ~26KB package; includes img2simg, simg_dump |
| **lpunpack** | Extract partitions from super.img | NOT in Debian | Build from `nmeum/android-tools` (CMake) or static binary | Requires protobuf, lz4, zstd deps |
| **payload-dumper-go** | Extract A/B OTA payload.bin | N/A | Pre-built Go binary from GitHub releases | **linux_arm64 confirmed** (v1.3.0) ~10MB |
| **unpack_bootimg** | Unpack boot.img (kernel + ramdisk) | `mkbootimg` (arm64, arch: all, Python) | `apt install mkbootimg` | Python script, supports v0-v4 headers |
| **erofs-utils** | Extract EROFS filesystems | `erofs-utils` (arm64 confirmed) | `apt install` | ~172KB; includes fsck.erofs, dump.erofs |
| **e2fsprogs** | ext4 extraction (debugfs, dump) | `e2fsprogs` (already in Dockerfile) | Already installed | For non-root ext4 extraction |
| **lz4** | Decompress LZ4-wrapped images | `liblz4-tool` | `apt install` | Command: `lz4 -d input output` |
| **brotli** | Decompress .br files | `brotli` | `apt install` | For `.new.dat.br` files |
| **unblob** | Generic firmware extraction | pip install | `pip install unblob` | Handles Android sparse + EROFS natively; does NOT handle super.img, boot.img, payload.bin |

### 2.2 Tool Gap Analysis

| Format | Handled by unblob? | Handled by binwalk? | Needs new tool? |
|--------|-------------------|---------------------|-----------------|
| Android sparse | YES | NO (causes timeout) | simg2img (fallback) |
| EROFS | YES | NO | erofs-utils (fallback) |
| super.img (LP) | NO | NO | **lpunpack required** |
| payload.bin (CrAU) | NO | NO | **payload-dumper-go required** |
| boot.img | NO | Partial (poor) | **unpack_bootimg required** |
| ext4 raw | YES | Partial | e2fsprogs (already available) |
| LZ4-wrapped | YES | YES | liblz4-tool (backup) |
| Brotli-compressed | NO | NO | **brotli required** |

---

## 3. Android ZIP Detection Strategy

### 3.1 Classification Heuristics

Add `"android_ota"` and `"android_factory"` to `classify_firmware()`:

```python
def _is_android_ota_zip(zip_path: str) -> str | None:
    """Detect Android OTA/firmware ZIP type.
    
    Returns: 'android_ab_ota', 'android_full_ota', 'android_factory',
             'android_mediatek', or None
    """
    with zipfile.ZipFile(zip_path) as zf:
        names = {info.filename for info in zf.infolist()}
        name_lower = {n.lower() for n in names}
        
        # A/B OTA: contains payload.bin
        if 'payload.bin' in names:
            return 'android_ab_ota'
        
        # MediaTek scatter file
        if any('scatter' in n and n.endswith('.txt') for n in name_lower):
            return 'android_mediatek'
        
        # Full OTA / factory image detection
        android_images = {'system.img', 'boot.img', 'vendor.img', 
                         'recovery.img', 'super.img'}
        found = names & android_images
        
        if len(found) >= 2:
            if any(n.startswith('flash') and n.endswith('.sh') for n in names):
                return 'android_factory'
            return 'android_full_ota'
        
        # Updater script (older OTAs)
        if 'META-INF/com/google/android/updater-script' in names:
            return 'android_full_ota'
    
    return None
```

### 3.2 Magic Byte Detection for Individual Images

```python
ANDROID_MAGIC = {
    b'\x3a\xff\x26\xed': 'android_sparse',   # Android sparse image
    b'ANDROID!':          'android_boot',      # boot.img
    b'VNDRBOOT':          'android_vendor_boot', # vendor_boot.img
    b'AVB0':              'android_vbmeta',    # vbmeta.img
    b'CrAU':              'android_payload',   # OTA payload.bin
}

# LZ4 frame magic (wraps sparse images in some firmware)
LZ4_MAGIC = b'\x04\x22\x4d\x18'

# EROFS superblock at offset 0x400
EROFS_MAGIC = b'\xe2\xe1\xf5\xe0'  # at offset 0x400

# ext4 superblock magic at offset 0x438
EXT4_MAGIC = b'\x53\xef'  # at offset 0x438
```

---

## 4. Extraction Pipeline Design

### 4.1 High-Level Flow

```
Upload ZIP
    │
    ├─ classify_firmware() detects "android_*" type
    │
    ├─ [android_ab_ota] payload.bin path:
    │   └─ Extract payload.bin from ZIP
    │   └─ payload-dumper-go → individual .img files
    │   └─ For each .img → partition pipeline (below)
    │
    ├─ [android_full_ota / android_factory / android_mediatek]:
    │   └─ Extract all .img files from ZIP
    │   └─ For each .img → partition pipeline (below)
    │
    └─ Partition pipeline (per .img):
        ├─ Is it Android sparse? (magic 0x3aff26ed)
        │   └─ simg2img → raw image → re-enter pipeline
        │
        ├─ Is it LZ4 compressed? (magic 0x04224D18)
        │   └─ lz4 -d → decompressed → re-enter pipeline
        │
        ├─ Is it super.img? (LP metadata signature inside raw image)
        │   └─ lpunpack → system.img, vendor.img, product.img, odm.img
        │   └─ For each → re-enter pipeline
        │
        ├─ Is it ext4? (magic 0x53EF at offset 0x438)
        │   └─ debugfs -R 'rdump / <output>' OR mount -o loop,ro
        │
        ├─ Is it EROFS? (magic at offset 0x400)
        │   └─ fsck.erofs --extract=<output> <image>
        │
        ├─ Is it boot.img? (magic ANDROID!)
        │   └─ unpack_bootimg → kernel + ramdisk
        │   └─ Decompress ramdisk (gzip/lz4) → cpio extract
        │
        └─ Unknown → skip (vbmeta, dtbo, etc. are metadata-only)

    Final: merge extracted filesystems → find_filesystem_root()
           (modified to understand Android layout: /system, /vendor, /product)
```

### 4.2 Android Filesystem Root Detection

Android doesn't have a traditional Linux rootfs. Instead:
- `/system` contains the OS (framework, apps, libs)
- `/vendor` contains hardware-specific blobs
- `/product` contains product customizations
- `/odm` contains ODM customizations
- `boot.img` ramdisk contains `/init`, `/init.rc`, SELinux policy

The `find_filesystem_root()` function needs modification:

```python
def _has_android_markers(path: str) -> bool:
    """Check if directory is an Android system partition."""
    entries = set(os.listdir(path))
    # system partition markers
    if 'framework' in entries and 'app' in entries:
        return True
    # vendor partition markers  
    if 'lib' in entries and 'firmware' in entries:
        return True
    # Android root (merged view)
    if 'system' in entries and 'vendor' in entries:
        return True
    return False
```

### 4.3 Implementation in `unpack.py`

New function: `unpack_android_firmware()` — called from `unpack_firmware()` when `classify_firmware()` returns an `android_*` type. Replaces the binwalk path entirely for Android images.

Key design decisions:
- **No root/mount required**: Use `debugfs` for ext4 (already in e2fsprogs) and `fsck.erofs --extract` for EROFS — both work without root
- **No loop mounts**: Avoids requiring `CAP_SYS_ADMIN` in Docker container
- **Parallel extraction**: Multiple partition images can be extracted concurrently with `asyncio.gather()`
- **Timeout**: 600s total (same as binwalk), but per-tool timeouts are much smaller (simg2img: 60s, lpunpack: 60s, payload-dumper-go: 300s for large payloads)

---

## 5. How Other Tools Handle Android

### 5.1 EMBA

- Module **P25** handles Android OTA extraction using `payload_dumper`
- Uses `simg2img` + `lpunpack` for sparse/super images
- Falls back to unblob for generic extraction
- Treats Android as a special case in the extraction layer

### 5.2 SRLabs Extractor

- Purpose-built for Android firmware
- Supports: android sparse, erofs, extfs, android signed images, android data image (brotli), pac, zip, lz4, tar, tar.md5, sin, ozip, app, kdz, bin, cpb, **super**
- Requires root (uses loopback mounts)
- Python-based; could be used as a reference implementation
- **Not suitable for direct integration** (root requirement, mount dependency)

### 5.3 AndroidDumps/Firmware_extractor

- Shell script (`extractor.sh`) handling 15+ Android formats
- Pipeline: detect format → extract outer container → sparse conversion → super extraction → filesystem extraction
- Uses: `simg2img`, `lpunpack`, `payload-dumper-go`, `sdat2img.py`, custom tools for Samsung/LG/Sony
- Good reference for detection heuristics and pipeline ordering

### 5.4 unblob

- Handles Android sparse images and EROFS natively (since v25.11.25)
- Does NOT handle: super.img, boot.img, payload.bin
- Could be used as a fallback/complement but not sufficient alone

---

## 6. ARM64 Host Considerations

The Wairz backend runs on ARM64 (Raspberry Pi 5, `aarch64`).

| Tool | ARM64 Status | Action Required |
|------|-------------|-----------------|
| simg2img | Debian `arm64` package available | `apt install android-sdk-libsparse-utils` |
| lpunpack | **No Debian package** | Build from `nmeum/android-tools` (CMake) OR download static binary; add to Dockerfile multi-stage build |
| payload-dumper-go | Pre-built `linux_arm64` binary on GitHub | Download in Dockerfile (similar to Grype/Syft pattern) |
| unpack_bootimg | Debian `mkbootimg` (arch: all, Python) | `apt install mkbootimg` |
| erofs-utils | Debian `arm64` package available | `apt install erofs-utils` |
| lz4 | Debian `arm64` package available | `apt install liblz4-tool` |
| brotli | Debian `arm64` package available | `apt install brotli` |

### lpunpack Build Strategy

Best option: build from `nmeum/android-tools` in a multi-stage Docker build:
```dockerfile
FROM python:3.12-slim AS lpunpack-builder
RUN apt-get update && apt-get install -y cmake g++ protobuf-compiler \
    libprotobuf-dev liblz4-dev libzstd-dev git
RUN git clone --depth 1 https://github.com/nmeum/android-tools.git /src \
    && cd /src && mkdir build && cd build \
    && cmake .. -DCMAKE_BUILD_TYPE=Release \
    && make lpunpack -j$(nproc)
# Then COPY --from=lpunpack-builder /src/build/vendor/lpunpack /usr/local/bin/
```

Alternative: use the Go-based `LonelyFool/lpunpack_and_lpmake` which may be easier to cross-compile.

---

## 7. SBOM Implications

### 7.1 Syft Capabilities for Android

- Syft supports **filesystem scanning** — it will find Debian/Alpine packages, Python/Java/Node artifacts within extracted Android images
- Syft supports **Java JAR** scanning (Android framework JARs in `/system/framework/`)
- Syft does NOT have a dedicated Android APK cataloger (Android `.apk` files are ZIP-wrapped DEX + resources; Syft won't parse the DEX manifest)
- Alpine `apk` support in Syft is for Alpine Linux packages, not Android APK files

### 7.2 What Syft Will Find in Android Firmware

- ELF shared libraries in `/system/lib64/`, `/vendor/lib64/` — binary cataloger
- Java JARs in `/system/framework/` — Java cataloger
- Python packages if present — Python cataloger
- Any embedded Linux packages (busybox, etc.) — binary cataloger

### 7.3 What Syft Will NOT Find

- Android app packages (`.apk` files) as distinct components
- DEX bytecode analysis
- Vendor blob identification (proprietary `.so` files without package metadata)
- Android build fingerprint / security patch level as version info

### 7.4 Recommendations

1. **Phase 1**: Use Syft as-is on extracted Android filesystem — it will find binary components, JARs, and any standard Linux packages
2. **Phase 2**: Parse `build.prop` for Android version, security patch level, vendor, model — add to firmware metadata
3. **Phase 3** (future): Custom cataloger for Android apps (parse `AndroidManifest.xml` from APK files) — significant effort, lower priority

---

## 8. Implementation Plan

### Phase 1: Android Detection + Basic Extraction (Effort: 2-3 days)

**Goal**: Detect Android firmware and extract using simg2img + ext4/EROFS tools.

1. **Dockerfile changes** (`backend/Dockerfile`):
   - Add packages: `android-sdk-libsparse-utils`, `erofs-utils`, `mkbootimg`, `liblz4-tool`, `brotli`
   - Approximately 30MB additional image size

2. **`classify_firmware()` changes** (`backend/app/workers/unpack.py`):
   - Add Android sparse magic detection (`0x3aff26ed`)
   - Add `_is_android_ota_zip()` for ZIP classification

3. **New function `unpack_android_zip()`** (`backend/app/workers/unpack.py`):
   - Extract images from ZIP
   - For each image: detect type → simg2img → extract ext4/EROFS
   - Handle super.img if lpunpack available (graceful degradation if not)

4. **Modify `find_filesystem_root()`** to understand Android layout

### Phase 2: A/B OTA + super.img Support (Effort: 2-3 days)

**Goal**: Handle modern Android (payload.bin, dynamic partitions).

1. **Dockerfile changes**:
   - Install `payload-dumper-go` (pre-built ARM64 binary, ~10MB)
   - Build `lpunpack` from `nmeum/android-tools` (multi-stage build)
   - Approximately 50MB additional image size

2. **New function `extract_payload_bin()`**:
   - Run `payload-dumper-go -o <output> <payload.bin>`
   - Returns list of extracted partition images

3. **New function `extract_super_img()`**:
   - `simg2img super.img super.raw` (if sparse)
   - `lpunpack super.raw <output>/`
   - Returns list of extracted partition images

4. **Partition type detection + recursive extraction**

### Phase 3: boot.img + Android Metadata (Effort: 1-2 days)

**Goal**: Extract boot images and surface Android-specific metadata.

1. **New function `extract_boot_img()`**:
   - `unpack_bootimg --boot_img <path> --out <output>`
   - Extract kernel, ramdisk (decompress gzip/lz4 → cpio extract)

2. **Android metadata extraction**:
   - Parse `build.prop` for: `ro.build.display.id`, `ro.build.version.release`, `ro.build.version.security_patch`, `ro.product.model`, `ro.product.manufacturer`
   - Surface in firmware metadata / OS info

3. **MCP tool updates**:
   - `get_firmware_metadata` — include Android-specific fields
   - `get_component_map` — understand Android partition layout

### Phase 4: Vendor-Specific Formats (Effort: 3-5 days, lower priority)

**Goal**: Handle Samsung, LG, Sony, Huawei, OPPO firmware.

- Each vendor has proprietary container formats
- Lower priority — focus on standard Android OTA first
- Reference: `AndroidDumps/Firmware_extractor/extractor.sh`

### Total Estimated Effort

| Phase | Effort | Priority | Docker Size Impact |
|-------|--------|----------|-------------------|
| Phase 1 | 2-3 days | HIGH | +30MB |
| Phase 2 | 2-3 days | HIGH | +60MB |
| Phase 3 | 1-2 days | MEDIUM | +0MB (tools already installed) |
| Phase 4 | 3-5 days | LOW | Varies |

**Total for Phase 1-3: 5-8 days, +90MB Docker image size**

---

## 9. Key Design Decisions

1. **No root/mount operations**: Use `debugfs` (ext4) and `fsck.erofs --extract` (EROFS) — both work unprivileged. Avoids needing `--privileged` Docker flag.

2. **Skip binwalk entirely for Android**: Android firmware should never hit binwalk. Detect early in `classify_firmware()` and route to dedicated pipeline.

3. **Graceful degradation**: If lpunpack or payload-dumper-go aren't installed, log a warning and skip those formats rather than failing the entire unpack.

4. **Recursive pipeline**: Partition images can be nested (sparse → super → system → ext4). The pipeline must handle this recursion with a depth limit (max 3-4 levels).

5. **Parallel extraction**: Multiple partition images are independent — extract concurrently with `asyncio.gather()`.

6. **Merged filesystem view**: After extracting system, vendor, product, etc., present them in a merged view under the firmware root (mirroring how Android mounts them).

---

## HANDOFF

### What was researched
Comprehensive investigation of Android firmware analysis support for the Wairz platform, covering all Android firmware formats, extraction tools, detection heuristics, pipeline design, ARM64 compatibility, and SBOM implications.

### Key findings
1. Android firmware uses a layered format: outer container (OTA ZIP) → partition images (sparse/raw) → filesystems (ext4/EROFS), requiring multi-stage extraction
2. The core tools needed are: simg2img (Debian ARM64 pkg), lpunpack (must build), payload-dumper-go (pre-built ARM64 binary), unpack_bootimg (Debian pkg), erofs-utils (Debian ARM64 pkg)
3. unblob handles Android sparse and EROFS but NOT super.img, boot.img, or payload.bin — dedicated tools are required
4. All critical tools work on ARM64/aarch64; lpunpack is the only one requiring a from-source build
5. Android firmware should bypass binwalk entirely — detected early via ZIP content inspection and magic bytes
6. No root/mount operations needed — debugfs and fsck.erofs work unprivileged

### Files examined
- `/home/kali/code/wairz/backend/app/workers/unpack.py` — current extraction pipeline
- `/home/kali/code/wairz/backend/app/services/firmware_service.py` — upload + ZIP handling
- `/home/kali/code/wairz/backend/Dockerfile` — current tool installation
- `/home/kali/code/wairz/backend/app/services/sbom_service.py` — existing Android marker detection

### What needs building
- Phase 1 (HIGH): Android ZIP detection + simg2img/ext4/EROFS extraction (2-3 days)
- Phase 2 (HIGH): payload-dumper-go + lpunpack for A/B OTA and super.img (2-3 days)  
- Phase 3 (MEDIUM): boot.img extraction + Android metadata parsing (1-2 days)
- Phase 4 (LOW): Vendor-specific formats — Samsung, MediaTek, etc. (3-5 days)

### Unresolved questions
1. Should ext4 extraction use `debugfs -R 'rdump'` (no root, works in Docker) or attempt `mount -o loop,ro` (needs CAP_SYS_ADMIN)?
2. Should the merged Android filesystem present `/system`, `/vendor`, `/product` as separate trees or overlay them into a single root?
3. lpunpack build strategy: build in Docker multi-stage (adds build time) vs. maintain pre-built binaries?
4. Should vendor-specific decryption (OPPO OZIP, Huawei UPDATE.APP) be supported, and if so, what are the legal/licensing implications?
