# Patterns: Android Firmware Support

> Extracted: 2026-04-06
> Campaign: .planning/campaigns/android-firmware-support.md
> Postmortem: none

## Successful Patterns

### 1. Filesystem Signature Scanning Over Metadata Parsing
- **Description:** Used filesystem magic byte scanning at 1MB boundaries to find EROFS/ext4 partitions inside super.img, instead of parsing LP (logical partition) metadata headers.
- **Evidence:** Phase 6 completed without lpunpack dependency. `_scan_super_partitions()` found all partitions. Decision log confirms "found all partitions without lpunpack."
- **Applies when:** Extracting data from container formats with documented but complex metadata. If the payload format (ext4, EROFS, squashfs) has reliable magic bytes, scanning for them directly is more robust than parsing the container's index.

### 2. Content-Based Naming Post-Extraction
- **Description:** Named super.img partitions (system/vendor/product) based on examining extracted filesystem content, not LP metadata labels.
- **Evidence:** Phase 11 added `_identify_partition_by_content()`. Decision log: "Content-based partition naming post-extraction rather than pre-extraction — more robust, doesn't depend on LP metadata."
- **Applies when:** Extracting multi-partition images where partition names exist in metadata but content is the ground truth. Useful for any firmware format with unreliable or missing partition labels.

### 3. Native Python Parser Over External Tool Dependency
- **Description:** Wrote a native Python boot.img parser (v0-v4 headers) instead of adding `mkbootimg`/`unpack_bootimg` as a Docker dependency.
- **Evidence:** Phase 7 completed with `_extract_boot_img()` in unpack_android.py. Decision log: "Native Python boot.img parser instead of mkbootimg dependency — simpler, no extra Docker tool needed."
- **Applies when:** The format is well-documented and simple (fixed-size headers + offsets). Prefer native parsing over subprocess calls for formats under ~500 bytes of header.

### 4. Chroot-Style Symlink Resolution
- **Description:** Implemented `_resolve_within_root()` that resolves absolute symlinks relative to the extracted root, not the host filesystem. Foundational fix for all firmware with absolute symlinks (common in Linux/Android rootfs).
- **Evidence:** Listed in Decision Log and Feature Ledger. Addressed a class of path traversal bugs across ALL firmware types, not just Android.
- **Applies when:** Walking or analyzing extracted firmware filesystems that contain absolute symlinks. NEVER use `os.path.realpath()` on symlinks inside extracted roots — it resolves against the host.

### 5. Multi-Phase 11-Step Pipeline with Clear End Conditions
- **Description:** Decomposed Android extraction into 11 granular phases with specific end conditions per phase. This allowed parallel agent work (3 agents per session) and easy progress tracking.
- **Evidence:** All 11 phases completed across 3 sessions without rework. Citadel rollout strategy in campaign file planned 3-agent parallelism.
- **Applies when:** Large extraction/analysis features with multiple independent tools (simg2img, lpunpack, payload-dumper-go, etc.). Each tool integration is its own phase with a testable end condition.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Filesystem scanning over LP metadata parsing | More robust, avoids complex container format parsing | Worked — found all partitions without lpunpack |
| Chroot symlink resolution over realpath | realpath follows symlinks into host FS — security risk | Worked — foundational fix for all firmware types |
| Preserve Android ZIPs intact on upload | Let existing unpack pipeline handle format detection | Worked — simpler than pre-extraction at upload time |
| Content-based partition naming | LP metadata labels may be missing or wrong | Worked — robust naming without metadata dependency |
| Native Python boot.img parser | Avoids Docker dependency for a simple format (v0-v4 headers) | Worked — no extra tool needed, covers all common versions |
| 2+ marker threshold for Android detection | Single marker could false-positive on non-Android ZIPs | Worked — 21 classification tests all passing |
