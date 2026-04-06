# Anti-patterns: Android Firmware Support

> Extracted: 2026-04-06
> Campaign: .planning/campaigns/android-firmware-support.md

## Failed Patterns

### 1. Extracting Largest File from ZIP at Upload Time
- **What was done:** Initially tried to detect Android ZIPs at upload time and extract the largest .img file, discarding the ZIP container.
- **Failure mode:** Lost partition structure. Android ZIPs contain multiple partition images (system, vendor, boot, etc.) that must be processed together. Extracting only the largest loses the rest.
- **Evidence:** Decision log: "Upload flow preserves Android ZIPs intact instead of extracting largest file." Phase 10 added `_is_android_firmware_zip()` to detect and preserve ZIPs.
- **How to avoid:** When a container format (ZIP, tar) has multiple meaningful payloads, preserve the container and handle extraction in the unpack pipeline where all parts are visible.

### 2. Using os.path.realpath on Extracted Firmware Symlinks
- **What was done:** Used `os.path.realpath()` to resolve symlinks inside extracted firmware rootfs.
- **Failure mode:** Absolute symlinks (e.g., `/lib/libcrypto.so → /usr/lib/libcrypto.so.1.1`) resolve against the HOST filesystem, not the extracted root. This is both a security risk (path traversal) and a functional bug (files not found).
- **Evidence:** `_resolve_within_root()` was created as a foundational fix, listed in both Feature Ledger and Decision Log.
- **How to avoid:** Never use `os.path.realpath()` on paths inside extracted firmware. Always resolve symlinks relative to the extracted root directory using a chroot-style resolution that strips the leading `/` and re-anchors to the extracted path.

### 3. Depending on LP Metadata for Partition Names
- **What was done:** Initially planned to read LP (logical partition) metadata from super.img to get partition names (system, vendor, product).
- **Failure mode:** LP metadata parsing is complex (offset 0x1000, variable-length structures) and names may be missing or generic in some OEM implementations.
- **Evidence:** Replaced by content-based naming in Phase 11. Decision: "Content-based partition naming post-extraction rather than pre-extraction — more robust."
- **How to avoid:** When metadata is complex and unreliable, prefer content-based identification (look inside the extracted data) over metadata-based identification (parse container headers).
