---
title: "Feature: Classifier patterns for NXP iMX RT MCU + ARM zImage + vendor-specific encrypted archives"
status: pending
priority: high
target: backend/app/services/hardware_firmware/classifier.py, data/firmware_patterns.yaml, data/vendor_prefixes.yaml, workers/unpack_common.py
estimated_sessions: 1
source: Live audit 2026-04-17 of project 00815038 (RespArray firmware) — found 4 un-classified .bin + zImage after extraction-integrity fix
---

## Overview

After the extraction-integrity campaign landed the recursive-archive + shallow-container fixes, project 00815038 (RespArray_1.05.00.17.zip) went from 0 to 11 detected blobs (all DTBs). But 4 MCU firmware .bin files + 1 Linux zImage + 1 frontboard firmware remain un-classified because the existing classifier patterns don't know about them.

## Gaps found

1. **NXP iMX RT1052 Cortex-M MCU firmware** — files like `imxrt1052_ix_iv_iap.bin` (89KB), `imxrt1052_ix_iv(MERGE).bin` (1.9MB). These are raw ARM Cortex-M7 firmware images.
   - First 4 bytes: initial stack pointer (0x2000xxxx or 0x1FFFxxxx for FlexRAM), next 4 bytes: reset handler address (0x600xxxxx for Boot ROM).
   - Filename pattern: `^imxrt\d+_.*\.bin$` → vendor=nxp, category=mcu.
   - Can also detect via BOOT_DATA magic at offset 0x1000 (iMX-RT bootable image header).

2. **Frontboard firmware** (RespArray-specific medical device MCU firmware):
   - `frontboard/ix_iv_070(MERGE).bin`
   - `frontboard/update/ix_iv_070(IAP).bin`
   - Filename pattern: `^ix_iv_\d+\(.*\)\.bin$` → vendor=edan (medical device OEM — add to vendor_prefixes.yaml as "Edan Instruments, Inc.")

3. **Linux zImage** — top-level kernel image `zImage-restore/zImage-restore` is detected as a file by the detector walker but not classified as hw firmware. The classifier detects `.ko` (kernel modules) and DTBs but not the compressed kernel zImage itself.
   - Magic bytes at offset 0x24: `0x016F2818` (little-endian) or look for `U5NM` at offset 0x30-0x34.
   - Filename pattern: `^zImage.*|^uImage.*|^vmlinuz.*` → category=kernel, format=zImage.

4. **Vendor-specific encrypted archives** — RespArray uses a proprietary format starting with magic `a3 df bb bf` for most of its `*.tar.xz`-extensioned archives (they're NOT real tar.xz). The recursive-extract helper correctly skips them (can't open), but the UI shows them unchanged. Could add:
   - A `_dir_has_custom_archive_magic()` check that detects this magic as a signed-archive variant.
   - A placeholder classifier entry `format=signed_archive_a3dfbbbf` so users see "unknown signed archive" rather than nothing.
   - Longer-term: reverse-engineer the magic (likely a sig/payload concatenation — the `.signature` files alongside hint at separable sig+body).

## Deliverables

1. `firmware_patterns.yaml` entries for:
   - `^imxrt\d+_.*\.bin$` → vendor=nxp, category=mcu, format=imxrt_bin, confidence=high.
   - `^ix_iv_\d+\(.*\)\.bin$` → vendor=edan, category=mcu, format=raw_bin, confidence=medium.
   - `^zImage(-restore)?$` → category=kernel, format=zImage, confidence=high.
   - `^vmlinuz.*$` → category=kernel, format=vmlinuz, confidence=high.
   - `^uImage.*$` → category=kernel, format=uImage, confidence=high.

2. `vendor_prefixes.yaml` entries:
   - `nxp` → "NXP Semiconductors" (already present, confirm).
   - `edan` → "Edan Instruments, Inc." (new).

3. `classifier.py` — magic-byte detection for:
   - Linux zImage (magic at offset 0x24 = `0x016F2818`).
   - iMX-RT BOOT_DATA header magic (offset 0x1000, for bootable iMX-RT images).
   - Optional: custom-archive magic `a3 df bb bf` → emit a classification with format `signed_archive` and category `other` so the file is visible in the UI.

4. Test fixture in `backend/tests/fixtures/mcu_classifier.py` with synthetic samples and a small test in `test_firmware_classification.py` covering each new pattern.

## Acceptance criteria

- [ ] Re-running detection on project 00815038 firmware b5bcf2db returns ≥15 blobs (was 11; adding 2 iMX-RT + 1 frontboard + 1 zImage = 15).
- [ ] New classifier tests pass.
- [ ] No regression in existing 250+ test suite.

## Risks

- `^zImage.*` pattern is broad; may false-positive on Android zImage partitions. Keep magic-byte check as gate.
- Edan is a niche medical-device vendor; low prior-art for patterns. Add with medium confidence.
- The custom encrypted format (`a3 df bb bf`) is an open question — don't attempt decode, just surface.

## References

- Root commit that uncovered this: 84d94ce (extraction-integrity multi-archive fix).
- Live firmware investigated: `/data/firmware/projects/00815038-cb0f-4642-b2bf-2f176fd807f7/firmware/b5bcf2db-7da7-4503-a0e2-5ffa0f2ed000/zip_contents/`.
- NXP iMX RT1052 reference manual — Boot ROM + BOOT_DATA structure.
- Linux kernel Documentation/arm/booting.rst — zImage format.
