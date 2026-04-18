# Campaign: Classifier patterns for NXP iMX RT MCU + ARM zImage + vendor-specific encrypted archives

**Status:** completed
**Completed:** 2026-04-17
**Created:** 2026-04-17
**Intake:** `.planning/intake/feature-classifier-patterns-mcu-kernel.md`
**Estimated sessions:** 1
**Estimated cost:** ~$2

## Direction

Teach the hardware-firmware classifier about three new blob families that turned up on the RespArray medical firmware (project 00815038) after the extraction-integrity fix:

1. **NXP i.MX RT Cortex-M MCU firmware** (`imxrt1052_*.bin`)
2. **Edan frontboard MCU firmware** (`ix_iv_NNN(MERGE|IAP).bin`)
3. **Linux kernel images** (`zImage`, `uImage`, `vmlinuz`) — currently invisible in classifier output
4. **Custom signed-archive format** (`a3 df bb bf` magic) — emit a placeholder so users see the file

Expected: re-detection on firmware b5bcf2db lifts blob count 11 → 15+.

## Phases

| # | Type | Name | Status | End Conditions |
|---|------|------|--------|----------------|
| 1 | research | Survey classifier structure + existing test patterns | complete | Read classifier.py (320 loc), patterns_loader.py, test_hardware_firmware_classifier_patterns.py |
| 2 | build | Add YAML patterns + vendor prefix | complete | firmware_patterns.yaml +5 entries (iMX-RT, Edan, zImage, uImage, vmlinuz); vendor_prefixes.yaml +edan |
| 3 | build | Extend classifier.py — new CATEGORIES, FORMATS, magic-byte gates | complete | `mcu`, `kernel` added to CATEGORIES; `imxrt_bin`, `zImage`, `uImage`, `vmlinuz`, `signed_archive` added to FORMATS; magic-byte check for zImage (0x016F2818 @ 0x24) + signed_archive (a3dfbbbf @ 0) |
| 4 | build | Tests for new patterns + magic | complete | 12 new tests in test_hardware_firmware_classifier_patterns.py covering iMX-RT, Edan, kernel images (zImage magic + filename fallback, uImage, vmlinuz), signed_archive, category/format export |
| 5 | verify | Full test suite regression check | complete | 225 tests pass across hardware/classifier/firmware-classification/extraction-integrity/firmware-paths |

## Phase End Conditions (machine-verifiable)

| Phase | Type | Check |
|-------|------|-------|
| 2 | file_exists | `backend/app/services/hardware_firmware/data/firmware_patterns.yaml` contains `imxrt` string |
| 2 | command_passes | `grep -q "edan" backend/app/services/hardware_firmware/data/vendor_prefixes.yaml` exits 0 |
| 3 | command_passes | `grep -q '"mcu"' backend/app/services/hardware_firmware/classifier.py` exits 0 |
| 4 | command_passes | `grep -q "imxrt\|zImage\|edan" backend/tests/test_hardware_firmware_classifier_patterns.py` exits 0 |
| 5 | command_passes | `docker compose exec backend pytest -q backend/tests/test_hardware_firmware_classifier_patterns.py` exits 0 |

## Design decisions

- **iMX-RT BOOT_DATA at offset 0x1000** — classifier only receives 64 bytes of magic per the detector (`_MAGIC_READ_BYTES = 64`), so we rely on filename pattern (`^imxrt\d+_.*\.bin$`) instead of deep header scan. Future phase could pass more bytes for MCU-category hits.
- **zImage magic at offset 0x24 (0x016F2818 LE)** — fits inside 64-byte buffer, adds high-confidence magic gate over the broad filename pattern.
- **`zImage.*` filename pattern** — could false-positive on Android zImage partition files, but category-level match on `kernel` is still correct for those, so acceptable.
- **Edan vendor** — new. Medical-device OEM; low prior-art for their blob format. Medium confidence.
- **signed_archive placeholder** — emits `category=other, format=signed_archive` so UI shows the file. No decode attempted (separate longer-term work).

## Active Context

Current phase: 2 (build YAML patterns). Research complete. Execute phases 2-4 sequentially, then verify.

## Continuation State

- checkpoint-phase-2: none (clean working tree check failed; continuing)

## Feature Ledger

- 2026-04-17 phase 2: vendor_prefixes.yaml → added `edan` (Edan Instruments, Inc.). firmware_patterns.yaml → added 5 entries: imxrt (nxp/mcu/high), ix_iv_N(suffix) (edan/mcu/medium), zImage (unknown/kernel/high), uImage (unknown/kernel/high), vmlinuz (unknown/kernel/high).
- 2026-04-17 phase 3: classifier.py → CATEGORIES +`mcu` +`kernel`; FORMATS +`imxrt_bin` +`zImage` +`uImage` +`vmlinuz` +`signed_archive`; `_classify_by_magic` → zImage magic gate (0x016F2818 @ 0x24) + signed_archive placeholder (\xa3\xdf\xbb\xbf @ 0).
- 2026-04-17 phase 4: test_hardware_firmware_classifier_patterns.py → +12 tests (24 → 36 in that file).
- 2026-04-17 phase 5: docker compose exec backend pytest — 225/225 pass across the related test modules.

## Decision Log

- 2026-04-17: Use filename-based detection for iMX-RT (not BOOT_DATA magic at 0x1000) — magic buffer is only 64 bytes. Follow-up: larger magic buffer if MCU support needs deep parsing.
