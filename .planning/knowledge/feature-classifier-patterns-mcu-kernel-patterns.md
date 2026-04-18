# Patterns: Classifier patterns — NXP iMX-RT MCU + ARM zImage + vendor signed archives

> Extracted: 2026-04-17
> Campaign: .planning/campaigns/completed/feature-classifier-patterns-mcu-kernel.md
> Postmortem: .planning/postmortems/postmortem-feature-classifier-patterns-mcu-kernel-2026-04-17.md

## Successful Patterns

### 1. Intake brief as implementation spec — regex + offsets inline
- **Description:** The intake file specified exact filename regexes (`^imxrt\d+_.*\.bin$`, `^ix_iv_\d+\(.*\)\.bin$`, `^zImage.*`, etc.) AND magic-byte offsets (`0x016F2818` at 0x24, `a3 df bb bf` at 0). The build phase copied those verbatim into YAML + Python with only trivial syntactic adaptation.
- **Evidence:** 5 YAML patterns + 2 magic-byte gates landed without rework. Zero phases looped. Total session time ≈ 1 hour.
- **Applies when:** Any campaign that extends a known data-driven classifier, lookup table, or pattern list. If the intake can specify the exact matcher shape, the build phase is near-mechanical — use intake space for design, not just problem description.

### 2. YAML + loader substrate pays compounding dividends
- **Description:** `patterns_loader.py` + `firmware_patterns.yaml` + `vendor_prefixes.yaml` is the third campaign (after hw-firmware phase 1 and phase 3 parsers) where "add rows to YAML" was the whole build. Each campaign added patterns, not parser code.
- **Evidence:** This campaign added 5 rows to firmware_patterns.yaml + 1 row to vendor_prefixes.yaml + 2 CATEGORIES + 5 FORMATS + 2 magic gates = 6 files of ~40 lines of change total. No classifier logic refactored.
- **Applies when:** Data-driven extension. When adding a new blob family, check if a YAML/TOML/JSON data file exists before reaching for code. If the load/match layer is already there, treat it as schema-first work.

### 3. Filename-first, magic-byte as tie-breaker / precedence
- **Description:** For zImage: the YAML pattern catches *any* file named `zImage*` (category=kernel), and a tighter magic-byte check at offset 0x24 (0x016F2818) upgrades the match to high-confidence when the canonical header is present. Both paths are tested. Cheap when magic fits in the 64-byte buffer, robust fallback when it doesn't.
- **Evidence:** Two separate tests — `test_classify_linux_zimage_by_magic` (magic path) and `test_classify_linux_zimage_by_filename_fallback` (YAML path) — both pass with the same detector output category.
- **Applies when:** Formats with a well-known header AND a well-known filename convention. Gate with magic when the header fits in the buffer; fall through to filename otherwise. Don't require magic when the filename is already distinctive — that's how real files in the wild with mangled headers still get categorized.

### 4. Run tests via project venv, not system Python
- **Description:** The backend container's system Python has no app dependencies. Tests must run as `docker compose exec backend .venv/bin/python -m pytest ...`. Short-circuit on `pytest` (not installed) or plain `python -m pytest` (no sqlalchemy) both fail misleadingly; `.venv/bin/python` just works.
- **Evidence:** Two failed test-runner invocations before finding `/app/.venv/bin/python`. Once found, every subsequent test batch worked first try.
- **Applies when:** Any test / manage command on the wairz backend container. Document in CLAUDE.md as a project convention.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| iMX-RT uses filename-only detection (not BOOT_DATA magic at 0x1000) | Detector's magic buffer is hard-coded to 64 bytes (`_MAGIC_READ_BYTES`). Offset 0x1000 = 4096 unreachable without widening the read. | Correct — all observed iMX-RT files on the RespArray firmware have matching filenames. Follow-up would require a parameterized magic-read size. |
| zImage has both a magic-byte gate AND a YAML filename pattern | Canonical zImage header (0x016F2818 @ 0x24) fits in the buffer and upgrades confidence; filename pattern covers mangled/embedded cases. | Correct — both tested paths pass. Magic wins when present, filename wins otherwise; same category result. |
| signed-archive (`a3 df bb bf`) gets a placeholder classification, not silent skip | Skipping leaves the UI blank for 4+ RespArray files. Surface "unknown signed archive" so users see what's there, even without decode. | Correct — format=signed_archive, category=other, medium confidence. Users now see an entry; deep decode deferred as a separate campaign. |
| Categories `mcu` and `kernel` are new top-level buckets | Neither fits existing categories (modem/tee/wifi/etc.) Cortex-M MCU firmware is a distinct class; Linux kernel images are compiler output, not a hardware component. | Correct — no DB constraint broken (category column is free String(32)). CATEGORIES set is documentation only. |
| Edan (medical OEM) added to vendor_prefixes.yaml with medium confidence | Low prior-art for Edan blob formats; only RespArray sample exists. | Correct for now — can tighten confidence if patterns confirm. |

## Applicability note

When the next "add classifier coverage for {device family}" campaign arrives, expect the shape to repeat:
1. Intake specifies filename regex + any available magic offsets.
2. Add rows to `firmware_patterns.yaml` (+ vendor to `vendor_prefixes.yaml` if new).
3. Add CATEGORIES / FORMATS entries if the family introduces a new bucket.
4. Add magic-byte gates in `_classify_by_magic` ONLY if the magic fits in the first 64 bytes.
5. Extend `test_hardware_firmware_classifier_patterns.py` — 2-3 tests per pattern (positive, magic-precedence if applicable, category/format export assertion).
6. Run via `.venv/bin/python -m pytest`.

Total change budget: ~50 lines of code + ~60 lines of tests.
