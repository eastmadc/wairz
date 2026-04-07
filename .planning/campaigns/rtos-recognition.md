# Campaign: RTOS/Bare-Metal Firmware Recognition

**Status:** completed
**Created:** 2026-04-06
**Seed:** `.planning/seeds/rtos-recognition.yaml`
**Estimated sessions:** 3-4
**Estimated cost:** ~$8

## Direction

Detect FreeRTOS, Zephyr, VxWorks, ThreadX/Azure RTOS, QNX, SafeRTOS, and uC/OS (II & III) from binary firmware images. Extract versions, companion components (network stacks, filesystems, crypto libraries), and generate SBOM entries. Component-level detection (per-binary, not per-firmware).

Deep research first — validate detection signatures against real-world binary patterns before building.

## Phases

| # | Type | Name | Status | End Conditions |
|---|------|------|--------|----------------|
| 1 | research | Deep RTOS fingerprinting research | complete | Research brief at `.planning/research/rtos-fingerprinting.md` |
| 2 | build | RTOS detection engine | complete | `backend/app/services/rtos_detection_service.py` (611 lines) |
| 3 | build | Deep metadata extraction | complete | `extract_companion_components()` covers 13 components |
| 4 | build | Firmware classifier + SBOM + MCP tool | complete | `classify_firmware()` returns RTOS types; `detect_rtos` MCP tool registered |
| 5 | verify | End-to-end verification | complete | Docker rebuilt, API healthy, imports verified |

## Phase Details

### Phase 1: Deep RTOS Fingerprinting Research

**Goal:** Validate and extend the seed's detection signatures against real-world patterns. Research edge cases.

**Research questions:**
1. VxWorks symbol table binary format — entry sizes 0x0E/0x10/0x14/0x18, how to reliably detect and parse
2. QNX IFS (Image Filesystem) header format — startup header 0x00ff7eeb, imagefs magic, endianness variants
3. Zephyr MCUboot image header — magic 0x96f3b83d, binary descriptor 0xb9863e5a7ea46046, version encoding
4. FreeRTOS vs SafeRTOS disambiguation — what symbols/strings reliably distinguish them
5. Stripped binary detection — when ELF symbol tables are stripped, what alternatives exist (string patterns, code patterns, section names)
6. ThreadX/Azure RTOS → Eclipse ThreadX rebrand — detection across versions
7. Real-world RTOS firmware samples — where to find test binaries, what signature variations exist
8. cpu_rec integration — how to use it for architecture detection on raw (non-ELF) RTOS blobs
9. Companion component version string formats — lwIP, wolfSSL, mbedTLS, LittleFS, FatFS patterns in the wild
10. Existing tools (binwalk, cpu_rec, FACT) — what RTOS detection do they implement, what can we learn

**Delegation:** Ouroboros lateral-think + Citadel research-fleet (3 parallel scouts)

### Phase 2: RTOS Detection Engine

**Goal:** Create `backend/app/services/rtos_detection_service.py` (~600 lines)

**Tiered detection:**
1. Magic byte scan (raw binary, fast reject)
2. String pattern scan (first 1MB)
3. Symbol/function name scan (LIEF ELF)
4. ELF section scan
5. VxWorks symbol table heuristic

**Acceptance:** All 8 RTOS targets detectable with structured results (name, version, confidence, methods).

### Phase 3: Deep Metadata Extraction

**Goal:** Extend detection for companion components

- Network stacks: lwIP, FreeRTOS+TCP, NetX Duo, VxWorks END, QNX io-pkt, uIP, Zephyr native
- Filesystems: LittleFS, SPIFFS, FatFS, FileX, VxWorks dosFs, QNX fs-qnx6
- Crypto: wolfSSL, mbedTLS, tinycrypt, BearSSL
- Task/thread names, build config, architecture

### Phase 4: Firmware Classifier + SBOM + MCP Tool

**Goal:** Wire everything into the existing pipeline

- Extend `classify_firmware()` in `unpack_common.py` (after ELF check, before linux_blob fallback)
- Generate SBOM entries from RTOS + companions via `sbom_service.py`
- Store metadata in `firmware.os_info` JSONB
- Add `detect_rtos` MCP tool in `binary.py`
- Scan individual binaries within Linux firmware (coprocessor blobs in `/lib/firmware/`)

### Phase 5: Verify

- All existing tests pass
- Docker rebuild succeeds
- API smoke test
- No new Python dependencies needed

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-06 | Deep research before build | User requested Ouroboros + Citadel deep research to validate signatures |
| 2026-04-06 | Component-level detection | Each binary gets its own RTOS classification, not per-firmware |
| 2026-04-06 | No Ghidra in hot path | Use LIEF + Capstone + strings — fast enough for batch scanning |

## Feature Ledger

| Phase | Feature | Status | Notes |
|-------|---------|--------|-------|
| 1 | Research brief | done | 3 parallel scouts, 253+ web searches |
| 2 | rtos_detection_service.py | done | 611 lines, 5-tier detection |
| 2 | detect_rtos() | done | Returns name, version, confidence, methods |
| 2 | extract_companion_components() | done | 13 components: lwIP, wolfSSL, mbedTLS, etc. |
| 2 | Tier 1: Magic bytes | done | Zephyr MCUboot, bindesc, QNX IFS, VxWorks MemFS |
| 2 | Tier 2: String patterns | done | ThreadX, uC/OS, FreeRTOS, VxWorks, Zephyr, QNX, SafeRTOS |
| 2 | Tier 3: Symbols | done | LIEF ELF/PE parsing for all 8 RTOS targets |
| 2 | Tier 4: ELF sections | done | Zephyr k_*_area, QNX .QNX_info, OSABI |
| 2 | Tier 5: VxWorks symtab | done | Heuristic scanning with 3 entry sizes |
| 4 | classify_firmware() RTOS | done | Returns freertos_elf, zephyr_elf, etc. + rtos_blob |
| 4 | detect_rtos MCP tool | done | Registered in binary.py |
| 4 | RTOS unpack pipeline | done | Stores os_info JSON, sets architecture/endianness |
| — | ZIP path collision fix | done | Bonus: fixed update.zip-inside-update.zip crash |

## Active Context

Campaign created 2026-04-06. Starting with Phase 1: deep research.

## Continuation State

```
current_phase: 1
current_step: starting research
checkpoint-phase-1: none
```
