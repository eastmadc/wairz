# Plan: RTOS/Bare-Metal Firmware Recognition (5.3)

**Priority:** Medium | **Effort:** Large (1-2 weeks) | **Route:** `/ouroboros:interview` then `/citadel:archon` (3 phases)

## Goal

Detect FreeRTOS, Zephyr, VxWorks, ThreadX from binary patterns. Extract versions. Generate basic SBOM.

## Current State

- `classify_firmware()` in `unpack_common.py` handles Android, UEFI, Linux — no RTOS
- `Firmware` model has `os_info` and `binary_info` JSONB fields ready for RTOS metadata
- `SbomComponent` model has `metadata_` field for extensibility
- No RTOS-related code exists anywhere in the codebase

## RTOS Detection Signatures

| RTOS | Magic/Pattern | Version Source |
|------|---------------|----------------|
| **Zephyr** | Magic `0xb9863e5a7ea46046` (binary descriptor header) | TLV tag `0x1800` for app version |
| **FreeRTOS** | String "IDLE" (default idle task), function `xPortSysTickHandler` | String pattern `FreeRTOS V\d+\.\d+` |
| **VxWorks** | Symbol table at known offset (heuristic scan) | Ghidra `VxWorksSymTab_Finder.java` |
| **ThreadX** | Function pattern matching (no public magic bytes) | String pattern `ThreadX V\d+` |

## Integration Approach

1. Extend `classify_firmware()` to check RTOS signatures before `linux_blob` fallback
2. RTOS binaries lack Linux filesystems — skip `find_filesystem_root()`, extract strings instead
3. Generate minimal SBOM from detected components using existing `SbomComponent` model
4. Add new MCP tool `detect_rtos` for on-demand analysis

## Phases

| Phase | Type | Scope |
|-------|------|-------|
| 1 | research | Deep dive on binary signatures, build pattern library |
| 2 | build | FreeRTOS + Zephyr detection (magic bytes + strings) |
| 3 | build | VxWorks + ThreadX (symbol table heuristics) + SBOM generation |

## References

- RECON 2017: Reversing FreeRTOS on embedded devices
- ONEKEY: Automated RTOS firmware analysis
- Zephyr binary descriptors documentation
- Quarkslab: Reverse engineering VxWorks
- Binary Ninja 4.2+ native VxWorks support
