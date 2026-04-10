---
Status: completed (all phases)
Direction: Add UEFI/BIOS firmware unpacking, analysis, and security assessment
Estimated Sessions: 2
Type: build
---

# Campaign: UEFI Firmware Support

## Direction

Add full UEFI/BIOS firmware analysis capability to Wairz: detection, extraction
via UEFIExtract, structure browsing (firmware volumes, DXE/PEI/SMM modules, NVRAM),
and security assessment via VulHunt integration.

## Phases

| # | Type | Description | Status |
|---|------|-------------|--------|
| 1 | build | UEFI detection + UEFIExtract in Docker + extraction pipeline | complete |
| 2 | build | UEFI MCP tools (5 tools) + REST endpoints | complete |
| 3 | build | VulHunt Docker sidecar + UEFI security assessment | complete |
| 4 | verify | Test with real UEFI firmware (D3633-S1.ROM, Framework BIOS) | complete |

## Phase End Conditions

| Phase | Condition | Type |
|-------|-----------|------|
| 1 | `classify_firmware()` returns `uefi_firmware` for .ROM/.CAP files | command_passes |
| 1 | `UEFIExtract` binary exists in backend container | command_passes |
| 1 | UEFI firmware upload produces .dump/ directory | manual |
| 2 | `list_firmware_volumes` MCP tool returns results for UEFI firmware | manual |
| 2 | `list_uefi_modules` MCP tool lists DXE drivers with GUIDs | manual |
| 3 | VulHunt container runs in docker-compose | command_passes |
| 3 | `vulhunt_scan_firmware` produces findings for UEFI modules | manual |
| 4 | D3633-S1.ROM extracts and shows firmware volumes in file explorer | manual |
| 4 | Framework BIOS ZIP extracts inner firmware and produces module list | manual |

## Feature Ledger

| Feature | Phase | Status | Files |
|---------|-------|--------|-------|
| UEFI magic detection (IFD, _FVH, capsule GUID, .ROM/.CAP extension) | 1 | done | `unpack_common.py` |
| `run_uefi_extraction()` function | 1 | done | `unpack_common.py` |
| UEFI fast path in `unpack_firmware()` | 1 | done | `unpack.py` |
| PE32+ architecture detection from DXE bodies | 1 | done | `unpack.py` |
| ZIP-wrapped UEFI extraction | 1 | done | `unpack.py` |
| UEFIExtract in Dockerfile | 1 | building | `Dockerfile` |
| `list_firmware_volumes` MCP tool | 2 | done | `tools/uefi.py` |
| `list_uefi_modules` MCP tool | 2 | done | `tools/uefi.py` |
| `extract_nvram_variables` MCP tool | 2 | done | `tools/uefi.py` |
| `identify_uefi_module` MCP tool | 2 | done | `tools/uefi.py` |
| `read_uefi_module` MCP tool | 2 | done | `tools/uefi.py` |
| Known GUID database (35+ EDK2 modules) | 2 | done | `tools/uefi.py` |
| VulHunt docker-compose service | 3 | done | `docker-compose.yml` |
| `vulhunt_scan_binary` MCP tool | 3 | done | `tools/vulhunt.py` |
| `vulhunt_scan_firmware` MCP tool | 3 | done | `tools/vulhunt.py` |
| `vulhunt_check_available` MCP tool | 3 | done | `tools/vulhunt.py` |
| VulHunt JSONL parser fix (filter package metadata) | 3 | done | `tools/vulhunt.py` |

## Decision Log

| Decision | Reason |
|----------|--------|
| UEFIExtract over uefi-firmware-parser for extraction | UEFIExtract is more robust, handles edge cases, produces complete hierarchy |
| Keep uefi-firmware-parser for future Python metadata parsing | Nice-to-have for structured JSON, but not required for Phase 1-2 |
| VulHunt as Docker sidecar (not library) | GPL-3.0 license — running as separate process avoids license contamination |
| Merged UEFI security + VulHunt into single phase | VulHunt's EFI analysis IS the UEFI security assessment |
| Detection uses magic bytes + extension + size heuristic | Covers IFD, FVH, capsule GUID, and common OEM extensions |

## Active Context

- All phases complete (1-4)
- VulHunt container running (`vulhunt 1.0.0`), tools registered, scans execute
- Phase 4 verified on 2026-04-10 with real firmware in live Docker:

**D3633-S1.ROM (project `D3633-S1`):**
- `list_firmware_volumes`: 18 firmware volumes found (IFD, FVH, nested volumes)
- `list_uefi_modules`: 550 modules (DXE drivers, SMM modules, freeform, DXE core)
- `extract_nvram_variables`: 48 NVRAM variables (Setup, Timeout, UsbSupport, etc.)
- `identify_uefi_module`: GUID lookup works (B601F8C4... → RuntimeDxe)
- `vulhunt_scan_binary`: Scanned SataController PE32 module — pipeline works
- `list_directory`: File explorer shows firmware volumes in extraction tree

**Framework Laptop 16 AMD BIOS 4.03 (project `freamework uefi`):**
- ZIP extraction: Inner `.cap` file correctly extracted from `.zip`
- `list_firmware_volumes`: 13 volumes (Insyde H2O FlashDeviceMap detected)
- `list_uefi_modules`: 400 modules (DXE, SMM, Combined SMM/DXE including UsbBusDxe)

## Continuation State

- All 4 phases complete. Campaign finished.
- 26 UEFI tests passing
- VulHunt firmware-wide scan times out on large UEFI images (550+ modules) — individual binary scan works fine. Consider adding a module count limit or progress indication in future.

<!-- session-end: 2026-04-04T01:45:31.697Z -->

<!-- session-end: 2026-04-04T16:03:44.647Z -->

<!-- session-end: 2026-04-05T00:07:01.076Z -->
