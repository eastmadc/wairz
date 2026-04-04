---
Status: active
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
| 3 | build | VulHunt Docker sidecar + UEFI security assessment | pending |
| 4 | verify | Test with real UEFI firmware (D3633-S1.ROM, Framework BIOS) | pending |

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
| VulHunt docker-compose service | 3 | pending | `docker-compose.yml` |
| `vulhunt_scan_binary` MCP tool | 3 | pending | `tools/vulhunt.py` |
| `vulhunt_scan_firmware` MCP tool | 3 | pending | `tools/vulhunt.py` |

## Decision Log

| Decision | Reason |
|----------|--------|
| UEFIExtract over uefi-firmware-parser for extraction | UEFIExtract is more robust, handles edge cases, produces complete hierarchy |
| Keep uefi-firmware-parser for future Python metadata parsing | Nice-to-have for structured JSON, but not required for Phase 1-2 |
| VulHunt as Docker sidecar (not library) | GPL-3.0 license — running as separate process avoids license contamination |
| Merged UEFI security + VulHunt into single phase | VulHunt's EFI analysis IS the UEFI security assessment |
| Detection uses magic bytes + extension + size heuristic | Covers IFD, FVH, capsule GUID, and common OEM extensions |

## Active Context

- Phase 1 code complete, Docker build running (UEFIExtract compiling on ARM64)
- Phase 2 code complete (5 MCP tools, GUID database)
- Phase 3 not started (VulHunt integration)

## Continuation State

- Docker build in progress (background task bdhod7kc5)
- All Python code syntax-verified
- Need to rebuild + deploy to test with real UEFI firmware
- checkpoint-phase-1: none (clean working tree at campaign start)
