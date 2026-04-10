# Patterns: UEFI Firmware Support Campaign

> Extracted: 2026-04-04 (updated 2026-04-10 with Phase 4 verification patterns)
> Campaign: .planning/campaigns/uefi-firmware-support.md
> Postmortem: none

## Successful Patterns

### 1. Magic Byte Detection + Extension + Size Heuristic
- **Description:** UEFI detection combines three signals: magic bytes (IFD `5AA5F00F` at 0x10, `_FVH` in first 64KB, EFI capsule GUID at 0), file extension (.ROM/.CAP/.FD/.UPD), and size range (2-64MB). Any one signal is sufficient.
- **Evidence:** All 3 test firmware correctly classified. 26/26 tests passing.
- **Applies when:** Adding detection for new firmware formats. Multi-signal approach reduces false negatives without increasing false positives.

### 2. UEFIExtract CLI + Virtual File Tree
- **Description:** Instead of writing a custom UEFI parser, use UEFIExtract (mature C++ tool) as a subprocess and map its `.dump/` output directory into the existing file tree. The dump hierarchy becomes the browsable structure.
- **Evidence:** 7785-8347 components extracted per firmware. File explorer works unchanged.
- **Applies when:** Integrating new extraction tools. Using tool output directories as virtual filesystems avoids custom parsing.

### 3. PE32+ Header Parsing Without Dependencies
- **Description:** PE32+ DllCharacteristics and section headers are simple fixed-offset structs. Parse directly with `struct.unpack_from()` instead of adding `pefile` dependency. Only need ~30 lines for ASLR/DEP/W^X/arch detection.
- **Evidence:** All security checks work correctly. 26 tests verify correctness. Zero new pip dependencies.
- **Applies when:** Parsing well-documented binary formats where a full library would be overkill.

### 4. Parallel Agent Delegation for Independent Work
- **Description:** Used 3 parallel agents + 1 background Docker build simultaneously: MCP bridge, SSE wiring, UEFI tests, VulHunt pull. Each agent got full context injection and clear scope.
- **Evidence:** All 4 tasks completed successfully in one round. No conflicts or rework.
- **Applies when:** Work decomposes into 3+ tasks that don't touch the same files.

### 5. REST Endpoint Alongside MCP Tool
- **Description:** For UEFI modules, built both the MCP tool (for Claude) and the REST endpoint + UI (for web users) in the same phase. Shared the parsing logic via imported functions.
- **Evidence:** UEFI modules accessible from both MCP and web UI. No code duplication.
- **Applies when:** Adding any analysis capability. Always build both channels together.

### 6. Generic MCP-to-REST Bridge (Whitelist Approach)
- **Description:** Instead of manually creating REST endpoints for each MCP tool, built a single `/tools/run` endpoint that calls through to ToolRegistry.execute(). Whitelist of 80 safe read-only tools, blocking dangerous ones.
- **Evidence:** 80 tools instantly accessible via REST. Single endpoint, ~150 lines total.
- **Applies when:** Any platform with an internal tool registry that needs external API exposure.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| UEFIExtract over uefi-firmware-parser | More robust C++ parser, handles all UEFI variants, maintained by LongSoft | Correct — extracted 7K-8K components from real firmware |
| Build UEFIExtract from source in Dockerfile | No pre-built ARM64 binaries available | Required 2 fixes: lowercase binary name, cmake/qt6 libs must stay |
| VulHunt as Docker sidecar with `mcp` entrypoint | GPL-3.0 isolation + minimal image has no shell utilities | Works — container stays alive, but CE ships with empty rules |
| Generic bridge over per-tool REST endpoints | 82 tools to expose, manual approach too expensive | Correct — one endpoint exposes all analysis tools |
| PE32+ parsing without pefile library | DllCharacteristics is a 2-byte field at a known offset | Correct — simpler, no dependency, fully tested |
| Keep cmake/qt6-base-dev in Docker image | Purging removes shared libs that UEFIExtract dynamically links | Required — 3 failed attempts before discovering this |
| Rewrite docker exec to MCP HTTP client | Backend container has no `docker` CLI; VulHunt already runs MCP server | Correct — eliminated dependency, cleaner architecture |
| SSE progress via existing Redis pub/sub | EventService + events router already handle assessment, emulation, etc. | Correct — just added "vulhunt" event type, zero new infrastructure |
| Scan all binaries by default (no cap) | User expected full scan; capping at 50 was misleading | Correct — per-binary SSE progress makes long scans tolerable |

### 7. MCP HTTP Client Over Docker Exec
- **Description:** When a sidecar container already exposes an MCP server (Streamable HTTP), communicate via HTTP POST to `/mcp` with JSON-RPC. Don't assume the host container has `docker` CLI. Parse SSE `data:` lines from the response.
- **Evidence:** VulHunt `docker exec` failed with `No such file or directory` because backend container lacks docker CLI. HTTP client worked immediately via `httpx.AsyncClient`.
- **Applies when:** Integrating any containerized tool that runs an MCP or HTTP server. Always prefer network communication over `docker exec`.

### 8. Reuse Existing SSE Infrastructure for Progress
- **Description:** Instead of building custom progress tracking (WebSocket, polling), add a new event type to the existing Redis pub/sub EventService. Frontend subscribes via `EventSource` to the same `/events` endpoint.
- **Evidence:** Added `vulhunt` to `VALID_EVENT_TYPES`, called `event_service.publish_progress()` in the scan loop. ~20 lines backend, ~15 lines frontend.
- **Applies when:** Any long-running operation needs progress feedback. The SSE pattern is already proven for unpacking, emulation, fuzzing, and assessment.

### 9. Infer Context From File Paths
- **Description:** UEFIExtract's `.dump/` directory names contain module type info (e.g., "RaidDriverSmm", "HeciInit"). Parse path components to infer VulHunt's `--component-attribute kind=` parameter instead of hardcoding.
- **Evidence:** VulHunt requires `kind=SmmModule` for SMM drivers, `kind=DxeDriver` for DXE. The `_infer_uefi_kind()` function maps path patterns to correct kinds.
- **Applies when:** Tool output encodes metadata in directory/file names. Extract it instead of guessing.

### 10. Real Firmware Verification Catches Scale Issues
- **Description:** Unit tests use small synthetic inputs. Real UEFI firmware (D3633-S1.ROM: 550 modules, 18 volumes; Framework BIOS: 400 modules, 13 volumes) revealed that `vulhunt_scan_firmware` times out when scanning all modules sequentially via HTTP. Per-binary scan works fine.
- **Evidence:** Phase 4 verification — `vulhunt_scan_firmware` curl hit 5-minute timeout on 550 modules. `vulhunt_scan_binary` on individual PE32 modules returned in <5s. All other tools (volumes, modules, NVRAM, GUID lookup, file explorer) handled scale without issue.
- **Applies when:** Building any analysis tool that iterates over firmware contents. Always test with real firmware that has 100+ components to catch timeout/performance issues that synthetic tests miss.

### 11. ZIP-Wrapped Firmware Extraction Pipeline
- **Description:** Framework BIOS ships as a ZIP containing a `.cap` capsule file. The unpack pipeline correctly extracts the ZIP, identifies the inner `.cap` as UEFI firmware, and runs UEFIExtract on it — producing a fully browsable module tree.
- **Evidence:** Phase 4 — `freamework uefi` project: ZIP→CAP extraction produced 13 firmware volumes, 400 modules, Insyde H2O FlashDeviceMap correctly identified. No manual intervention needed.
- **Applies when:** Supporting vendor firmware distributions. Many OEMs wrap firmware in ZIP/7z/RAR. The recursive unpack + re-classify pattern handles this transparently.
