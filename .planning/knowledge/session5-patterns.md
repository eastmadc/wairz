# Patterns: Session 5 — YARA, Multi-Firmware, Comparison, Security Page

> Extracted: 2026-04-03 (updated end-of-session)
> Source: session 5 commits (8089103, 6280ff1, fd39ef5, 870f9d3, 77fafcb)
> Postmortem: none

## Successful Patterns

### 1. Backend-ready dependency injection for firmware_id
- **Description:** The `resolve_firmware()` dependency in `deps.py` already accepted an optional `firmware_id` query parameter, so adding multi-firmware support to SBOM/Explorer pages was a frontend-only change (no backend modifications needed).
- **Evidence:** SBOM page firmware selector wired in one commit without touching any backend routers.
- **Applies when:** Adding per-resource selection to existing endpoints — always check if the backend already supports the parameter before planning backend changes.

### 2. Per-category truncation for comparison diffs
- **Description:** Changed comparison from a global 500-entry limit (which starved removed/modified when added > 500) to per-category limits (500 per category). Simple fix with high impact.
- **Evidence:** User reported comparison showing only "Added" with 0 removed/modified despite real changes existing. Fix exposed 88 removed + 500 modified entries.
- **Applies when:** Any endpoint that returns categorized results with a truncation limit — always truncate per-category, not globally.

### 3. YARA rule files as external .yar files (not embedded strings)
- **Description:** Stored YARA rules in separate `.yar` files under `app/yara_rules/` rather than embedding as Python strings. Easier to maintain, validate, and extend. Users can add custom rules by dropping files in the directory.
- **Evidence:** Initial attempt with complex rules had syntax errors (unreferenced strings, invalid regex) — separate files made them easy to debug individually.
- **Applies when:** Adding any rule-based scanning — keep rules in their native format, not embedded in Python.

### 4. Thread executor for CPU-bound scanning
- **Description:** YARA scanning and security audit use `loop.run_in_executor(None, scan_function, ...)` to avoid blocking the async event loop during CPU-bound filesystem walks.
- **Evidence:** Follows the established pattern from comparison_service and security_audit_service. YARA scans 1,287 files without blocking API responsiveness.
- **Applies when:** Any filesystem-walking or CPU-bound analysis — always run in thread executor.

### 5. Progress callback pattern for long-running background tasks
- **Description:** Added an optional `progress_callback` async function parameter to `unpack_firmware()`. The background task wrapper provides a callback that writes to the DB. The frontend polls every 2s and displays the progress bar.
- **Evidence:** Progress stages report at classification (5%), format detection (10%), extraction (15-90%), completion (100%). Clean separation — the unpack function doesn't know about the DB.
- **Applies when:** Any background task >10s where users need visibility. Pass a callback, don't couple the worker to the DB.

### 6. Text diff as a separate endpoint (not inline in filesystem diff)
- **Description:** Added `/compare/text` as a separate endpoint rather than embedding diffs inline in the filesystem comparison response. This keeps the filesystem diff fast (no reading file contents) and lets the frontend fetch diffs on demand (click to view).
- **Evidence:** Filesystem diff with 15K files takes ~3s. Adding inline diffs for 500 modified files would make it 30s+. On-demand text diff is instant per file.
- **Applies when:** Any comparison feature with potentially large result sets — return summaries first, details on demand.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| External .yar rule files instead of embedded Python strings | Easier to validate, debug, extend; users can add custom rules | Caught 5 syntax errors during compilation that would have been harder to find embedded |
| Scan all firmware versions in security audit (not just first) | User reported 500 error with `scalar_one_or_none()` on multi-firmware project | Fixed crash, now scans all versions and aggregates findings |
| Firmware version selector in Zustand store (not URL params) | Simpler than query params, persists across page navigations within a project | Works well — auto-selects latest firmware, resets on project change |
| yara-python 4.x StringMatch API (not legacy tuples) | yara-python 4.5+ uses `StringMatch.instances` instead of `(offset, id, data)` tuples | Had to fix evidence builder after discovering API change in tests |
| Single SecurityScanPage with tabs (not separate pages) | Audit and YARA are closely related — one page with tabs is cleaner than two sidebar entries | Clean UX, both scan types share the findings display |
| Raise comparison limit to 2000/category backend, 500/page frontend | User reported limited visibility with 500 global cap | Full visibility for most firmware comparisons |

## Additional Patterns (end-of-session)

### 7. Graceful degradation for MCP server startup
- **Description:** Instead of calling `sys.exit(1)` when no firmware exists, the MCP server now starts normally and returns descriptive errors at the tool-call level. Project management tools (switch_project, list_projects) work without firmware.
- **Evidence:** GH #21 reported MCP crash as indistinguishable from network errors. Fix lets users connect MCP to empty projects and get helpful guidance.
- **Applies when:** Any server/service that can operate in a degraded mode — always prefer startup with degraded capabilities over fatal exit.

### 8. Issue triage before building
- **Description:** Before building new features, triaged all open GitHub issues. Found 6 of 7 were already fixed in prior sessions. Saved time that would have been spent investigating already-resolved problems.
- **Evidence:** Issues #2, #7, #10, #13, #14, #15 all already fixed. Only #21 needed work.
- **Applies when:** Start of any session — triage open issues first to avoid duplicate work and to close resolved issues.

### 9. On-demand detail loading for comparison
- **Description:** Text diff is a separate endpoint (`/compare/text`) loaded on click, not embedded in the filesystem diff response. Binary diff similarly loaded on click. This keeps the main comparison fast.
- **Evidence:** Filesystem diff with 15K+ files takes ~3s. Adding inline text diffs would make it 30s+. On-demand loading is instant per file.
- **Applies when:** Any feature where detail data is expensive and only needed for a subset of results.

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| MCP graceful degradation (no sys.exit on missing firmware) | GH #21 — crash indistinguishable from network errors | Users can connect to empty projects and get guidance |
| Combined SecurityScanPage with tabs | Audit and YARA are related security tools | Clean sidebar, shared findings display |
| Reusable FirmwareSelector component | Multiple pages need firmware version selection | Used in SbomPage, ExplorePage, SecurityScanPage |
