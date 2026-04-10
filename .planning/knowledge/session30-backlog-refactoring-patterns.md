# Patterns: S30 Backlog Refactoring Sprint

> Extracted: 2026-04-10
> Session: S30 — R1/R2/R3/R8/R9 backlog items
> Postmortem: none (direct sprint, no campaign)

## Successful Patterns

### 1. Parallel Agent Splits for Independent Refactoring
- **Description:** Launched 3 agents simultaneously (one per file split: emulation_service.py, FileViewer.tsx, ProjectDetailPage.tsx). Each agent had full context about the file structure, import dependencies, and conventions. All succeeded without merge conflicts.
- **Evidence:** All 3 agents completed independently in ~3 minutes. No overlapping file modifications.
- **Applies when:** Splitting N independent files — if they don't share imports or edit the same files, parallelize.

### 2. Backward-Compatible Python Module Extraction
- **Description:** When extracting `emulation_constants.py` and `emulation_preset_service.py` from `emulation_service.py`, preserved all existing import paths. Re-exported `_validate_kernel_file` from the original module so `kernel_service.py` doesn't break. Used delegation (not inheritance) for preset methods — EmulationService wraps EmulationPresetService calls.
- **Evidence:** Zero import changes needed in any caller file. All 364 tests passed.
- **Applies when:** Extracting code from a module with many external importers — re-export symbols from the original location.

### 3. get_db Auto-Commit Awareness for flush/commit Decision
- **Description:** Discovered `get_db()` (FastAPI dependency) auto-commits via `yield session; await session.commit()`. This means: (a) routers never need explicit `commit()` — it's redundant, (b) services must use `flush()` since they're shared between MCP (own commit) and REST (get_db commits), (c) only background tasks with `async_session_factory()` legitimately need `commit()`.
- **Evidence:** Audited all routers and services. Found 20 incorrect commit() calls. After fixing, all tests pass and API smoke tests succeed.
- **Applies when:** Any new router or service code — always use `flush()` unless you own your own session.

### 4. Verify Background Task Sessions Before Bulk-Replacing
- **Description:** Before blindly replacing all `commit()` → `flush()`, checked each file for `async_session_factory()` usage. Found 3 legitimate commit() calls in firmware.py background tasks and 1 in device_service.py — these create their own sessions with no auto-commit, so `commit()` is correct there.
- **Evidence:** firmware.py lines 202/250/297 use `async with async_session_factory() as db:` — their own transaction. device_service.py line 326 same pattern.
- **Applies when:** Any batch refactoring of DB transaction code — always check the session source before changing.

### 5. React Component Split by Natural Boundaries
- **Description:** FileViewer.tsx had 7 internal `function` components separated by comment headers. Each became its own file. ProjectDetailPage had 2 clear extraction targets (firmware card and action buttons). Splitting along these existing boundaries produced clean, focused files with minimal cross-imports.
- **Evidence:** FileViewer 869→219 lines (6 sub-components), ProjectDetailPage 710→330 lines (2 sub-components). TypeScript clean first try.
- **Applies when:** Splitting React files — look for existing `function` components within the file, not arbitrary line cuts.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Services always flush(), never commit() | Services are shared between MCP (dispatch owns commit) and REST (get_db owns commit). Service-level commit breaks MCP rollback. | Correct — 20 fixes, all tests pass |
| Router commit() → flush() too | get_db auto-commits; mid-request commit() breaks atomicity (partial commits on later errors) | Correct — cleaner transaction model |
| R8 (error handling): no changes | Bare except blocks only exist in SSE/background tasks — intentional fire-and-forget with logging | Correct — these aren't bugs |
| ClamAV behind Docker Compose profile | clamav/clamav:latest has no ARM64 image, blocks builds on RPi | Unblocked ARM64 development |
| Delegation over inheritance for preset extraction | EmulationService delegates to EmulationPresetService rather than inheriting — simpler, no mixin complexity | Clean separation, identical public API |
