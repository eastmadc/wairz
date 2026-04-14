# Patterns: Firmware ID Passthrough Fix (Session 37)

> Extracted: 2026-04-14
> Campaign: none (in-session bugfix)
> Postmortem: none

## Successful Patterns

### 1. Systematic firmware_id audit across all API callers
- **Description:** When a firmware-scoped bug is found in one API call, audit ALL frontend API functions and their callers for the same missing `firmware_id` parameter. The file explorer search was the reported bug, but the same issue existed in `getFileDownloadUrl`, `getFileInfo`, and `UefiModules`.
- **Evidence:** Found 4 additional missing `firmware_id` callers after fixing the initial search bug (FileViewer download, getFileInfo in explorerStore, UefiModules list + download)
- **Applies when:** Any bug where a query parameter (especially `firmware_id`) is missing from one API call — always audit sibling calls in the same API module

### 2. Backend dependency chain already handles firmware_id
- **Description:** The backend `resolve_firmware` dependency in `deps.py` already accepts `firmware_id` as a Query param and falls through to "first firmware" when None. No backend changes were needed — the fix was entirely in the frontend passing the parameter.
- **Evidence:** `curl` tests confirmed the `/search` endpoint correctly filters by `firmware_id` when provided
- **Applies when:** Diagnosing firmware-scope bugs — check whether the backend already supports the parameter before modifying backend code

### 3. Test with curl before and after
- **Description:** Used direct `curl` calls against both firmware IDs to confirm: (a) the default behavior returns wrong-firmware results, (b) explicit `firmware_id` returns correct results. This proved the backend was fine and the fix was frontend-only.
- **Evidence:** `curl` with `firmware_id=188c5b24...` (DPCS10_260413-1709) returned 0 results for "Factory", confirming correct filtering
- **Applies when:** Any firmware-scoped bug — test the raw API first to isolate frontend vs backend

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Fix frontend only, no backend changes | `resolve_firmware` dependency already accepts `firmware_id` query param | Correct — 2-file fix (files.ts + FileTree.tsx) for initial bug |
| Audit all API functions in files.ts | Same pattern likely repeated | Found 3 more missing `firmware_id` params |
| Use `useProjectStore.getState()` in callbacks | Consistent with existing pattern in explorerStore.ts | Clean, no new patterns introduced |
