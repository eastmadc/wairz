# Anti-patterns: Firmware ID Passthrough Fix (Session 37)

> Extracted: 2026-04-14
> Campaign: none (in-session bugfix)

## Failed Patterns

### 1. Inconsistent firmware_id passing in the same store/module
- **What was done:** `explorerStore.ts` passes `fwId` in `loadRootDirectory`, `loadDirectory`, and `readFile` — but NOT in `getFileInfo` (called from `selectFile`). Same store, same function, inconsistent handling.
- **Failure mode:** Selecting a file while viewing firmware B would fetch file info from firmware A (the default), while the file content would correctly come from firmware B. Could cause wrong MIME type detection, wrong file size display, or binary/text misclassification.
- **Evidence:** `explorerStore.ts:205` — `getFileInfo(projectId, node.id)` missing fwId, while line 221 correctly uses `const fwId = useProjectStore.getState().selectedFirmwareId`
- **How to avoid:** When adding `firmware_id` support to any API function, grep for ALL callers of that function AND all sibling API calls in the same file. If `readFile` passes `fwId`, every other file-operation API call in the same flow must too.

### 2. API functions defaulting to no firmware_id
- **What was done:** `searchFiles()`, `getFileInfo()`, and `getFileDownloadUrl()` in `files.ts` were written without a `firmwareId` parameter, while `listDirectory()` and `readFile()` in the same file had it.
- **Failure mode:** Any caller of the firmware-unaware functions would silently query the default (first) firmware instead of the selected one. In multi-firmware projects, this returns wrong data.
- **Evidence:** `files.ts` — 3 of 5 file API functions were missing `firmwareId` param
- **How to avoid:** When the backend dependency chain includes `firmware_id` (via `resolve_firmware`), EVERY frontend API function that hits that router should accept and forward `firmwareId`. Check at API-layer creation time, not after a bug report.
