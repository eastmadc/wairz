# Stream Beta Wave 3 — Research (Rule #19)

**Intake:** `.planning/intake/frontend-store-isolation-and-types.md`
**Branch:** `feat/stream-beta-2026-04-19`
**Baseline HEAD:** `c954039` on `clean-history`
**Baseline `npx tsc -b --force`:** 0 errors.
**Rule-17 canary (isolated worktree at `.worktrees/stream-beta`):** PASSED (exit=2 on `const x: number = "nope"`).
**Rule #23 active incident during execution:** While editing in the shared `/home/dustin/code/wairz` checkout, the harness twice switched on-disk HEAD to `feat/stream-alpha-2026-04-19` and `feat/stream-gamma-2026-04-19`, wiping my in-memory explorerStore/projectStore/vulnerabilityStore edits back to baseline (confirmed via post-stomp grep). Mitigation: `git worktree add .worktrees/stream-beta feat/stream-beta-2026-04-19` with `frontend/node_modules` symlinked from the main checkout. All three sub-task commits landed from the isolated worktree. Evidence: `git worktree list` shows two entries post-fix; `git log --oneline feat/stream-beta-2026-04-19 ^clean-history` shows a clean 3-commit sequence (S1/S2/S3).

## S1 — Store reset race on project switch

### Existing store shapes (actual, not intake claims)

```
explorerStore.ts
  loadRootDirectory(projectId)              // 1 arg — reads fwId from projectStore
  loadDirectory(projectId, path)            // 2 args
  selectFile(projectId, node)               // 2 args — already had selectedPath guard
  navigateToPath(projectId, targetPath)
  loadDocuments(projectId)                  // 1 arg
  selectDocument(projectId, document)       // 2 args — already had selectedDocumentId guard
  saveDocument(projectId)                   // 1 arg
  createNote(projectId, title)              // 2 args
  reset()                                   // nullary

projectStore.ts
  fetchProject(id)
  clearCurrentProject()                     // clears currentProject + selectedFirmwareId
  setSelectedFirmware(firmwareId)

vulnerabilityStore.ts
  loadVulnerabilities(projectId, firmwareId?)
  loadMore(projectId, firmwareId?)
  resolve(projectId, vulnId, status, justification?)
  bulkResolve(projectId, ids, status, justification?)
  reset()
```

### Intake deviations

- Intake proposes `loadRootDirectory(projectId, firmwareId)` (2 args). Actual: 1 arg. Widening would break 12+ call sites. Rejected; kept 1-arg signatures.
- Intake uses `resetExplorer()`. Actual: `reset()` (pages alias as `resetExplorer = s.reset`).
- Intake implied `loadDirectory` already had in-flight guards — it did NOT. Only `selectFile`/`selectDocument` had commit-sentinels (`selectedPath`, `selectedDocumentId`). Tree-level loads had zero guards.

### Design applied

Added `currentProjectId: string | null` to each store's state. Each async action captures its `projectId` at entry, `set({ currentProjectId: projectId, ... })` synchronously, then checks `get().currentProjectId === projectId` after every `await` before committing. No public-signature changes.

## S2 — ProjectRouteGuard

### Truth

All 11 per-project routes use `/projects/:projectId/*` — confirmed in App.tsx:39–50 baseline. ProjectsPage (the list at `/projects`) intentionally NOT wrapped — no `:projectId` and needs persistent project list.

### Reset targets on route change

`explorerStore.reset()` + `vulnerabilityStore.reset()` + `projectStore.clearCurrentProject()`.

## S3 — DeviceAcquisitionPage `as any` removal (end-to-end)

### Critical Rule #19 finding

Backend Pydantic schemas SILENTLY STRIP the BROM fields. Verified in `wairz-backend-1`:

```python
>>> DeviceInfo(**{'serial':'X','mode':'brom','available':True,'error':None,'chipset':'MT6765'}).model_dump()
{'serial': 'X', 'model': None, 'device': None, 'transport_id': None, 'state': 'device'}
```

Pydantic v2 default `extra="ignore"` drops unknown keys at `DeviceInfo(**d)` (router line 51). Frontend's `(dev as any).mode` therefore evaluated to `undefined` at runtime — BROM UI path was dead code at the serialization boundary, not merely type-unsafe. Typing the frontend alone would leave the feature broken.

### Scope decision

Extended S3 to end-to-end: widened backend `DeviceInfo` (`mode`, `available`, `error`) + `DeviceDetailResponse` (`chipset`), propagated `chipset` from bridge through service (`device_service.py:76-82`, previously dropped) through router (`routers/device.py:69-74`). Then mirrored types in frontend `types/device.ts` and removed 5 `as any` casts in `DeviceAcquisitionPage.tsx`.

**DeviceMode union = `'adb' | 'brom' | 'preloader'`** — exactly what the bridge emits at `scripts/wairz-device-bridge.py:139,221,250-252,282,298,326,384`. Intake's proposed `'edl' | 'fastboot' | 'unknown'` would be Rule-19 fabrication; rejected.

### Rejected additions

Intake proposed `soc`, `bootloader_version`, `security_patch`, `partitions: PartitionInfo[]` on `DeviceDetail`. These are NOT top-level bridge fields — they arrive via `getprop` dict keys (`ro.boot.*`, `ro.build.version.security_patch`). Adding them as top-level fields would have been fabrication. Existing `getprop: Record<string, string>` surface is the correct path.

### Verified via Pydantic round-trip in wairz-backend-1

```
adb: {'serial': 'A', ..., 'mode': 'adb', 'available': None, 'error': None}
brom: {'serial': 'MTK_BROM_0', ..., 'mode': 'brom', 'available': True, 'error': None}
detail with chipset: {..., 'chipset': 'MT6765'}
```

All four previously-dropped fields now preserved through the schema.

## Nothing already solved

- S1: `grep currentProjectId frontend/src/stores/*.ts` = 0 matches at baseline (not solved).
- S2: `frontend/src/components/ProjectRouteGuard.tsx` did not exist (not solved).
- S3: `grep 'as any' frontend/src/pages/DeviceAcquisitionPage.tsx` = 5 hits at baseline (not solved).

All three were genuine live work.

## Open threads for future streams

- Discriminated unions per acquisition mode once bridge supports more than `adb`/`brom`/`preloader`. Not today — don't invent.
- Backend `list_devices` router currently flattens to a single `DeviceInfo`; once BROM-specific fields proliferate, consider a `BromDeviceInfo | AdbDeviceInfo` union with a literal-typed `mode` discriminator.
- Rule #23 mitigation strategy proven: isolated `git worktree add` under the PROJECT_ROOT works, survived two cross-stream HEAD-switch stomps from Alpha/Gamma streams in the shared checkout.
