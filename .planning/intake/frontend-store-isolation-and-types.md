---
title: "Frontend: Store Isolation, Project-ID Guards, Device Types"
status: pending
priority: high
target: frontend/src/stores/, frontend/src/pages/, frontend/src/types/
---

## Problem

Three related frontend correctness issues.

### S1. Store reset race on project switch

`ExplorePage.tsx:35-38` calls `resetExplorer()` in effect cleanup. But:
- Direct navigation `/projects/A/explore` → `/projects/B/explore` **doesn't unmount** the `ExplorePage`'s parent; only the page props change
- Even when cleanup runs, the previous project's `loadRootDirectory` may still be in flight
- `explorerStore.loadRootDirectory:114-147` doesn't check whether project has changed — it uses `useProjectStore.getState().selectedFirmwareId` but accepts any result

Scenario: user switches projects via URL. Old project's in-flight `listDirectory` completes after new project's `setSelectedFirmwareId` fires. Old tree data lands in the new project's store.

### S2. No project-id consistency guard

`projectStore.selectedFirmwareId` is a single global value. When `ProjectDetailPage` unmounts and clears it, the clear only happens on unmount — which never happens on URL-only navigation.

### S3. `as any` casts in DeviceAcquisitionPage

Five load-bearing `as any` casts bypass TypeScript on critical branches:

```typescript
// DeviceAcquisitionPage.tsx:377-380
(dev as any).mode
(dev as any).available
(dev as any).error

// DeviceAcquisitionPage.tsx:481, 484
(deviceDetail as any).chipset
```

These are MediaTek BROM-specific fields that exist at runtime but aren't in `frontend/src/types/device.ts`. Any backend rename or removal causes silent UI degradation with zero compile-time signal.

## Approach

### Fix S1 + S2 — Project-ID guard across stores

**Step 1 — Add projectId as an explicit parameter to store actions.**

```typescript
// explorerStore.ts
interface ExplorerState {
  // ...existing...
  currentProjectId: string | null  // track which project the store is hydrated for
}

loadRootDirectory: async (projectId: string, firmwareId: string) => {
  // Bail if project switched while we were loading
  if (get().currentProjectId !== null && get().currentProjectId !== projectId) {
    return
  }
  set({ currentProjectId: projectId, treeLoading: true })
  try {
    const nodes = await listRootDirectory(projectId, firmwareId)
    // Commit only if still the current project
    if (get().currentProjectId === projectId) {
      set({ tree: nodes, treeLoading: false })
    }
  } catch (e) {
    if (get().currentProjectId === projectId) {
      set({ treeError: String(e), treeLoading: false })
    }
  }
}
```

Apply the same "check before commit" pattern to `loadDirectory`, `selectFile`, `loadDocuments`, `selectDocument`, `saveDocument`, `createNote`.

**Step 2 — Reset store on project change.**

In `App.tsx` or a top-level ProjectRoute wrapper:

```typescript
// Watches :projectId and resets stores when it changes
function ProjectRouteGuard({ children }: { children: ReactNode }) {
  const { projectId } = useParams<{ projectId: string }>()
  const resetExplorer = useExplorerStore((s) => s.resetExplorer)
  const resetVulnerabilities = useVulnerabilityStore((s) => s.reset)
  const clearCurrent = useProjectStore((s) => s.clearCurrentProject)

  useEffect(() => {
    return () => {
      resetExplorer()
      resetVulnerabilities()
      clearCurrent()
    }
  }, [projectId, resetExplorer, resetVulnerabilities, clearCurrent])
  
  return <>{children}</>
}
```

Wrap all `/projects/:projectId/*` routes with this guard.

### Fix S3 — Type DeviceInfo properly

Update `frontend/src/types/device.ts`:

```typescript
export type DeviceMode = 'adb' | 'brom' | 'edl' | 'fastboot' | 'unknown'

export interface DeviceInfo {
  device_id: string
  manufacturer?: string
  model?: string
  mode: DeviceMode
  available: boolean
  error?: string
  // ...
}

export interface DeviceDetail extends DeviceInfo {
  chipset?: string        // MediaTek chipset (e.g., "mt6755")
  soc?: string
  bootloader_version?: string
  security_patch?: string
  partitions?: PartitionInfo[]
  // ...
}

export interface PartitionInfo {
  name: string
  size_mb: number
  readable: boolean
}
```

Verify backend field names match (`backend/app/services/device_service.py`). Add any missing fields.

Update `DeviceAcquisitionPage.tsx`:

```typescript
// Before
(dev as any).mode

// After
dev.mode  // TS-checked, refactor-safe
```

Remove all 5 `as any` casts.

## Files

### S1 + S2
- `frontend/src/stores/explorerStore.ts` (add currentProjectId + guards)
- `frontend/src/stores/projectStore.ts` (similar treatment)
- `frontend/src/stores/vulnerabilityStore.ts`
- `frontend/src/App.tsx` (wrap routes in ProjectRouteGuard)
- `frontend/src/components/ProjectRouteGuard.tsx` (new)

### S3
- `frontend/src/types/device.ts` (add DeviceInfo, DeviceDetail, mode/chipset fields)
- `frontend/src/pages/DeviceAcquisitionPage.tsx` (remove all 5 casts)
- Verify backend `device_service.py` response shape matches

## Acceptance Criteria

- [ ] Rapidly switching `/projects/A/explore` ↔ `/projects/B/explore` never shows A's tree in B (add E2E test)
- [ ] `grep -rn 'as any' frontend/src/pages/DeviceAcquisitionPage.tsx` returns zero hits
- [ ] `npx tsc --noEmit` passes without `@ts-ignore`
- [ ] Existing DeviceAcquisition tests pass (run frontend/src/pages/__tests__ if present, or manual Playwright)

## Risks

- Adding `currentProjectId` to every store touch point adds boilerplate — consider a small helper `withProjectGuard(projectId, fn)`
- Device types may differ per chipset (MediaTek vs Qualcomm vs Samsung) — use discriminated unions if so
- Backend device_service may actually return Record<string, any> (grep to confirm) — if so, also clean up the backend Pydantic schema

## References

- Frontend review C1, C3, C6, H7
