---
title: "Frontend: Code Splitting + List Virtualization"
status: pending
priority: high
target: frontend/src/
---

> **Status note 2026-04-21 (Rule-19 audit — partial ship):** V1 code-splitting is
> shipped; V2 virtualization is partial (~50%). Do not close this intake yet.
>
> Shipped:
> - **V1** route-level code-splitting — commit `914d139`
>   (`feat(frontend): PageLoader + lazy route imports in App.tsx`). 15 `React.lazy()`
>   imports live at `frontend/src/App.tsx` (verified via `grep -c`).
> - **V2 partial** react-window virtualization in SbomPage — commit `bf60b53`. Three
>   files import `react-window`:
>   - `frontend/src/pages/SbomPage.tsx` (vulnerability list)
>   - `frontend/src/components/sbom/VulnerabilityRowVirtual.tsx`
>   - `frontend/src/components/findings/FindingsList.tsx` (virtualized list used
>     internally by the Findings page)
>
> Remaining gap (candidate for stream β 2026-04-21 or a follow-up campaign):
> - APK scan results, other large lists in SecurityScanPage (still use `.slice(0, 200)`
>   per the original intake problem statement).
> - Confirm FindingsPage.tsx actually renders `FindingsList` virtualized (it does
>   import the virtualized component — verify end-to-end behaviour under a 10k-finding
>   fixture).
>
> Retain `status: pending` until the SecurityScanPage virtualization sweep lands.
> Companion stream (β) on 2026-04-21 may close the remaining gap this session.

## Problem

### V1. No code-splitting

`frontend/src/App.tsx:5-18` statically imports all 14 pages. `grep -rn 'React\.lazy\|import(' frontend/src` returns zero hits.

Heavy dependencies ship in the initial bundle regardless of route:
- Monaco Editor (large)
- xterm.js
- ReactFlow (used in ComponentMapPage)
- Recharts (used in ComparisonPage — 992+ lines)

A user landing on `/projects` downloads Monaco Editor to look at a list of projects.

### V2. No list virtualization

Large lists render all rows:
- `SbomPage.tsx` — 1133 lines, renders up to 50K vulnerability rows
- Findings lists
- APK scan results (when many findings per APK)

The only current truncation is `.slice(0, 200)` in `SecurityScanPage.tsx:459` and similar — which limits UX, doesn't virtualize.

## Approach

### V1 — Route-level code splitting

Step 1. Convert page imports to `React.lazy`:

```typescript
// Before (App.tsx:5-18)
import ProjectsPage from '@/pages/ProjectsPage'
import ProjectDetailPage from '@/pages/ProjectDetailPage'
// ...

// After
import { lazy, Suspense } from 'react'
const ProjectsPage = lazy(() => import('@/pages/ProjectsPage'))
const ProjectDetailPage = lazy(() => import('@/pages/ProjectDetailPage'))
// ...
```

Step 2. Wrap `<Routes>` in `<Suspense>`:

```typescript
<ErrorBoundary>
  <Suspense fallback={<PageLoader />}>
    <Routes>
      <Route path="/projects" element={<ProjectsPage />} />
      {/* ... */}
    </Routes>
  </Suspense>
</ErrorBoundary>
```

Create `PageLoader`:
```typescript
// frontend/src/components/PageLoader.tsx
export function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64">
      <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
    </div>
  )
}
```

Step 3. Split heavy component imports.

Monaco is used in `ExplorePage` (file viewer). Already heavy inside — wrap it in `lazy` within ExplorePage:

```typescript
const MonacoEditor = lazy(() => import('@monaco-editor/react'))

// In render:
<Suspense fallback={<div>Loading editor...</div>}>
  <MonacoEditor ... />
</Suspense>
```

Same pattern for xterm.js (EmulationPage, FuzzingPage terminals) and ReactFlow (ComponentMapPage).

Step 4. Measure.

Add bundle analysis:
```bash
cd frontend && npx vite-bundle-visualizer
```

Target: initial JS bundle under 500 KB gzipped. Current state likely >2 MB.

### V2 — Virtualize large lists with react-window

Add dependency:
```bash
cd frontend && npm install react-window @types/react-window
```

Replace large list rendering in:

**SbomPage.tsx — vulnerability list:**

```typescript
import { FixedSizeList as List } from 'react-window'

<List
  height={600}
  itemCount={vulnerabilities.length}
  itemSize={72}
  width="100%"
>
  {({ index, style }) => (
    <div style={style}>
      <VulnerabilityRow vuln={vulnerabilities[index]} />
    </div>
  )}
</List>
```

**FindingsPage.tsx / FindingsList — findings list** — same pattern.

**APK Scan results** — `SecurityScanResults.tsx` finding rows (nested groups make this harder; consider `VariableSizeList`).

### V3 — Tree virtualization (file explorer)

`ExplorePage` uses `react-arborist` (already virtualized for the tree). Verify it's actually virtualizing on a firmware with 10K+ files. Check `frontend/src/components/explorer/FileTree.tsx`.

## Files

### V1
- `frontend/src/App.tsx` (lazy all pages, Suspense wrapper)
- `frontend/src/components/PageLoader.tsx` (new)
- `frontend/src/pages/ExplorePage.tsx` (lazy Monaco)
- `frontend/src/pages/EmulationPage.tsx`, `FuzzingPage.tsx` (lazy xterm)
- `frontend/src/pages/ComponentMapPage.tsx` (lazy ReactFlow)

### V2
- `frontend/package.json` (react-window dep)
- `frontend/src/pages/SbomPage.tsx`
- `frontend/src/pages/FindingsPage.tsx` (and/or FindingsList component)
- `frontend/src/components/apk-scan/SecurityScanResults.tsx` (more complex, may defer)

## Acceptance Criteria

### V1
- [ ] `npx vite-bundle-visualizer` shows route-level chunks
- [ ] Initial bundle (landing on `/`) under 500 KB gzipped
- [ ] Monaco only loads when ExplorePage is first visited (verify in Network tab — `monaco-*.js` appears only then)
- [ ] No regression in existing E2E tests

### V2
- [ ] SbomPage with 10K vulnerabilities renders in under 1 second, scrolls at 60fps
- [ ] Findings list with 5K entries renders similarly
- [ ] react-window is only loaded on pages that use it (check bundle split)

## Risks

- Lazy imports break SSR if added later — document that this codebase is CSR-only
- `React.lazy` requires `Suspense` — forgetting it causes a runtime error visible in ErrorBoundary
- `react-window` requires fixed row heights; variable-height rows need `VariableSizeList` and measurement
- Monaco's lazy load may cause a flicker — acceptable, document it

## References

- Frontend review H11 (no code-splitting), H12 (no virtualization)
