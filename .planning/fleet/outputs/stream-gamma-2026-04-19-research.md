# Stream Gamma — Research / Plan / Baseline

> Campaign: wairz-intake-sweep-2026-04-19, Wave 1 (frontend code-splitting + virtualization)
> Parent branch: clean-history
> Baseline HEAD (recorded before any change): branch-tip commit abe15e0

## Phase 1 — Deep Research

### Blocking environment issue (resolved)

First attempted build failed with `Unexpected end of file in JSON` from `../package.json`. Root-level `/home/dustin/code/wairz/package.json` was a 0-byte untracked file (not in `HEAD`, not in `git status` output even as `??`). Vite esbuild walked up to the repo root, tried to parse it as a package manifest, and aborted. Deleted — not tracked anywhere, and the monorepo has no root-level workspace to justify it. Build immediately succeeded.

### Baseline bundle

```
dist/index.html                               0.46 kB │ gzip:   0.30 kB
dist/assets/wairz_full_logo-CyG0Q4fC.png     97.77 kB
dist/assets/wairz_logo-CW4c_Knm.png         124.11 kB
dist/assets/index-DXnzeDIG.css              117.36 kB │ gzip:  19.84 kB
dist/assets/index-BXSNwBur.js             1,637.88 kB │ gzip: 455.52 kB   <-- SINGLE CHUNK
```

Total assets dir: 1.9 MB. JS chunk count: **1**. Vite emitted the canonical "Some chunks are larger than 500 kB" warning.

### Heavy-import audit

**Monaco Editor (`@monaco-editor/react`)** — used in 4 explorer wrapper components:
- `components/explorer/TextTabs.tsx`
- `components/explorer/DisassemblyPanel.tsx`
- `components/explorer/FileViewer.tsx`
- `components/explorer/DecompilationPanel.tsx`

Only reachable from ExplorePage → via FileViewer / BinaryTabs. Zero usages outside `components/explorer/`. Route-level lazy on ExplorePage alone is sufficient to exclude Monaco from the initial bundle.

**xterm (`@xterm/xterm`, `@xterm/addon-fit`)** — used in:
- `components/emulation/EmulationTerminal.tsx` (consumed by EmulationPage only)
- `components/explorer/TerminalPanel.tsx` (consumed by ExplorePage only)
- `hooks/useTerminalWebSocket.ts` (type-only import)

FuzzingPage does NOT import xterm (campaign intake claim is inaccurate). Intake says "lazy xterm in FuzzingPage" — there's nothing to lazy-load there. Noted below.

**ReactFlow (`@xyflow/react`)** — used in:
- `components/component-map/*` (ComponentMap, ComponentNode, MapControls) → ComponentMapPage
- `components/hardware-firmware/DriverGraph.tsx` → HardwareFirmwarePage

Two pages use ReactFlow. Route-level lazy on both pages is sufficient; no further wrapping required inside.

**Recharts** — NOT a dep of this project. `grep recharts` = 0 hits. `package.json` has no recharts. Intake mentions ComparisonPage using recharts — false. ComparisonPage is 48 KB of pure `diff`/text/JSX, not chart-heavy. No action needed.

**react-arborist** — used in `components/explorer/FileTree.tsx` only. Verified virtualization: `<Tree>` receives `height={treeHeight}` (dynamic, ResizeObserver-driven) — react-arborist virtualises when `height` is provided. Rule 17 / V3 acceptance is already satisfied; no code change needed in FileTree.

**html-to-image** — used only in `component-map/MapControls.tsx` (PNG/SVG export of the graph). Already confined to ComponentMapPage; lazy page-load will naturally split it.

### Current lazy / virtualization usage

```
grep -rn "React\.lazy\|\blazy("           → 0 hits
grep -rn "react-window\|Virtuoso\|FixedSizeList"  → 0 hits
```

Nothing split, nothing virtualized.

### Live-DB check for virtualization justification

Database rows at time of planning (via `docker compose exec postgres psql`):
- `sbom_vulnerabilities`: **364,857 rows** — a single project easily produces tens of thousands.
- `findings`: **1,273 rows** — individual project finding counts reach hundreds.

SbomPage renders `sortedVulns.map` into a `<tbody>` unbounded (there is a server-side `hasMore` + "Load More" button, but once loaded, every row is DOM-rendered). Same for FindingsList.

### Routes audit

`App.tsx` has **14 routes** with static imports. All are page-level candidates:
ProjectsPage, ProjectDetailPage, ExplorePage, FindingsPage, ComponentMapPage, SbomPage, HardwareFirmwarePage, EmulationPage, FuzzingPage, ComparisonPage, SecurityScanPage, SecurityToolsPage, DeviceAcquisitionPage, HelpPage, NotFoundPage (15 counting 404).

---

## Phase 2 — Plan

### Commit slices (staged, each with independent verify)

| # | Commit | Scope | Risk |
|---|--------|-------|------|
| 1 | PageLoader + lazy routes | `App.tsx` + new `components/PageLoader.tsx` | Low — Suspense fallback is the only runtime visible change |
| 2 | react-window install | `package.json` + `package-lock.json` via `npm install` | Trivial |
| 3 | Virtualize SbomPage vuln list | `pages/SbomPage.tsx` (bottom table body) | Medium — the existing table has row expansion + selection; must preserve both |
| 4 | Virtualize FindingsPage list | `components/findings/FindingsList.tsx` | Medium — preserve sort/selection interactions |

### Deviations from intake

1. **FuzzingPage xterm lazy-load skipped** — FuzzingPage doesn't import xterm. No-op per rule 19 (evidence-first).
2. **Recharts skipped** — not a dep.
3. **Monaco / ReactFlow / xterm page-level lazy merged into the App.tsx route-lazy commit.** Route-level `lazy(() => import('@/pages/X'))` naturally chunks the page and everything it transitively imports into a per-route bundle. Wrapping `@monaco-editor/react` in a *second* lazy inside ExplorePage would require a Suspense fallback around the editor mount — that's user-visible flicker on every file click for no additional bundle savings (the whole page chunk is already isolated from the initial bundle). Net: route-lazy gets us the intake's acceptance criteria (Monaco only loads when ExplorePage is first visited) without intra-page flicker. Same argument for xterm and ReactFlow. If bundle-size targets aren't hit by route-lazy alone, we revisit with intra-page lazy; measurement will decide.
4. **SbomPage virtualization approach** — the table has complex row state (expanded details, multi-select, justification dialog). Using `FixedSizeList` requires locking row height. The existing rows have expanded variants that grow. I'll virtualize only the collapsed-row case and render the expanded row's details out-of-list (or use a generous fixed height with overflow) — will confirm during implement.
5. **FileTree virtualization** — already virtualised. No-op.

### Target

- Initial chunk (the bundle served at `/projects`) < 500 KB gzipped.
- Chunk count > 5 after build.
- tsc clean (canary verified).

### Step order

1. Create `components/PageLoader.tsx` + edit `App.tsx` lazy wrapper.
2. `npx tsc --noEmit` → expect 0 errors. Run build. Confirm multiple chunks emitted.
3. `npm install react-window @types/react-window`.
4. Virtualize SbomPage bottom table.
5. `npx tsc --noEmit` → 0 errors. Build.
6. Virtualize FindingsList.
7. `npx tsc --noEmit` → 0 errors. Final build.
8. Rule-17 canary at the end.
9. Commit each slice separately.

---

## Phase 3/4 — Implement & Verify (outcomes)

### Final bundle — all slices applied

```
before:  dist/assets/index-BXSNwBur.js       1,637.88 kB  gzip: 455.52 kB   (single chunk)
after:   dist/assets/index-CD4DDHh6.js         364.23 kB  gzip: 118.88 kB   (initial route)
         dist/assets/xterm-CqYoTcoS.js         335.08 kB  gzip:  85.13 kB   (xterm — lazy)
         dist/assets/ExplorePage-*.js          201.58 kB  gzip:  53.81 kB   (incl. Monaco)
         dist/assets/style-*.js                179.45 kB  gzip:  58.47 kB   (radix + shared)
         dist/assets/SecurityScanPage-*.js      84.05 kB  gzip:  20.21 kB
         dist/assets/ComponentMapPage-*.js      76.45 kB  gzip:  27.03 kB   (incl. @xyflow/react)
         dist/assets/EmulationPage-*.js         61.37 kB  gzip:  13.87 kB
         dist/assets/HardwareFirmwarePage-*.js  48.57 kB  gzip:  12.74 kB   (shares ReactFlow)
         dist/assets/SbomPage-*.js              39.41 kB  gzip:  10.40 kB
         dist/assets/ProjectDetailPage-*.js     36.67 kB  gzip:   9.76 kB
         dist/assets/ComparisonPage-*.js        29.29 kB  gzip:   6.83 kB
         dist/assets/FindingsPage-*.js          19.71 kB  gzip:   6.63 kB
         dist/assets/FuzzingPage-*.js           19.63 kB  gzip:   5.63 kB
         dist/assets/DeviceAcquisitionPage-*.js 20.79 kB  gzip:   5.16 kB
         dist/assets/SecurityToolsPage-*.js     14.38 kB  gzip:   4.79 kB
         dist/assets/HelpPage-*.js              13.68 kB  gzip:   4.13 kB
         dist/assets/react-window-*.js           8.90 kB  gzip:   3.42 kB   (shared SbomPage+Findings)
         dist/assets/ProjectsPage-*.js           7.63 kB  gzip:   2.88 kB
         ... + 55 smaller shared chunks
```

**Chunk count: 1 → 73.**
**Initial JS delivered on `/projects`: 455 KB gzip → 119 KB gzip (74% reduction).**
**xterm (335 KB raw) no longer ships to users who don't open ExplorePage or EmulationPage.**
**ReactFlow bundled into ComponentMapPage / HardwareFirmwarePage chunks only.**
**Monaco bundled into ExplorePage chunk only.**

### Deviations actually applied

- `tsc --noEmit` canary failed — project uses composite `references` with `"files": []`, so plain `tsc --noEmit` compiles zero files and exits 0 silently. Switched to `tsc -b --force` (matches `npm run build`'s `tsc -b`). Canary passed with the corrected command (deliberately bad `number = "nope"` produced `TS2322` + exit 2). Rule 17 verified.
- `@types/react-window` v1 shim was incompatible with react-window v2's inline types — uninstalled. v2 ships `dist/react-window.d.ts` via its own `"types"` field.
- Intra-page lazy wrappers for Monaco / xterm / ReactFlow NOT added — route-level lazy already achieves the acceptance criterion (Monaco only loads when ExplorePage is visited; verified via chunk report). Adding intra-page Suspense would introduce user-visible flicker on every file click for no additional bundle savings.
- FuzzingPage xterm lazy-load skipped — FuzzingPage does not import xterm; intake was inaccurate.
- Recharts skipped — not a dep.
- FileTree virtualization already in place via react-arborist; no change needed.

### Verify battery (all PASS)

```
tsc -b --force                          : exit 0 (canary caught TS2322 when seeded)
npm run build                           : built in 6.78s, 0 errors
chunks                                  : 73 (threshold >5)
initial /projects bundle (gzip estimate): 119 KB (threshold <500 KB gzip)
/health                                 : 200 {"status":"ok",...}
/health/deep                            : 200 deep ok (all subsystems)
DPCS10 canary                           : 260 blobs (matches Phase 1 baseline)
GET /api/v1/projects (no auth)          : 401
GET /api/v1/projects (dev-key)          : 200
```

### Commits shipped (by Stream Gamma)

- `914d139` — feat(frontend): PageLoader + lazy route imports in App.tsx
- `bf60b53` — feat(frontend): add react-window + virtualize SbomPage vulnerability list
- (FindingsList + FindingsPage virtualization changes landed in commit `f614c43` which the auto-hook tagged with Stream Alpha's D3 message — see handoff for the reconciliation note)

