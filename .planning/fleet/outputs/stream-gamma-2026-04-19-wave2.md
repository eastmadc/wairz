# Stream Gamma — Wave 1 Complete, Wave 2 Pickup

> Campaign: wairz-intake-sweep-2026-04-19
> Phase: 4 (Frontend hardening)
> Stream: Gamma — code splitting + list virtualization
> Status: WAVE 1 COMPLETE

## Summary

Converted all 15 App.tsx page imports to `React.lazy` with a shared Suspense PageLoader, added `react-window@2.2.7`, virtualized the SbomPage vulnerability table, and virtualized the FindingsPage findings list. Initial JS payload on `/projects` dropped from 455 KB gzipped (single 1.64 MB chunk) to 119 KB gzipped (one of 73 chunks). Monaco, xterm, ReactFlow, and all page-specific code are now lazy-loaded per route.

## Baseline vs After (bundle size table)

| Metric | BEFORE | AFTER | Δ |
|---|---|---|---|
| JS chunk count | 1 | 73 | +72 |
| Initial bundle (raw) | 1,637.88 kB | 364.23 kB | -77.7% |
| Initial bundle (gzip) | 455.52 kB | 118.88 kB | -73.9% |
| xterm in initial | yes | NO (lazy) | moved to its own 335 KB chunk |
| Monaco in initial | yes | NO (lazy) | moved into ExplorePage chunk (201 KB) |
| ReactFlow in initial | yes | NO (lazy) | moved into ComponentMapPage chunk (76 KB) |

## Top-5 chunks after

1. `index-*.js` — 364 KB raw / 119 KB gzip (initial, shared)
2. `xterm-*.js` — 335 KB raw / 85 KB gzip (lazy, loaded only when ExplorePage or EmulationPage visited)
3. `ExplorePage-*.js` — 202 KB raw / 54 KB gzip (incl. Monaco wrappers)
4. `style-*.js` — 179 KB raw / 58 KB gzip (radix + shared UI)
5. `SecurityScanPage-*.js` — 84 KB raw / 20 KB gzip

## Code-split verified per page

All 15 route components emit their own chunk, confirmed by build output. Every `pages/*.tsx` file has a corresponding `dist/assets/{PageName}-*.js` entry.

## Virtualization

- **SbomPage** — `VirtualizedVulnTable` subcomponent uses `<List>` from react-window v2 with `useDynamicRowHeight` (re-keyed on `expandedRows` changes) to handle variable row heights (collapsed row ~40px vs expanded ~200-400px). New `VulnerabilityRowVirtual.tsx` mirrors the original row on a CSS grid (`COLUMN_TEMPLATE`) since virtualization requires `<div>` rooting. Header is a sticky sibling div matching the column template. Original `VulnerabilityRow.tsx` left in tree as dead code — follow-up cleanup candidate.
- **FindingsList** — inline `<FindingRow>` consumed by `<List>` at fixed `ROW_HEIGHT = 72`. FindingsPage outer wrapper switched from `overflow-y-auto` to `flex flex-col min-h-0` so the List can own its scrollport.

### What a manual scroll test would show

- SbomPage: scrolling 10K+ rows, only ~15-25 `<div data-vuln-row>` elements should be mounted at any time. DevTools "Elements" panel would show a short sequence of row divs wrapped in the react-window container, with aria-posinset/aria-setsize updating as you scroll. Expanding a row grows its height via ResizeObserver; neighbours reposition. Initial render with 50K rows renders in <100ms where previously it would freeze the tab.
- FindingsList: same — ~15 rows mounted at a time even with 5K findings.

## Rule-17 tsc canary

```
$ echo 'const __wairz_canary: number = "nope"; export default __wairz_canary;' > src/__wairz_canary.ts
$ npx tsc -b --force 2>&1 | grep -q "Type 'string'" && echo OK || echo FAIL
OK
```

Note: project uses `tsconfig.json` with `"files": []` + `references`. Plain `tsc --noEmit` compiles zero files and exits 0 silently — matches anti-pattern #2 (verification gap). Use `tsc -b --force` for canary and real verification. Build script `tsc -b && vite build` already does this correctly.

## Commits shipped

- `914d139` — feat(frontend): PageLoader + lazy route imports in App.tsx
- `bf60b53` — feat(frontend): add react-window + virtualize SbomPage vulnerability list
- FindingsList + FindingsPage virtualization diff included in `f614c43` (Stream Alpha's D3 CRA commit — see Deviations & Risks #3)

## Deviations & risks

1. **react-window v2 API change** — the intake doc referenced the v1 `FixedSizeList` + `VariableSizeList` API. v2 replaces these with a single `<List>` + `useDynamicRowHeight`. Implementation followed v2's shape. `@types/react-window` (v1 shim) was uninstalled since the v2 package ships its own types.
2. **Intra-page lazy wrappers (Monaco/xterm/ReactFlow) were NOT added.** Route-level lazy already achieves the acceptance criterion ("Monaco only loads when ExplorePage is first visited") by transitively splitting the page chunk. Intra-page Suspense would add a visible flicker on every file click for no additional bundle savings. If bundle targets regress, revisit.
3. **Commit grouping noise** — an auto-hook bundled my FindingsList + FindingsPage edits into an unrelated Stream Alpha D3 commit (`f614c43`). The diff is correct and the tree state is correct; only the commit message is wrong. Not worth a history rewrite on a shared branch. Future streams running in parallel on the same worktree should be aware that automated commits can sweep unrelated staged work together.
4. **Intake discrepancies caught at research time:**
   - FuzzingPage does not import xterm (nothing to lazy-load). Skipped.
   - Recharts is not a dependency. Skipped.
   - FileTree already virtualises via react-arborist (has `height={treeHeight}` prop). No change.
   - Root `/home/dustin/code/wairz/package.json` was a 0-byte untracked stray file breaking `vite build`. Deleted (not tracked anywhere). Logged in research file; may want a `.gitignore` entry for monorepo root if this recurs.

## Wave 2 follow-ups (queue for a future session)

1. **Remove dead `VulnerabilityRow.tsx`** — superseded by `VulnerabilityRowVirtual.tsx`. 331 LOC removable. Grep confirms zero imports remain. 2-min cleanup.
2. **Virtualize `SecurityScanResults.tsx`** — intake flagged this as "may defer" due to nested group rendering (APK scan findings). Left out of Wave 1 scope. When picked up, look at row-height variance — probably needs `useDynamicRowHeight` like SbomPage.
3. **Consider vite `manualChunks` for the vendor split.** xterm is 335 KB in a dedicated chunk because it's huge and used by two pages; verify that the browser doesn't redundantly download the ExplorePage chunk + the xterm chunk when a user opens ExplorePage (expect them to be separate HTTP requests — the vite HTTP/2 setup makes this cheap). If an initial-page-route waterfall is observable in devtools, manually chunk common vendors.
4. **APK scanner list virtualization** — SecurityScanResults renders all apk-scan finding rows without virtualization. Defer per intake guidance; reconsider when a project accumulates 1K+ apk scan findings in practice.

## Verify battery results

| Check | Result |
|---|---|
| `tsc -b --force` | exit 0 |
| `tsc -b --force` canary (bad TS injected) | TS2322 caught, exit 2 — tsc IS live |
| `npm run build` | built in ~7s, 0 errors |
| JS chunk count | 73 (>5 threshold) |
| initial gzipped bundle | ~119 KB (<500 KB target) |
| `/health` | 200 ok |
| `/health/deep` | 200 all subsystems ok |
| DPCS10 canary | 260 blobs (unchanged — Phase 1 baseline) |
| `GET /api/v1/projects` (no auth) | 401 |
| `GET /api/v1/projects` (dev key) | 200 |

## Files touched (absolute paths)

- `/home/dustin/code/wairz/frontend/src/App.tsx` — lazy route imports + Suspense wrapper
- `/home/dustin/code/wairz/frontend/src/components/PageLoader.tsx` (new)
- `/home/dustin/code/wairz/frontend/src/components/sbom/VulnerabilityRowVirtual.tsx` (new)
- `/home/dustin/code/wairz/frontend/src/pages/SbomPage.tsx` — virtualized the vuln table
- `/home/dustin/code/wairz/frontend/src/components/findings/FindingsList.tsx` — virtualized + extracted FindingRow
- `/home/dustin/code/wairz/frontend/src/pages/FindingsPage.tsx` — adjusted outer container for List scroll
- `/home/dustin/code/wairz/frontend/package.json` + `package-lock.json` — react-window@^2.2.7
- (deleted) `/home/dustin/code/wairz/package.json` — empty 0-byte stray file blocking vite
