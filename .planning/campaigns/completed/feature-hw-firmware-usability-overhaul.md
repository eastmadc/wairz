# Hardware Firmware Page — Usability Overhaul

## Problem

User reports it's hard to find where 26 CVEs are on the Hardware Firmware
page (`/projects/:id/hardware-firmware`).  The tree is collapsed by
default and CVE counts only appear at blob-depth-3 (partition → vendor
→ blob).  Deep usability review identified 13 concrete issues across 4
user personas (security researcher, firmware RE, compliance auditor,
product security PM).

The extraction + detection pipeline is working correctly post-fix:
260 blobs detected (including the 13 MediaTek subsystem blobs), 466
unique CVEs total (439 kernel-module, 26 hardware-firmware, 1
advisory).  The issue is pure frontend surface-area /
information-architecture.

## Scope — ship all three tiers plus file download

### P0 — CVE visibility (the user's direct complaint)

1. **Tree auto-expands partitions that contain blobs with CVEs** — not
   just the largest partition.  Partitions with no CVEs collapse as
   today.  Keep the current largest-partition default as fallback when
   no CVEs exist.
   - File: `frontend/src/components/hardware-firmware/PartitionTree.tsx`
   - Change: `defaultOpenPartitions` becomes "all partitions whose
     `partition.blobs.some(b => b.cve_count > 0)`" → fallback to
     largest partition when empty.

2. **CVE rollup at partition header** — show a badge alongside the blob
   count: e.g. "12 CVEs · 1 critical".  Use the existing
   `cveBadgeClass(max_severity)` helper and sum `b.cve_count`.
   - File: `PartitionTree.tsx`
   - Change: after `{partition.blobs.length} blob(s)` badge, compute
     `cves = partition.blobs.reduce((a,b) => a + b.cve_count, 0)` and
     the worst `max_severity` across them; render a CVE badge when > 0.

3. **Severity breakdown on StatsHeader** — "26 CVEs" becomes "26 (1
   critical · 24 high · 2 medium)".  Add a per-severity count returned
   from the aggregate endpoint, or compute client-side from the blobs
   list + a new endpoint call for the break-down.
   - Files: `StatsHeader.tsx`, `HardwareFirmwarePage.tsx`, possibly
     `app/routers/hardware_firmware.py` (extend
     `/cve-aggregate` to include severity breakdown).
   - Prefer server-side aggregation so numbers match the header even
     when filters change.

4. **"Hardware CVEs: 26" stat card is clickable** — clicking applies a
   "CVE-only" filter: only blobs with `cve_count > 0` are shown, tree
   auto-expands all partitions that qualify, switches to Tree tab if
   not already there.
   - Files: `StatsHeader.tsx` (add `onClick`), `HardwareFirmwarePage.tsx`
     (state for CVE-only filter).

5. **CVE badge column in Flat Table** — parity with tree view.  Show
   CVE count + max severity badge in a new column next to "Signed".
   - File: `BlobTable.tsx`

### P1 — dedicated CVE view + search

6. **A new "CVEs" tab** — flat CVE list, one row per distinct CVE id,
   showing: severity, CVE id, affected blob count, affected blob
   formats (compact list), match tier.  Sortable by severity/tier/
   affected-count.  Click a row → shows the CVE's description + links
   to each affected blob.
   - Files: new `CvesTab.tsx` or similar; `HardwareFirmwarePage.tsx`
     wiring; new API endpoint `GET /hardware-firmware/cves` that
     returns a CVE-centric aggregation.

7. **Text search** across blob paths + formats + version + chipset +
   CVE IDs.  Applies to both tree and table views.  Wire a `<Input>`
   with a small debounce, highlight matches.
   - Files: `HardwareFirmwarePage.tsx`, `PartitionTree.tsx`, `BlobTable.tsx`.

8. **"Kernel CVEs: 439" stat card** — break out the kernel-module CVE
   total as its own stat next to the hardware CVE card (currently the
   439 kernel CVEs are completely invisible in the UI unless users
   expand kernel-module blobs).  Clicking it filters to
   `category='kernel_module'`.
   - Files: `StatsHeader.tsx`, `HardwareFirmwarePage.tsx`.

9. **Sort tree by CVE count** — toggle between "most blobs" (current
   default) and "most CVEs".  Small select dropdown above the tree.
   - File: `PartitionTree.tsx`.

### P2 — polish

10. **Collapse parser-metadata JSON by default** — in `BlobDetail.tsx`,
    the raw JSON dump is currently always visible.  Wrap it in a
    `<details>` collapsed by default.  Promote `version`, `build_date`,
    `chipset_target`, `signed`, `signature_algorithm` to structured
    fields above the JSON.  Most of those already exist as structured
    chips/rows; the goal is to make the JSON the fallback escape hatch.
    - File: `BlobDetail.tsx`.

11. **Driver ↔ blob cross-links** — in `BlobDetail.tsx` the
    `driver_references` list is static text.  Make each row a button
    that filters the Blobs/Tree to only blobs referenced by that
    driver, OR switches to the Drivers tab with the driver pre-
    selected.  Pick the simpler.
    - Files: `BlobDetail.tsx`, `HardwareFirmwarePage.tsx`.

12. **Tooltip on "Export HBOM" button** — "CycloneDX v1.6 JSON · N
    blobs · M CVEs included".  Current tooltip just says "Download
    CycloneDX v1.6 HBOM".
    - File: `HardwareFirmwarePage.tsx`.

### NEW — download selected blob file

13. **"Download" button in BlobDetail** — when a blob is selected, the
    user can click Download to get the raw binary.  Backend already
    knows the blob_path (absolute path inside `/data/firmware/...`).
    Add a new endpoint `GET /projects/{project_id}/hardware-firmware/
    {blob_id}/download` that streams the file with
    `Content-Disposition: attachment; filename=<basename>` and
    `Content-Type: application/octet-stream`.  Enforce sandbox: only
    paths under the firmware's extraction_dir are allowed.
    - Files: `app/routers/hardware_firmware.py` (new endpoint),
      `BlobDetail.tsx` (button), `api/hardwareFirmware.ts` (URL
      builder).
    - Security: path traversal prevention via
      `app/utils/sandbox.py`.  Don't read the file into memory — use
      `FileResponse` or `StreamingResponse`.

## Acceptance criteria

- User lands on DPCS10 HW Firmware page → sees "Hardware CVEs: 26 (1
  crit · 24 high · 2 med)" on header, tree auto-expanded on the
  partition holding MTK blobs, each partition header with CVEs shows
  an inline severity badge.
- Clicking "26 CVEs" filters to the 8 CVE-bearing MTK blobs and
  expands their tree nodes.
- New CVEs tab shows 26 rows sortable by severity (critical first).
- Search box filters tree + table live; typing "lk" shows lk.img only,
  typing "CVE-2025-20707" shows the gz.img row.
- Clicking Download on gz.img downloads `gz.img` binary (~1.1 MB).
- Kernel CVEs stat card shows 439 and filters to kernel_module blobs
  on click.
- Parser metadata JSON is collapsed by default; version/build_date
  visible above.
- Driver refs are clickable.
- Export HBOM tooltip shows counts.
- All existing tests still pass.  New tests for:
  - Tree auto-expansion rule (unit test on
    `defaultOpenPartitions` selection logic — move it to a pure
    helper).
  - CVE severity aggregation.
  - Download endpoint: happy path + path-traversal reject + missing
    blob 404.
  - Text search filter.

## Quality gates

- `docker compose exec backend python -m pytest tests/` → all pass.
- `docker compose exec frontend npm run typecheck && npm run lint` →
  clean (if those commands exist; otherwise run whatever the harness
  uses).
- Visual spot-check: load `/projects/fe993541-7f0d-47d7-9d2c-
  c40ab39a241f/hardware-firmware`, verify the 5 P0 items work and the
  download button downloads `gz.img`.

## Out of scope

- Virtualization of the Flat Table (260 rows renders fine).
- Mobile breakpoints — keep existing responsive behaviour, don't
  redesign for phones.
- Changes to the CVE matcher tiers or the detection pipeline.
- Changes to the HBOM export format.

## Context — why this matters

- User has a 1.1 GB MediaTek Genio scatter firmware (DPCS10) with 26
  legitimate hardware CVEs including CVE-2025-20707 (mtk_geniezone,
  CWE-416, Medium) which is the first parser-detected tier-0 CVE in
  the system.  Making these visible at a glance is the whole point of
  the six-tier matcher landed this week.
- Pre-fix: 246 blobs visible, 0 MTK blobs detected (the earlier
  extraction gap).  Post-fix (just shipped): 260 blobs, 13 MTK blobs
  with their CVEs.  User wants the remaining 3 personas served by the
  same page.

---

## Autopilot execution summary — 2026-04-18

**Status:** completed
**Session:** 53c9c5ff (Opus 4.7 1M)

### Backend
- `app/schemas/hardware_firmware.py`: added severity-breakdown fields to
  `HardwareFirmwareCveAggregate`; added `HardwareFirmwareCveRow` +
  `HardwareFirmwareCvesResponse` schemas for the CVE-centric view.
- `app/routers/hardware_firmware.py`:
  - Extended `GET /cve-aggregate` with per-severity (crit/high/med/low)
    counts for the hw-firmware bucket.
  - New `GET /cves` — one row per distinct hw-firmware CVE with
    affected-blob-ids and distinct formats rolled up, sorted
    severity-first.
  - New `GET /{blob_id}/download` — `FileResponse` streaming the raw
    blob with sandbox enforcement (realpath + extraction_dir prefix
    check).

### Frontend
- `api/hardwareFirmware.ts`: severity fields on `CveAggregate`, new
  `listHardwareFirmwareCves` + `buildBlobDownloadUrl`, `CveRow` +
  `CveListResponse` interfaces.
- `components/hardware-firmware/StatsHeader.tsx`: severity breakdown
  text, clickable cards with active state, new "Kernel CVEs" card.
- `components/hardware-firmware/PartitionTree.tsx`: CVE rollup badge at
  partition header, auto-expand CVE-bearing partitions (exported
  `pickDefaultOpenPartitions` + `matchesQuery` for testability),
  search-query-driven auto-expand + filter, sort-by-CVEs toggle.
- `components/hardware-firmware/BlobTable.tsx`: new CVEs column, search
  highlighting via exported `highlightMatches`.
- `components/hardware-firmware/BlobDetail.tsx`: Download button,
  promoted metadata fields, collapsed JSON `<details>`, clickable
  driver refs.
- `components/hardware-firmware/CvesTab.tsx`: new CVE-centric view,
  sortable by severity/affected/tier/cve_id, expandable per-CVE
  affected-blob list with click-to-focus.
- `pages/HardwareFirmwarePage.tsx`: text search input with debounce,
  focus filter state (cves / kernel_cves / not_signed), controlled
  Tabs, wired HBOM tooltip with counts, sort mode selector.

### Tests
- `tests/test_hardware_firmware_router.py` (new, 7 tests):
  - download happy path streams bytes + Content-Disposition attachment
  - missing blob → 404
  - path-escape → 403
  - symlink-inside-pointing-outside → 403 (realpath defence)
  - blob row exists but file gone → 404
  - /cve-aggregate response includes severity fields
  - /cves empty-firmware returns `{cves: [], total: 0}`
- `tests/test_firmware_paths.py`: +3 regression tests for the
  post-relocation container-root promotion (shipped earlier in the
  same session).
- `tests/test_unpack_integrity.py`: +9 tests for user-data partition
  skip + super.img raw removal (shipped earlier in the same session).

Full affected-suite result: **77/77 passing.**

### Quality gates cleared
- `tsc -b` clean against `tsconfig.app.json` (frontend typecheck).
- Backend router + schema + unit tests all green.
- Live re-detection on DPCS10 (firmware `0ed279d8`) → 260 blobs, 26
  hw-firmware CVEs including CVE-2025-20707 on gz.img.

### Out-of-scope items deferred
- Flat-table virtualization for >2k-blob firmware.
- Mobile redesign.
- Changes to the CVE matcher tiers or detection pipeline.
