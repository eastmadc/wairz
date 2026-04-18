# Patterns: Hardware Firmware Page — Usability Overhaul

> Extracted: 2026-04-18
> Campaign: `.planning/campaigns/completed/feature-hw-firmware-usability-overhaul.md`
> Postmortem: none

## Successful Patterns

### 1. Author the intake brief ourselves BEFORE invoking autopilot

- **Description:** Instead of dropping a one-paragraph intake item and
  letting autopilot "figure it out," the brief was written as a 180-line
  spec with exact file paths, 13 numbered change items across three
  priority tiers, per-item acceptance criteria, explicit quality gates,
  and out-of-scope carve-outs.
- **Evidence:** Autopilot ran straight through brief → build → verify
  without asking a single clarifying question; every acceptance criterion
  mapped to a specific test assertion; 77/77 tests passed on first run.
- **Applies when:** The user has already done the research / user
  studies and wants execution rather than discovery. Autopilot's brief
  phase is a safety net, not a substitute for knowing what you want.

### 2. Server-side severity aggregation over client-side compute

- **Description:** Extended `GET /cve-aggregate` with per-severity
  counts (`hw_severity_critical/high/medium/low`) so the StatsHeader
  shows the breakdown without computing it in React.
- **Evidence:** Header numbers match partition-tree badges even when
  server-side filters (category / vendor / signed_only) change the
  visible set; no client reducer diverges from the canonical count.
- **Applies when:** The number you render has to match a persisted
  database fact AND downstream filters can change which rows are
  visible. Computing client-side produces two sources of truth.

### 3. Export the pure selection logic so it's unit-testable

- **Description:** `pickDefaultOpenPartitions`, `matchesQuery`,
  `highlightMatches` all lifted out of component bodies into named
  exports. Components wrap them; tests import them directly.
- **Evidence:** Tree auto-expansion rule, search filter predicate, and
  highlight rendering all have focused unit tests without needing
  React-dom or testing-library in the stack.
- **Applies when:** A UI decision encodes a user-visible contract
  (which items appear, which partitions open, which spans highlight).
  Inline in a component → untested. Exported → cheap tests.

### 4. Sandbox enforcement via realpath + prefix check (not string compare)

- **Description:** `GET /{blob_id}/download` calls `os.path.realpath()`
  on BOTH the blob path and the sandbox roots before running
  `candidate.startswith(root + "/")`. Rejects any path whose resolved
  target falls outside the firmware's extraction_dir.
- **Evidence:** Test `test_symlink_to_outside_is_rejected` — a symlink
  placed INSIDE extraction_dir but pointing OUTSIDE it is rejected 403.
  A naive `str.startswith(extraction_dir)` check would have let it
  through.
- **Applies when:** Any new endpoint that serves user-named filesystem
  paths. Path traversal isn't just `../` — symlinks, weird casing, and
  realpath differences across bind-mounts all bite. Use `realpath` on
  both sides before comparing.

### 5. Idempotent re-detection via delete-then-insert + unique constraint

- **Description:** When detection logic changes post-insert, delete the
  existing blob rows for that firmware and call `detect_hardware_firmware`
  fresh. The insert uses `on_conflict_do_nothing` on
  `(firmware_id, blob_sha256)` so duplicate runs are safe.
- **Evidence:** Re-ran detection on firmware `0ed279d8` after the
  container-root fix: 246 stale blobs deleted, 260 fresh blobs inserted,
  no DB constraint errors, graph build succeeded.
- **Applies when:** You have a post-extraction detector that projects
  filesystem state into DB rows. If the detector changes, rows from the
  prior version are stale. A delete+reinsert under a conflict-do-nothing
  constraint is simpler than per-row diffing.

### 6. `docker cp` + in-container pytest for fast iteration

- **Description:** Before running `docker compose up -d --build`, copy
  the updated Python files into the running container with `docker cp`
  and invoke `pytest` against them directly. Full suite runs in seconds
  instead of the ~2-minute image rebuild cycle.
- **Evidence:** Caught the `<Fragment>` key issue and the realpath
  edge cases in under a minute each. Only did the full rebuild once at
  the end of the campaign.
- **Applies when:** Iterating on Python changes that don't need new
  system packages. Frontend changes with HMR work the same way but the
  build step is different (tsc + vite). Use for TEST cycles only — ship
  via proper rebuild.

### 7. Controlled Tabs let stat cards drive navigation

- **Description:** Converted the `<Tabs>` in `HardwareFirmwarePage`
  from `defaultValue` to controlled `value`/`onValueChange`. Stat-card
  click handlers can now switch the active tab alongside applying a
  filter, landing the user exactly where their intent goes.
- **Evidence:** "Hardware CVEs" card → Tree tab with CVE sort mode;
  "Kernel CVEs" card → Flat Table with kernel-module filter (bypassing
  the default hide-kernel-modules toggle).
- **Applies when:** A landing surface has headline metrics AND multiple
  views of the same data. Uncontrolled tabs force the user to find the
  right view themselves after clicking a metric.

## Key Decisions

| Decision | Rationale | Outcome |
|---|---|---|
| Autopilot over Archon for execution | Scope fit "well-scoped medium feature"; no multi-session decomposition needed | Completed in one session, 77/77 tests green |
| Extend `/cve-aggregate` rather than add a second endpoint | Clients already poll it on page load; severity fields are near-free server-side | One round-trip, no extra loading state |
| `FileResponse` over `StreamingResponse` for download | Native filename + Content-Disposition + Content-Length support; file is on local disk | 1.1 MB gz.img verified end-to-end |
| 200 ms debounce on search input | Felt instant during typing; avoided re-render thrash on tree filter | Adopted |
| Kernel CVEs as separate stat card (not merged) | 439 kernel CVEs would visually drown the 26 hw-firmware ones | Adopted — product-PM persona served |
| Skip low-confidence quality rules this campaign | Most lessons were judgment calls, not specific-regex-detectable | No new harness rules added; captured as patterns instead |
