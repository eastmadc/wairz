# Patterns: Wairz Intake Sweep — Wave 1 close (2026-04-22, session 7e8dd7c3)

> Extracted: 2026-04-22
> Campaign: `.planning/campaigns/completed/wairz-intake-sweep-2026-04-19.md`
> Handoff: `.planning/knowledge/handoff-2026-04-22-session-7e8dd7c3-end.md`
> Postmortem: none
> Baseline: c7b8a34 → b99e6c6 (+33 commits)

The campaign closes this session. All 5 Phase 5 god-class splits
shipped; all 8 frontend virtualization targets closed; Rules #27 + #28
adopted. 5× validation of the "N additive + 1 cut-over" pattern now
makes it a Learned Rule.

## Successful Patterns

### 1. "N additive + 1 cut-over" pattern — 5× validated, now Rule #27

- **Description:** When decomposing a ≥1000 LOC single-file class/module
  into a subpackage, ship N-1 pure-additive commits (each extracts one
  topic file; old monolith unchanged; callers still hit the monolith;
  local `python3 -m py_compile` only, no rebuild, no invariant probe)
  followed by 1 atomic cut-over commit (delete monolith + update ≤5
  callers in-place OR keep a `from app.services.new_pkg import *`
  shim for >5). Rule #8 rebuild + Rule #11 runtime smoke run ONCE
  after the cut-over, not per commit.
- **Evidence:** All 3 Phase 5 splits this session shipped clean:
  - α sbom (9 commits — 8 additive + 1 cut-over, 2412 LOC → 21 files
    with Strategy pattern)
  - β emulation (7 commits — 6 additive + 1 cut-over, 1664 LOC → 7
    files, acyclic import DAG)
  - γ mobsfscan (5 commits — 4 additive + 1 cut-over, 1539 LOC → 5
    files, simplest of the 3)
  
  Combined with b56eb487 γ (manifest_checks, 8 commits) and b56eb487 δ
  (security_audit_service, 8 commits): **5 consecutive clean shippings
  across 2 sessions. 34 additive + 5 cut-over commits, 0 reverts, 0
  cross-stream sweeps** (under Rule #23 worktree discipline). The
  pattern now has enough evidence (Citadel quality bar was 4+) to
  graduate from "pattern" to "Learned Rule #27" in CLAUDE.md.
- **Applies when:** Any single-file refactor ≥1000 LOC with ≥3 topic
  seams. Especially: Mixin→composition conversions, Strategy-pattern
  extractions, god-class decompositions, module-move relocations.
  DOES NOT apply to in-place edits that change class shape mid-refactor
  (remove/rename a field on an existing class) — those need Rule #8
  rebuild immediately.

### 2. Rule #19 applied at cut-over time catches intake under-counts

- **Description:** The intake's caller list can be stale or
  under-counted — lazy imports (function-body `from ... import X`)
  regularly slip through the write-time grep. Re-running
  `grep -rn 'from app.services.<old_module> import' backend/` in the
  cut-over commit (NOT just at the start of the stream) reveals any
  new callers added between intake time and refactor time. If
  count > intake-listed count by ≤1-2, update in-place in the cut-over
  commit and note the discrepancy in the commit message.
- **Evidence:** Stream α's `sbom_service` cut-over: intake listed 4
  callers (`assessment_service.py`, `routers/sbom.py`,
  `ai/tools/sbom.py`, `tests/test_android_sbom.py`). Re-grep found a
  5th: `ai/tools/sbom.py:544` has a lazy
  `from app.services.sbom_service import CPE_VENDOR_MAP` inside a
  function body. Updated in the same cut-over commit; under-count
  noted in the commit message as a learning signal. Without the
  re-grep, the cut-over commit would have deleted the monolith while
  `CPE_VENDOR_MAP` referenced the old module, causing a latent
  ImportError at next invocation of that function.
- **Applies when:** Every cut-over commit of a god-class split.
  Mechanical check: `grep -rn 'from app.services.<name>_service' backend/
  | grep -v __pycache__ | grep -v '\.pyc'` — must return 0 results
  AFTER all in-place caller updates land in the cut-over commit.

### 3. Rule #19 at topic-file-extraction time drops dead-abstractions

- **Description:** The intake's prescribed topic-file list is a
  guidance, not a prescription. If a prescribed topic file maps to
  NO code in the actual monolith (the intake was written against a
  different mental model, or the library choices changed), drop that
  file per Rule #19. Don't create an empty placeholder; don't write
  dormant code anticipating a feature that doesn't exist.
- **Evidence:** Stream α's sbom intake prescribed `lief_strategy.py`
  and `rpm_strategy.py`. Neither corresponded to actual monolith code:
  the monolith uses `pyelftools` (not LIEF) for ELF parsing, and
  `Syft` (delegated CLI) handles RPM catalog parsing — no native
  `rpm` parser exists. α correctly skipped creating placeholder
  files per Rule #19 and named the actual ELF-parsing strategy
  `so_files_strategy.py` instead (matching what the code does, not
  what the intake assumed). Documented in the cut-over commit.
- **Applies when:** Any refactor with a prescribed target layout from
  a design doc / intake. Before creating a topic file, grep the
  monolith for its purported keywords — if zero hits, drop it.

### 4. Variable-height list virtualization via flat-row discriminator

- **Description:** For expandable lists (collapsed row → expand to
  show details) or nested groups (section header + child findings),
  flatten the tree to a single `Row[]` array with a `kind`
  discriminator (e.g. `'group' | 'finding' | 'detail'`). The flat
  array is a `useMemo([tree, expandedSet, ...])` that rebuilds when
  expansion changes. React-window's variable-size `List` gets a
  `rowHeight: (index) => number` function that inspects
  `rows[index].kind` and returns the appropriate pre-computed height.
  When expansion changes, the `useMemo` rebuilds the array → react-window
  naturally invalidates its height cache → no `resetAfterIndex`
  bookkeeping.
- **Evidence:** Stream δ used this pattern for all 3 targets:
  - `DriversTable.tsx`: 2-kind rows (`driver` → 32px; `detail` →
    `DETAIL_CHROME_HEIGHT + depCount * DETAIL_DEP_HEIGHT`)
  - `CvesTab.tsx`: 2-kind rows with description-wrap estimate
    (`DETAIL_CHROME(60) + ceil(description.length/100) * 18 +
    max(1, blobCount) * 20`) + `overflow-y-auto` safety net
  - `SecurityScanResults.tsx`: 3-kind rows
    (`group | finding | detail`) with the most complex height math;
    deep-link rewired via `useListRef` + `scrollToRow(index, 'center')`
    inside `requestAnimationFrame` (old `document.querySelector` no
    longer works — off-screen rows aren't in the DOM).
  
  All 3 files type-check cleanly per-commit (`npx tsc -b --force`);
  all 3 have ≥ 2 virt-hints on the acceptance grep; per-chunk bundle
  verification confirms `HardwareFirmwarePage-*.js` (7 hits for
  Cves+Drivers+BlobTable bundled together) and
  `SecurityScanPage-*.js` (5 hits).
- **Applies when:** React lists where row height varies by state
  (expanded/collapsed), by content (text-wrap, badge count,
  conditional subcomponents), or by hierarchical level (group header
  vs. leaf). Avoids ResizeObserver dependency for cases where height
  is a closed-form function of data.

### 5. Deep-linking-to-virtualized-row via scrollToRow inside rAF

- **Description:** Scrolling to a specific row in a virtualized list
  (for deep-links, permalinks, or programmatic focus) cannot use
  `document.querySelector('[data-id]').scrollIntoView()` because
  off-screen rows aren't in the DOM — they exist only as items in
  the virtualization's `rows[]` array. The replacement pattern:
  1. `useListRef` (react-window v2) to get an imperative handle on
     the `List` component.
  2. A state flag that marks "I want to scroll to row X".
  3. A second effect that watches `virtRows` (the flat array) for
     the target row's index; when found, call
     `listRef.current?.scrollToRow({ index, align: 'center' })`
     inside `requestAnimationFrame` (to ensure layout is complete).
  4. If the target row is behind a collapsed group/expandable row,
     set expansion state FIRST; the `useMemo` rebuilds `virtRows`
     with the target now included; then the scroll effect fires.
- **Evidence:** `SecurityScanResults.tsx` (commit f92989d): deep-link
  from `?finding=<id>` query param → `expandedGroups.add(group)` →
  wait for `virtRows` to rebuild → `scrollToRow` inside `rAF`.
  Works for deeply-nested groups+findings+details.
- **Applies when:** Any virtualized list with deep-linkable rows or
  programmatic-scroll needs. Do NOT try to retrofit `scrollIntoView`
  on the parent container — it won't see the off-screen row.

### 6. Cron-job migration during service split

- **Description:** When a god-class split moves the class that houses
  a cron callable (or its module-level helpers), the `WorkerSettings.cron_jobs`
  array must still register the callable. Two risks:
  1. Function-scope imports inside the cron callable (common in wairz —
     `arq_worker.py:363` has a function-scope
     `from app.services.emulation_service import EmulationService`
     to avoid a top-level cycle). These must be updated to the new
     path in the cut-over commit.
  2. The cron registration itself (`cron(callable, minute=...)`) is
     unchanged; only the callable's internal imports need updating.
  
  Post-rebuild invariant: `len(WorkerSettings.cron_jobs) == 7` must
  hold.
- **Evidence:** Stream β's emulation split preserved
  `cleanup_emulation_expired_job` cron correctly:
  `arq_worker.py:363` function-scope import updated from
  `emulation_service` → `emulation` in the cut-over commit;
  `arq_worker.py:688` cron registration (`cron(cleanup_emulation_expired_job,
  minute={5, 35})`) unchanged; post-rebuild `cron_jobs=7` verified.
- **Applies when:** Any service split where the target service has
  active cron registrations. Grep pattern:
  `grep -n 'from app.services.<old>' backend/app/workers/arq_worker.py`
  — if hits are found, they must be updated in the cut-over commit.

### 7. Service split public-API simplification: private method → free function

- **Description:** During a god-class split, look for
  `_private_method` references in callers (cross-module calls to
  methods that should have been public). When the method is moved to
  a topic-file that naturally lives outside the class instance
  (`docker_ops.py`, `kernel_selection.py`, etc.), it can become a
  free function with explicit parameters — cleaner API, easier to
  test, no instance-coupling. Update the caller in the same
  cut-over commit.
- **Evidence:** Stream β's emulation split found `fuzzing_service.py:405-408`
  was calling `EmulationService._copy_dir_to_container(...)` as a
  private method on the class. In the split, `_copy_dir_to_container`
  became `copy_dir_to_container(docker_client, container, src, dst)`
  — a free function in `emulation/docker_ops.py`. The caller import
  switched from `from app.services.emulation_service import EmulationService`
  + instance-method call to
  `from app.services.emulation.docker_ops import copy_dir_to_container`
  + free-function call. Cleaner, no fake instance construction.
- **Applies when:** God-class splits where a private method is used
  cross-module. Consider promoting to a public free function if:
  (a) the method doesn't depend on `self` state (just helpers), or
  (b) the callers are already faking instance construction just to
  call it.

### 8. Per-chunk bundle verification using library-level tokens, not identifier tokens

- **Description:** Modern bundlers (esbuild, rollup) mangle identifier
  names aggressively. Tokens like `VirtFindingRow`,
  `estimateDetailHeight`, `DETAIL_CHROME_HEIGHT`, `DRIVER_ROW_HEIGHT`
  — all unique to δ's implementation — get renamed to single letters
  in production bundles. Grep for them returns 0 hits post-build.
  INSTEAD, verify via tokens that survive minification:
  - `react-window` (string literal in comments / import specifier — may
    survive or not depending on tree-shaking)
  - `rowHeight`, `itemSize`, `rowComponent` — these are library
    public-API property names, often survive as object-property
    accesses in the minified bundle
  - `List` — library export name, often retained as a reference
- **Evidence:** Stream δ's per-chunk verification:
  `HardwareFirmwarePage-CjqRzjFx.js` 7 hits on
  `rowComponent|itemSize|rowHeight|react-window|useVirtualizer|useListRef`;
  `SecurityScanPage-C0jzq_Pe.js` 5 hits;
  `react-window-D4b5zYty.js` 16 hits (the vendor chunk bundles the
  library definitions — guaranteed survivable tokens). Grep for
  identifier-specific tokens (`VirtFindingRow`, `DETAIL_CHROME_HEIGHT`)
  returned 0 hits — those are mangled.
- **Applies when:** Rule #26 per-chunk verification after any Vite
  build. Use library-API tokens for verification; use identifier
  tokens only if you know the bundle config disables mangling (rare).

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Dispatch 4 parallel Wave-1 streams (α/β/γ backend + δ frontend) in isolated worktrees | All 3 backend splits touch pairwise-disjoint caller sets; δ's 3 files are frontend-only. Pre-dispatch caller grep confirmed zero overlap. | 25 commits in parallel, 0 conflicts, 0 cross-stream sweeps. Serial merge α→β→γ→δ → all --no-ff clean. |
| Agent Option B (local py_compile only) over Option A (docker cp + transient smoke) per stream | Splits were well-disciplined (≤9 commits each); post-merge Rule #8 rebuild + Rule #11 smoke in main session is cheap. `docker cp` pattern is validation-speed tool, not durable state — reserve for longer splits where pre-merge confidence is needed. | Zero post-merge surprises; all smokes passed first-try. Main session's 3-minute rebuild + smoke pipeline handled all 3 splits. |
| ε adoption committed INLINE (not as a 5th worktree) | No parallel streams running at ε time (all 4 merged); 2 doc edits (CLAUDE.md + mex mirror); committing inline avoided the overhead of a worktree-lifecycle for a trivial change. Rule #23 discipline applies to parallel work — sequential inline docs are fine. | 2 commits shipped in 60 seconds; no worktree bookkeeping. |
| ζ campaign close in SAME session as α/β/γ/δ/ε | Phase 5 was 5/5 after Wave 1; delaying close to a fresh session would have lost the natural "close on clean slate" moment. Campaign file still cacheable; git mv + status flip = 1 commit. | Campaign cleanly archived with full 7-session trail. No debt for next session. |
| Skip Wave 2 η (private-API P3 audit) | 37 function-local imports is open-ended work; already documented as "deferred to standalone campaign"; better as a dedicated focused session with Rule-23 dispatch discipline than squeezed into session-end budget. | Campaign closes cleanly without half-finished P3 work. η scheduled for a future dedicated session. |

## Applicability Notes

- **Rule #27 graduation** — this session's 3 splits (plus last session's
  2) provide the 4+ clean shippings the Citadel quality bar requires.
  Pattern moved from knowledge → CLAUDE.md Learned Rule #27. The
  `.mex/context/conventions.md` Verify Checklist mirror was updated
  in the same session per Rule #21.
- **Rule #28 graduation** — uniform +14-22% LOC drift across 5
  Phase-5 targets is a strong signal that intakes age predictably.
  Pattern moved from knowledge → CLAUDE.md Learned Rule #28.
- **Rule #23 discipline** — 6 consecutive sessions of clean
  worktree-per-stream dispatch with 0 cross-stream sweeps. The
  pattern is now deeply durable; the risk of breaking it is
  essentially just operator forgetfulness (the dispatch prompts
  explicitly include `git worktree add` verbatim now).
- **Rule #26 discipline** — frontend rebuild verification via
  per-chunk grep caught both pre-existing and new virtualization
  consistently. 8 total virtualized components tracked across 3
  sessions; no "works at HEAD but boots fail" frontend incidents
  since the rule was adopted.
- **δ's variable-height technique** (flat-row discriminator + closed-form
  heights) is the house style for wairz frontend virtualization going
  forward. It extends the `react-window` v2 `List` + `rowComponent`
  pattern established in Wave 1 of b56eb487 to handle expandable /
  nested cases without ResizeObserver complexity. Worth a
  `.mex/patterns/` recipe file: "virtualize-variable-height-list.md".

## Cross-references

- This session's handoff:
  `.planning/knowledge/handoff-2026-04-22-session-7e8dd7c3-end.md`
- Prior session's patterns (the 2 Rule-adoption candidates originated
  here): `.planning/knowledge/wairz-intake-sweep-wave1-close-2026-04-21-patterns.md`
- Cumulative campaign artifact:
  `.planning/campaigns/completed/wairz-intake-sweep-2026-04-19.md`
  (all 7 sessions, full trail)
- Learned Rules now in CLAUDE.md: 26 → 28 after ε commits (`d4e762f`,
  `2bd8612`).
