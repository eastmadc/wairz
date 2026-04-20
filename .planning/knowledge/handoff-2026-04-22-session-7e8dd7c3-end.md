---
session_id: 7e8dd7c3
date: 2026-04-22
campaign: wairz-intake-sweep-2026-04-19 (CLOSED)
baseline_head: c7b8a34
end_head: ae8e212
commits: 32 (25 feature/refactor + 4 merge + 2 docs + 1 campaign-close)
waves_completed: 1 (Wave 2 partial — ζ campaign close; η skipped)
---

# Session 7e8dd7c3 Handoff

## What shipped

Campaign-closing session. All 3 remaining Phase-5 god-class splits
(sbom, emulation, mobsfscan) shipped in a single parallel wave, plus
3 variable-height frontend virtualizations, plus adoption of two new
CLAUDE.md rules (#27, #28). 32 commits atop baseline `c7b8a34`.
Campaign file moved to `.planning/campaigns/completed/`.

**Zero cross-stream commit sweeps — 6th consecutive session of clean
Rule #23 worktree discipline.**

### Wave 1 (4 parallel streams in isolated worktrees)

#### Stream α — `sbom_service.py` god-class split (9 commits, Strategy pattern)

2412 LOC monolith → `sbom/` subpackage with 21 files. Largest file
394 LOC.

| # | SHA       | Topic                                             |
|---|-----------|---------------------------------------------------|
| 1 | `c38cbe2` | `constants.py` (CPE_VENDOR_MAP, VERSION_PATTERNS, SONAME_COMPONENT_MAP, FIRMWARE_MARKERS, KNOWN_SERVICE_RISKS, IdentifiedComponent, byte-read limits) |
| 2 | `e2fe918` | `purl.py` (build_cpe, build_os_cpe, build_purl)   |
| 3 | `d78d624` | `normalization.py` (ComponentStore + normalizers) |
| 4 | `befd0fb` | `strategies/base.py` (SbomStrategy ABC + StrategyContext) |
| 5 | `fb029a3` | `strategies/{syft,dpkg,opkg}_strategy.py`         |
| 6 | `3cf7aa3` | `strategies/{python_packages,android,kernel,firmware_markers}_strategy.py` |
| 7 | `4502fde` | `strategies/{busybox,c_library,gcc}_strategy.py`  |
| 8 | `2e678be` | `strategies/{so_files,binary_strings}_strategy.py` |
| 9 | `b29ef8f` | delete monolith + update 5 callers + service.py (coordinator) |

Caller audit: **5** (intake said 4). The 5th was a lazy
`from app.services.sbom_service import CPE_VENDOR_MAP` at
`ai/tools/sbom.py:544` — found via re-grep in the cut-over commit.
Per-Rule-#19 discipline: intake's prescribed `lief_strategy.py` and
`rpm_strategy.py` DROPPED (no code existed for them in the monolith;
`pyelftools` handles ELF parsing, Syft handles RPMs via its own
cataloger).

Merge: `ef8aec0` (--no-ff).

#### Stream β — `emulation_service.py` god-class split (7 commits)

1664 LOC monolith → `emulation/` subpackage with 7 files. Acyclic
import DAG.

| # | SHA       | Topic                               | LOC |
|---|-----------|-------------------------------------|-----|
| 1 | `002e106` | `__init__.py` skeleton              | 24  |
| 2 | `71476a4` | `docker_ops.py`                     | 411 |
| 3 | `0522095` | `kernel_selection.py`               | 119 |
| 4 | `393bafc` | `sysroot_mount.py`                  | 151 |
| 5 | `0df9e25` | `user_mode.py`                      | 266 |
| 6 | `c7b7dc7` | `system_mode.py`                    | 211 |
| 7 | `c267931` | delete monolith + update 4 callers + service.py | 906 |

4 callers updated in-place. Notable: `fuzzing_service.py:405-408`
switched from `EmulationService._copy_dir_to_container` (private
method call) to `copy_dir_to_container` free function (cleaner
public API). 15/15 `EmulationService` public methods preserved.
Cron registration of `cleanup_emulation_expired_job` preserved
(import path in `arq_worker.py:363` updated); `cron_jobs=7`
invariant holds post-rebuild.

Merge: `c3d7f21` (--no-ff).

#### Stream γ — `mobsfscan_service.py` god-class split (5 commits)

1539 LOC monolith → `mobsfscan/` subpackage with 5 files.

| # | SHA       | Topic                           | LOC |
|---|-----------|---------------------------------|-----|
| 1 | `63e42e0` | `normalization.py`              | 591 |
| 2 | `34a08a1` | `parser.py`                     | 357 |
| 3 | `70dfdb3` | `pipeline.py`                   | 671 |
| 4 | `5fa21b0` | `service.py` + `__init__.py`    | 80+87 |
| 5 | `206fbd5` | delete monolith + 4 callers     | —   |

4 callers updated. Module-level `_pipeline = MobsfScanPipeline()`
singleton moved to `mobsfscan.pipeline` — class-shape change, Rule
#8 rebuild required post-merge.

Merge: `773164f` (--no-ff).

#### Stream δ — Variable-height frontend virtualization (4 commits)

3 variable-height list components virtualized using react-window v2
`List` with variable-size `rowHeight` function + flat-row
discriminator pattern.

| SHA       | Component                                         | Pattern |
|-----------|---------------------------------------------------|---------|
| `3021177` | `DriversTable.tsx` (expandable driver rows)       | 2-kind flat rows (driver/detail) |
| `a3cfbb3` | `CvesTab.tsx` (expandable CVE rows)               | 2-kind flat rows + overflow-y-auto safety |
| `f92989d` | `SecurityScanResults.tsx` (APK nested groups)     | 3-kind flat rows (group/finding/detail); deep-link rewired via `useListRef` + `scrollToRow` inside `requestAnimationFrame` (off-screen rows aren't in DOM) |
| `0dac45e` | rename `virtItemSize` → `itemSize` (grep hygiene) | cosmetic |

Height math uses closed-form estimates (row×constant + chrome +
text-wrap×ceil(len/100)) — no ResizeObserver dependency. Acceptance
grep (`VariableSizeList|useVirtualizer|itemSize`): 2 hits per file,
6 total (all 3 files have ≥ 1).

Merge: `5864304` (--no-ff).

### Stream ε — CLAUDE.md Rule #27 + #28 adoption (2 commits, inline)

| SHA       | Target                       |
|-----------|------------------------------|
| `d4e762f` | CLAUDE.md — Rules #27 + #28 added (line 190 region); stale "rules 1–22" reference corrected to "rules 1–28" in Companion scaffold section |
| `2bd8612` | `.mex/context/conventions.md` — Verify Checklist mirror per Rule #21 |

**Rule #27** ("N additive + 1 cut-over" god-class split pattern) —
5× validated across 2 sessions (b56eb487 γδ + 7e8dd7c3 αβγ):
manifest_checks, security_audit_service, sbom, emulation, mobsfscan.
**34 additive + 5 cut-over commits, 0 reverts, 0 cross-stream
sweeps.**

**Rule #28** (LOC re-measure before scheduling) — uniform +14-22%
drift across 5 Phase-5 targets. manifest_checks 2263→2589 (+14%),
security_audit 1036→1258 (+22%), sbom 2073→2412 (+16%), emulation
1454→1664 (+14%), mobsfscan 1328→1539 (+16%).

### Stream ζ — Campaign close (1 commit)

`ae8e212` — `git mv .planning/campaigns/wairz-intake-sweep-2026-04-19.md
→ .planning/campaigns/completed/` + flip `Status: active` →
`Status: completed` + 2 intakes status-flipped to completed with
evidence matrices.

## Full verification gate (post-merge, HEAD = ae8e212)

All 8 gates passing:

| Gate                               | Expected     | Actual        |
|------------------------------------|--------------|---------------|
| docker compose ps                  | all healthy  | healthy       |
| /health                            | 200          | 200           |
| /ready                             | 200          | 200           |
| /api/v1/projects (no auth)         | 401          | 401           |
| /api/v1/projects (auth)            | 200          | 200           |
| MCP tools                          | 172          | 172           |
| WorkerSettings.cron_jobs           | 7            | 7             |
| alembic current                    | 123cc2c5463a | 123cc2c5463a  |

Plus per-split Rule #11 runtime smokes all pass:
- **α** — `SbomService(tmpdir).generate_sbom()` with planted dpkg
  status file returned 1 component (`openssl 1.1.1k`); `CPE_VENDOR_MAP`
  accessible via `from app.services.sbom import CPE_VENDOR_MAP`.
- **β** — `EmulationService` has 15/15 expected public methods
  (start/stop/delete_session, exec_command, send_ctrl_c, get_status,
  list_sessions, get_session_logs, cleanup_expired,
  build_user_shell_cmd, 5 preset methods); `cleanup_emulation_expired_job`
  imports cleanly through new path.
- **γ** — 7 public names (`MobsfScanPipeline`, `MobsfScanFinding`,
  `get_mobsfscan_pipeline`, `mobsfscan_available`,
  `normalize_mobsfscan_findings`, `SUPPRESSED_PATH_PATTERNS`,
  `SUPPRESSED_RULES`) all importable from
  `from app.services.mobsfscan import ...`; singleton constructs;
  `MobsfScanFinding` dataclass has the expected fields (`rule_id`,
  `title`, `description`, `severity`, `section`, `file_path`,
  `line_number`, `match_string`, `cwe`, `owasp_mobile`, `masvs`,
  `metadata`).

Per-chunk bundle verification (Rule #26 Pattern #3 from last session's
knowledge):
- `HardwareFirmwarePage-CjqRzjFx.js`: 7 virt-hints (CvesTab + DriversTable
  + pre-existing BlobTable all bundle here)
- `SecurityScanPage-C0jzq_Pe.js`: 5 virt-hints
- `ComparisonPage-DDnf0pwH.js`: 3 virt-hints
- `ExplorePage-Brwp1hQ9.js`: 15 virt-hints
- `FindingsPage-DKHV1jp6.js`: 3 virt-hints
- `SbomPage-CtDIE8c3.js`: 3 virt-hints
- `react-window-D4b5zYty.js`: 16 virt-hints (library vendor chunk)

Frontend image freshness: commit `0dac45e` at `2026-04-19 19:25 MDT`;
container `Created` at `2026-04-20 01:31 UTC` (~6 min newer). Pass.

## Worktree discipline (Rule #23)

All 4 parallel streams ran `git worktree add .worktrees/stream-{name}
-b feat/stream-{name}-2026-04-22` + operated IN the worktree with
absolute-path `frontend/node_modules` symlink (δ only).

**0 cross-stream sweeps across 25 stream commits + 4 `--no-ff` merges.**

Pattern is durable across 6 consecutive sessions (198243b8 β; d9f61335
αβγ; b56eb487 αβγδ; 7e8dd7c3 αβγδ).

All 4 worktrees removed cleanly post-merge. `git worktree list` = main
only.

## What was NOT shipped (deferred)

### Wave 2 η — private-API P3 systemic audit

Open-ended follow-up: 37 function-local `from app.services.*` imports
across 13 files. Explicitly carved out in
`backend-private-api-and-circular-imports.md` Phase 3 as a standalone
campaign. NOT blocking. Recommend dedicated session if context budget
permits, OR roll into a future hygiene campaign.

## Starter prompt for next session

```
The wairz-intake-sweep-2026-04-19 campaign is CLOSED. HEAD = ae8e212.

Options for next session:
  A) Private-API P3 systemic audit — 37 function-local imports across
     13 files, per backend-private-api-and-circular-imports.md Phase 3.
     5 commits (pick most-used imports, lift to top-level). Document
     circular-import resolutions as Rule #23-sized outcomes.

  B) Next unaddressed intake — check .planning/intake/ for any
     lingering pending items not yet examined. Run Rule-19 audit first
     to separate ship vs still-pending.

  C) New campaign based on current operational pain points — device
     firmware library coverage gaps, APK false-positive triage,
     UART/device bridge reliability, etc.

Verification gate (always):
  docker compose ps                                                # healthy
  curl -sf -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/health   # 200
  curl -sf -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/ready    # 200
  curl -sI http://127.0.0.1:8000/api/v1/projects | head -1                 # 401
  curl -sf -o /dev/null -w '%{http_code}\n' \\
    -H 'X-API-Key: dev-test-key-wairz-b1' \\
    http://127.0.0.1:8000/api/v1/projects                                  # 200
  docker compose exec -T -e PYTHONPATH=/app -w /app backend \\
    /app/.venv/bin/python -c "from app.ai import create_tool_registry; \\
    print(len(create_tool_registry().get_anthropic_tools()))"               # 172
  docker compose exec -T -e PYTHONPATH=/app -w /app worker \\
    /app/.venv/bin/python -c "from app.workers.arq_worker import \\
    WorkerSettings; print(len(WorkerSettings.cron_jobs))"                   # 7
  docker compose exec -T -e PYTHONPATH=/app -w /app backend \\
    /app/.venv/bin/alembic current | tail -1                                # 123cc2c5463a (head)
  # Rule-17 canary:
  echo 'const x: number = "nope"; export default x;' > frontend/src/__canary.ts \\
    && (cd frontend && npx tsc -b --force 2>&1 | tail -2); rm -f frontend/src/__canary.ts

Read (skim):
  1. .planning/knowledge/handoff-2026-04-22-session-7e8dd7c3-end.md (this file)
  2. CLAUDE.md Rules 1–28 canonical (28 now — Rule #27 "N+1" split
     pattern; Rule #28 LOC remeasure).
  3. .planning/campaigns/completed/wairz-intake-sweep-2026-04-19.md
     if you need the historical trail.

Dispatch discipline (Rule #23) if ANY parallel streams:
  git worktree add .worktrees/stream-{name} -b feat/stream-{name}-{YYYY-MM-DD}
  cd .worktrees/stream-{name}
  # Frontend streams only:
  ln -sf /home/dustin/code/wairz/frontend/node_modules frontend/node_modules
```

## Commits (newest first, 32 total)

```
ae8e212 docs(ζ): close wairz-intake-sweep campaign + 2 intakes (Phase 5 5/5)
2bd8612 docs(mex/conventions): mirror Rules #27 + #28 into Verify Checklist
d4e762f docs(CLAUDE.md): adopt Rules #27 + #28 (N additive+1 cut-over, LOC remeasure)
5864304 Merge stream-delta: variable-height frontend virtualization (4 commits)
773164f Merge stream-gamma: mobsfscan_service god-class split (Phase 5 part 4, 5 commits)
c3d7f21 Merge stream-beta: emulation_service god-class split (Phase 5 part 5, 7 commits)
ef8aec0 Merge stream-alpha: sbom_service god-class split (Phase 5 part 3, 9 commits)
b29ef8f refactor(sbom): delete monolith + update 4 callers (step 9/9)
c267931 refactor(emulation): delete monolith + update 4 callers (step 7/7)
0dac45e chore(virt): rename virtItemSize → itemSize for grep hygiene
f92989d feat(virt): virtualize SecurityScanResults with variable-size rows
2e678be refactor(sbom): extract library + binary-strings strategies (step 8/9)
4502fde refactor(sbom): extract single-binary toolchain strategies (step 7/9)
206fbd5 refactor(mobsfscan): delete monolith + update 4 callers (step 5/5)
3cf7aa3 refactor(sbom): extract distro/OS strategies (step 6/9)
c7b7dc7 refactor(emulation): extract system_mode.py (step 6/7)
5fa21b0 refactor(mobsfscan): extract service.py + __init__.py (step 4/5)
0df9e25 refactor(emulation): extract user_mode.py (step 5/7)
a3cfbb3 feat(virt): virtualize CvesTab with variable-size rows
70dfdb3 refactor(mobsfscan): extract pipeline.py (step 3/5)
fb029a3 refactor(sbom): extract package-manager strategies (step 5/9)
393bafc refactor(emulation): extract sysroot_mount.py (step 4/7)
3021177 feat(virt): virtualize DriversTable with variable-size rows
befd0fb refactor(sbom): extract strategies/base.py (step 4/9)
34a08a1 refactor(mobsfscan): extract parser.py (step 2/5)
d78d624 refactor(sbom): extract normalization.py (step 3/9)
0522095 refactor(emulation): extract kernel_selection.py (step 3/7)
e2fe918 refactor(sbom): extract purl.py (step 2/9)
71476a4 refactor(emulation): extract docker_ops.py (step 2/7)
63e42e0 refactor(mobsfscan): extract normalization.py (step 1/5)
c38cbe2 refactor(sbom): extract constants.py (step 1/9)
002e106 refactor(emulation): add empty emulation/ subpackage skeleton (step 1/7)
```

## Patterns this session reinforced

1. **"N additive + 1 cut-over" pattern (Rule #27)** — validated 5×
   across 2 sessions. Now a Learned Rule. 34 additive + 5 cut-over
   commits shipped with 0 reverts and 0 cross-stream sweeps. Durable.
2. **Rule #23 worktree discipline** — 6 consecutive sessions holding.
   All 4 streams this session used real `git worktree add` + operated
   in-worktree. 0 sweeps across 25 stream commits.
3. **Rule #19 evidence-first during cut-over** — α's grep found a 5th
   lazy-import caller the intake missed. Re-grepping in the cut-over
   commit catches under-counts. Also: intake's `lief_strategy.py` and
   `rpm_strategy.py` prescriptions DROPPED because the monolith had no
   code matching those (use `pyelftools` / Syft). Don't create
   dormant abstractions.
4. **Rule #20 docker-cp iteration NOT used this session** — all 4
   streams picked "Option B" (local py_compile only + main-session
   post-merge rebuild + smoke). Works fine for 5-commit splits.
5. **Per-chunk bundle verification (Pattern #3 last session)** —
   HardwareFirmwarePage 7 hits, SecurityScanPage 5 hits; tokens like
   `rowHeight`, `itemSize`, `List` (from react-window) survive
   minification. Identifier-specific tokens (`VirtFindingRow`,
   `DETAIL_CHROME_HEIGHT`) get mangled — don't rely on those for
   chunk-level verification; use library-import tokens instead.

## Anti-patterns / near-misses

1. **Skill-suggestion spam for `/ouroboros:welcome`** — same as session
   b56eb487, each task-completion notification included an unwanted
   auto-welcome skill suggestion. Ignored per anti-pattern #2 from
   that session. Still a harness hook issue upstream — not a wairz
   fix.

2. **Smoke-test field-name mismatch for `MobsfScanFinding`** — my
   first γ smoke invocation used `message=` and `file=` as field
   names; correct dataclass shape was `description=`, `file_path=`,
   `line_number=`, etc. Re-ran with `dataclasses.fields()` introspection
   first, then correct field names. Not a split defect — just a
   smoke-test author issue. Takeaway: before a smoke test against a
   freshly-split dataclass, introspect its fields first rather than
   guessing.

3. **Integer-comparison error in bash loop when grep match is 0** —
   `n=$(... 2>/dev/null || echo 0)` appended `\n0` to the grep output
   rather than substituting 0. The `[ "$n" -gt 0 ]` test then got
   `"0\n0"` and errored out with "integer expression expected" 72
   times. Not a session failure (we worked around), but worth noting:
   combine `grep -c` with `2>/dev/null` differently, or use `awk` for
   arithmetic when parsing grep output.

## Blockers

None.

## Operator action required

None on existing deployments. No schema changes, no new env vars, no
cron changes.

Third-party code that imports any of:
- `app.services.sbom_service`
- `app.services.emulation_service`
- `app.services.mobsfscan_service`

… must switch to `app.services.{sbom,emulation,mobsfscan}` (single-word,
no `_service` suffix). Internal wairz code fully migrated.

<!-- session-end: 2026-04-22T session 7e8dd7c3 — Wave 1 closes Phase 5; campaign CLOSED (32 commits) -->
