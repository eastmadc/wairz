# Patterns: Strategic Next-Steps Session (2026-04-19)

> Extracted: 2026-04-19 (session 480666ce)
> Campaign: none (post-close follow-on to `wairz-intake-sweep-2026-04-19.md`)
> Postmortem: none — session commits only
> Related /learn outputs: `wairz-rule29-timeout-alignment-research-2026-04-22-patterns.md`,
> `wairz-frontend-axios-timeout-sweep-2026-04-22-patterns.md`

## Context

Open-ended "deep research next steps" prompt after the big intake-sweep
campaign closed (HEAD `2bd8612`). Shipped 6 commits across 4 distinct
work items: intake #2 Rule #19 no-op close, Q4 Ghidra singleton refactor,
backend pytest CI gap closure (new), and emulation+fuzzing 202+polling
campaign queued (not executed). All four items surfaced from a parallel
pair of research agents (strategic + tactical) whose output was then
triaged against real codebase evidence.

## Successful Patterns

### 1. Parallel research agents as decision substrate
- **Description:** For "what should we do next?" queries, spawn TWO research agents in parallel: one strategic (what new campaigns should exist?), one tactical (which partial intakes to pick up?). Brief each with scope constraints forbidding overlap, full evidence-gathering instructions, and a concrete output format.
- **Evidence:** Session 480666ce spawned Agent 1 (strategic, ranked 6 candidate campaigns with composite scores) and Agent 2 (tactical, verdict on 3 partial intakes). Both returned in <6 min wall clock, total $X budget. User then chose "all three sequentially" with full visibility into the tradeoffs.
- **Applies when:** Session-level "what's next" decisions after a campaign closes. NOT for narrowly-scoped questions (use /research skill, single agent).

### 2. Rule #19 "evidence-first" applied to CI pre-existing failures
- **Description:** When a new CI job surfaces N pre-existing failures (~189 in 18 files this session), do NOT block the workflow addition until they're fixed. Ship a green baseline on the STABLE subset (60 files, 1086 tests) with explicit `--ignore=` flags, AND author a follow-up intake documenting each excluded file. Preserves trustworthy green signal while honoring measurement.
- **Evidence:** Commit `ea5f1c7` shipped `.github/workflows/backend-tests.yml` with 15 `--ignore=` flags; companion intake `.planning/intake/backend-pytest-unstable-tests.md` catalogued the failures per-file with triage categories.
- **Applies when:** Adopting a new CI gate on legacy code. Analog to Rule #19's "measure before prescribing" — measure what's failing, gate on what you CAN gate, intake the rest.

### 3. Mock-patch strategy for module-level-function refactors
- **Description:** When converting a class-singleton to module-level functions, tests patched via `patch("module.get_singleton", return_value=mock)` break silently (symbol removal doesn't raise ImportError — only AttributeError at patch-entry). Fix pattern: `patch("module.imported_submodule", replacement_mock)` (positional 2nd arg, not `return_value=`). The replacement_mock replaces the module name binding, preserving attribute access shape: callers' `imported_submodule.X()` resolves to `replacement_mock.X()`.
- **Evidence:** Commit `4cb7bdd` updated 10 test patches across `test_binary_tools.py` (7) and `test_taint_llm.py` (3). Before: `patch("app.ai.tools.binary.get_analysis_cache", return_value=mock_cache)`. After: `patch("app.ai.tools.binary.ghidra_service", mock_cache)`. Test suite pass count rebounded 28/28 + 39/39.
- **Applies when:** Any refactor that replaces a class-singleton wrapper with direct module-level function calls. Grep `backend/tests/` for patch targets in the same session as the src change.

### 4. Lazy-construct asyncio.Lock at module scope
- **Description:** Module-level `_lock = asyncio.Lock()` at import time CAN fail in strict async contexts ("no running event loop"). Safe pattern: module-level `_lock: asyncio.Lock | None = None` + helper `def _get_lock() -> asyncio.Lock: global _lock; if _lock is None: _lock = asyncio.Lock(); return _lock`. First `await lock:` call constructs the Lock inside the running loop.
- **Evidence:** `ghidra_service.py:196-216` (commit `a7bfe47`). Avoided "RuntimeError: no running event loop" during module import from worker processes where the loop starts later than the `app.services` package import.
- **Applies when:** Moving per-class `self._lock = asyncio.Lock()` state to module scope during a singleton-drop refactor.

### 5. `docker cp` + in-container pytest for CI-workflow dev-loop
- **Description:** Iterate on a new pytest-in-CI workflow WITHOUT running on GitHub: `docker compose up -d backend --wait` (already running), `docker cp backend/tests wairz-backend-1:/app/tests`, `docker compose exec -T backend /app/.venv/bin/pip install --quiet pytest pytest-asyncio`, `docker compose exec -T -w /app -e PYTHONPATH=/app backend .../pytest tests/`. Matches Rule #20 exception — one-file additive changes don't need a rebuild.
- **Evidence:** Session 480666ce iterated 4 times on the ignore-list and pytest flags in <2 minutes each, vs. ~6-8 minute round-trip via a push-and-wait CI run. Final workflow committed `ea5f1c7` matched local validation exactly (1086 passed).
- **Applies when:** Authoring or tuning a GitHub Actions workflow whose body is shell commands running inside docker-compose services.

### 6. Campaign-queue-but-not-execute pattern
- **Description:** When a research pass identifies a high-ROI next campaign BUT the current session has already shipped 3 other items, queue the campaign as a `.planning/campaigns/*.md` file with `Status: queued` (not `completed`, not `in-progress`). Include: motivation with exact file:line evidence, phase table, end-conditions, risks, decision log, and pickup instructions. Next session starts with `cat .planning/campaigns/emulation-fuzzing-202-polling.md` and hits the ground running.
- **Evidence:** Commit `6ef6a56` — `emulation-fuzzing-202-polling.md` 111 lines, 2 streams specified, 8 end-conditions, 5 risks, 4 decision-log entries. Next session pickup is a single file-read.
- **Applies when:** Strategic research identifies ≥2 high-ROI candidates and the session budget can only absorb 1. Queue the others with full evidence so the next session doesn't re-do the research.

### 7. Campaign-close audit via Rule #19 before carrying partials forward
- **Description:** Before treating a `status: partial` intake as pending work, re-walk the intake's listed deferred items against actual in-tree state. N-of-M items may have silently shipped in intervening commits. Close the intake as `status: completed` with an evidence matrix in frontmatter; carry forward only the genuinely-pending residual as a new brief (or documented deferral if no consumer exists).
- **Evidence:** Commit `4a3dd29` — `infra-secrets-and-auth-defaults` had 5 deferred items; 4 had silently shipped across `83e31c8`, `b9f438f`, and README.md:332-378. Only `docker-compose.prod.yml` remained, with README explicitly documenting it as "roadmap but not yet in-tree" — no live consumer. Intake closed; no new brief created. Net: avoided scheduling phantom work.
- **Applies when:** An intake is >48 hours old and its status is still `partial`. Always re-measure before acting.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Close intake #2 as documented no-op, don't create new brief | Residual (`docker-compose.prod.yml`) has NO in-tree consumer; README already documents as roadmap. Rule #19: don't write dormant code / dormant intakes for consumers that don't exist. | 1 commit, 54 lines frontmatter update; no drift risk. |
| Q4 as a single atomic commit (not N-additive + 1-cutover) | File 696 LOC — below Rule #27's ≥1000 LOC threshold. 22 call sites across 5 files, all mechanical + grep-verifiable. Rule #25 explicitly allows single-atomic-change as one commit. | 1 refactor commit + 1 test-patch commit + 1 intake-close commit. Bisect-clean. |
| CI workflow ignores 18 files instead of fixing them | Fixing 189 pre-existing failures is a multi-session campaign; blocking CI addition on it delays the green-signal benefit for the 1086 stable tests indefinitely. Rule #19 analogy: measure now, intake the red tide, ship the green signal. | Commit `ea5f1c7` + follow-up intake `backend-pytest-unstable-tests.md`. CI green on day 1. |
| Queue emulation+fuzzing campaign, don't execute | 4 tasks already in-flight this session (Rule #25 one-session-one-scope discipline). Research was already done; queuing it costs 1 commit + 111 lines, saves the next session's research round. | Commit `6ef6a56`. Pickup is a `cat` away. |
| Accept research agent's scope undercount in-session | Agent 2 said "18 call sites"; `grep` found 22. Rule #22 discipline caught it before first edit. Design adapted from "quick mechanical rename" to "re-home class state to module scope with lazy-lock." | Refactor landed clean; undercount documented in quick-wins intake closure. |

## References

- Rule #19 (CLAUDE.md) — evidence-first before writing remediation code
- Rule #22 — grep all sites first, typecheck every 1-2 edits
- Rule #25 — commit each sub-task independently
- Rule #27 — N-additive + 1-cutover (did NOT apply here, file <1000 LOC)
- Commit range: `4a3dd29..6ef6a56` (6 commits)
