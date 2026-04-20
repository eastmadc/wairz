# Anti-patterns: Strategic Next-Steps Session (2026-04-19)

> Extracted: 2026-04-19 (session 480666ce)
> Campaign: none (post-close follow-on to `wairz-intake-sweep-2026-04-19.md`)

## Failed Patterns

### 1. Research-agent "stateless wrapper" assumption without reading the class body
- **What was done:** Agent 2 (tactical research) claimed the `GhidraAnalysisCache` singleton was a "vestigial stateless wrapper" based on reading `get_analysis_cache()` signature + the fact that `_cache.py` module helpers existed. Recommended the refactor as "~90 min mechanical rename" with ROI score 5.
- **Failure mode:** Missed the `__init__` body: `self._analysis_locks: dict[str, asyncio.Event] = {}` + `self._lock = asyncio.Lock()`. The class held REAL concurrency state — a per-binary-SHA mutex guaranteeing only one Ghidra run per binary. "Drop the singleton" as the research framed it would have removed the concurrency guard, corrupting concurrent analyses.
- **Evidence:** Caught in-session at `ghidra_service.py:198-216` read, before any edit. Refactor reshaped to "re-home state to module scope with lazy-constructed `_lock`" instead of deletion.
- **How to avoid:** Research-agent briefs should REQUIRE reading the `__init__` body + field declarations of any class named as "vestigial" / "wrapper" / "stateless." Grep for `self\._` assignments. If any exist, call it "stateful" and update the scope estimate.

### 2. Research-agent under-scoped caller audit (off by ~10%)
- **What was done:** Agent 2 enumerated 18 call sites across 4 files. Design assumed a ~60-min refactor.
- **Failure mode:** `routers/analysis.py` had 4 more `get_analysis_cache()` call sites + a top-level import. Agent's grep must have missed the routers/ path or stopped at an incorrect limit. Real scope: 22 call sites across 5 files, ~43 `cache.X(...)` method invocations.
- **Evidence:** Session 480666ce `grep -rn 'get_analysis_cache\|_analysis_cache' backend/app/` pre-refactor — 23 hits (including 1 singleton self-reference). Agent's report said 18.
- **How to avoid:** Always re-run the grep in-session before first edit, per Rule #22. Cross-check agent's file list against `backend/app/{services,routers,ai/tools,workers}/` — a full directory walk, not a targeted grep.

### 3. Bulk sed leaves placeholder comments that violate the comments policy
- **What was done:** First-pass sed replaced `    cache = get_analysis_cache()` with `    # (cache alias removed — use ghidra_service.X directly)` to preserve line numbers and visually mark the change.
- **Failure mode:** CLAUDE.md "Default to writing no comments" — placeholder comments are noise that future readers have to interpret. They don't explain WHY, they explain what used to be there.
- **Evidence:** Second sed pass required to strip `# (cache alias removed ...)` lines. Would have landed in the first-pass commit if not caught.
- **How to avoid:** When doing bulk sed for a variable-rename refactor: plan for line-removal (not replacement) from the start. Use `sed -i '/pattern/d'` to delete the marker line, not replace-then-strip.

### 4. Test patches of soon-to-be-removed symbols don't fail at import time
- **What was done:** Commit `a7bfe47` removed `get_analysis_cache` from `ghidra_service.py`. Module import still works (the name just isn't there). 10 test files patched `"app.ai.tools.X.get_analysis_cache"` via `mock.patch`. All passed `py_compile`, passed Python imports, passed the Rule #11 runtime smoke.
- **Failure mode:** `mock.patch` only resolves the target AttributeError at __enter__ time — i.e. during test RUN, not collect. The refactor looked clean at commit time and broke 10 tests when the next pytest invocation happened.
- **Evidence:** Stable-subset pytest run caught it: 7 binary_tools failures + 3 taint_llm failures — all `AttributeError: module has no attribute 'get_analysis_cache'` from `mock.patch.__enter__`. Fixed in `4cb7bdd`.
- **How to avoid:** After removing a public name from `backend/app/services/X.py`, ALWAYS `grep -rn 'X\.removed_name' backend/tests/`. If any hits, update those test patches in the SAME commit as the removal. Adds this to Rule #22's mechanical-migration checklist: "grep tests/ for patch-target strings of removed symbols."

### 5. Initial CI workflow assumed tests were in the container image
- **What was done:** First draft of `.github/workflows/backend-tests.yml` ran `docker compose exec -T -w /app/backend backend pytest` — assumed `/app/backend/tests/` existed.
- **Failure mode:** `tests/` is excluded from the production image via `backend/.dockerignore` (Q9). The `exec -w /app/backend` failed with "no such file or directory."
- **Evidence:** First local dry-run failed immediately. Caught before commit.
- **How to avoid:** When authoring a CI workflow that runs pytest against a production image, explicitly `docker cp backend/tests container:/app/tests` as the first step. Document the `.dockerignore` exclusion in a workflow comment so the next author doesn't re-discover.

### 6. Initial CI workflow assumed dev deps were in the production image
- **What was done:** First draft of the workflow called `pytest` directly via `/app/.venv/bin/python -m pytest`.
- **Failure mode:** `pytest` + `pytest-asyncio` live under `[dependency-groups].dev` in `pyproject.toml`, not in production deps. Production image does NOT install them. Got `No module named pytest`.
- **Evidence:** Caught locally via `docker compose exec backend /app/.venv/bin/python -m pytest tests/ --collect-only` — clean-slate failure.
- **How to avoid:** `pip install --quiet pytest pytest-asyncio` inside the backend container BEFORE the pytest step in the workflow. Alternative: move these to `dependencies` (bloats production image — reject). Alternative: build a `Dockerfile.test` with dev deps (adds CI complexity — reject for now).

## Referenced Rules

- CLAUDE.md Rule #19 — evidence-first before writing remediation code
- CLAUDE.md Rule #22 — grep all sites first; applies transitively to `tests/` for patch targets
- CLAUDE.md comments policy — "Default to writing no comments"
- `.dockerignore` Q9 — `tests/` excluded from production image
