# Anti-patterns: Phase 5 Cache Refactor + Private-API / Cycle Break (session 93a4948d)

> Extracted: 2026-04-19
> Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md` (active — Phase 5 2/3)

## Failed Patterns

### 1. Intake file list as complete scope (list rot)
- **What was done:** Intake `backend-cache-module-extraction-and-ttl.md` enumerated 7 call sites in its `Files` section. Had the session trusted that list, 3 additional query-and-upsert sites (`ai/tools/filesystem.py` component_map, `routers/component_map.py`, `mcp_server.py` save_code_cleanup) would have been left unmigrated — the acceptance grep would have failed.
- **Failure mode:** Intake files are written at intake-creation time; code drifts, new sites get added, and the file list silently ages out. A partial migration is worse than no migration because the half-migrated state inherits the bugs of both patterns.
- **Evidence:** Session grep found 10 sites; intake listed 7. 43% scope delta.
- **How to avoid:** Always run the acceptance grep BEFORE starting, not after. Treat `Files:` in any intake as a starting hint, never a contract. This lesson lives in CLAUDE.md Rule #22 ("grep all sites first, typecheck every 1–2 edits, use the intake's acceptance grep as the completion check") but was not fully internalised for intake-driven work until this session.

### 2. Live-DB-deleting smoke test
- **What was done:** Integration smoke test called `invalidate_firmware(session, existing_firmware_id)` against a real production firmware's ID to verify the helper. Deleted 3 cache rows — 2 test rows plus 1 legitimate `firmware_metadata` row that had nothing to do with the smoke test.
- **Failure mode:** The deleted row regenerates on next scan, so impact is minor — but the test was more destructive than necessary. If the test had used a firmware with expensive-to-regenerate cache (Ghidra decompilations, JADX class dumps), cost would have been meaningful.
- **Evidence:** Session smoke-test output `invalidated count=3 (>=2 expected)` followed by the post-test AnalysisCache row-count check showing `firmware_metadata: 10` (one less than before).
- **How to avoid:** For integration smoke tests that mutate, either: (a) create a throwaway test firmware row with a dedicated project_id at test start, (b) constrain the invalidation helper call path to `operation IN (...)` so only test rows get deleted, or (c) use a dedicated pytest database or transaction-rollback fixture. Ad-hoc inline smoke against prod data is fine for reads but risky for writes.

### 3. Function-local imports re-introduced during migration
- **What was done:** The `mobsfscan_service` cache migration commit (`909101c`) kept `from app.services import _cache` INSIDE method bodies, mirroring the pre-existing function-local `from app.models.analysis_cache import AnalysisCache` that had been there. This recreated the same anti-pattern the cycle-break work was trying to eliminate.
- **Failure mode:** Function-local imports hide cycles from static analysis and duplicate the import on every call. Needed a follow-up commit (`835dd70` "hoist `_cache` import to module level") to clean up.
- **Evidence:** Commit diff of `909101c` vs `835dd70`.
- **How to avoid:** When replacing a function-local import, ALWAYS replace with top-level unless there's a documented cycle reason. A "maintaining convention" rationale is too weak — the convention should be bent back toward top-level.

### 4. Settings class-shape change without restart awareness in commit message
- **What was done:** Added `analysis_cache_retention_days: int = 30` to `Settings` in commit `d100595`. This is a Rule #20 class-shape change to a `@lru_cache`'d `get_settings()` instance. The commit message did not flag this.
- **Failure mode:** If a later session cherry-picked this commit into a running container and tried to call `get_settings().analysis_cache_retention_days` before rebuilding, it would raise `AttributeError` — the symptom described in Rule #20. Session mitigated it with an end-of-session rebuild, but the commit message leaves no trace of the requirement.
- **Evidence:** `d100595` commit message — no restart/rebuild note despite the Settings field addition.
- **How to avoid:** For commits that add/remove fields on cached class instances (Settings, @dataclass singletons, SQLAlchemy model metadata), include a footer line: `Requires: backend+worker rebuild (class-shape change, Rule #20).` Harness.json could flag this via a quality rule that pattern-matches `class Settings(BaseSettings):` edits without a rebuild note.

### 5. Stale `AnalysisCache` docstring references post-migration
- **What was done:** Docstrings in `mobsfscan_service.py`, `jadx_service.py`, `android_bytecode.py` still mention `"AnalysisCache"` by name even though the code no longer imports it. Examples: `jadx_service:4`: "Results are cached in the AnalysisCache table"; `mobsfscan_service:1154`: "Check AnalysisCache for prior mobsfscan results".
- **Failure mode:** Docstring references rot into lies if the underlying `AnalysisCache` model gets renamed (unlikely) or if the caching path changes enough that the docstring misleads future readers. Low-severity, but real.
- **Evidence:** `grep -n 'AnalysisCache' backend/app/services/mobsfscan_service.py backend/app/services/jadx_service.py` shows 9+ comment/docstring lines still referencing the old name.
- **How to avoid:** When migrating all code paths off a symbol, grep docstrings too (`grep -n 'AnalysisCache' -- '*.py'` hits both). Either rewrite the docstrings to reference the new module (`app.services._cache`) or the underlying table (`analysis_cache`), or leave them if the reference is semantically correct (talking about the TABLE, not the MODEL). Session judged these as table-references (acceptable) — but the distinction should be deliberate.
