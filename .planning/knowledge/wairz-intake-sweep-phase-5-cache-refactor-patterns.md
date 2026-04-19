# Patterns: Phase 5 Cache Refactor + Private-API / Cycle Break (session 93a4948d)

> Extracted: 2026-04-19
> Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md` (active — Phase 5 2/3)
> Postmortem: none (sub-campaign scope; overall campaign still active)
> Commit range: `d100595..b2706d1` (14 commits, +1,012/-319 LOC, 23 files)

## Successful Patterns

### 1. Rule-22 grep-everything-first before migration
- **Description:** Before starting the 7-site cache migration the intake listed, ran `grep -rn 'AnalysisCache' backend/app/ --include="*.py"` and found **10** query-and-upsert sites — 3 beyond the intake's file manifest (`ai/tools/filesystem.py` component_map, `routers/component_map.py`, `mcp_server.py` save_code_cleanup). Widened scope at the start, not after. Two additional AnalysisCache references (`export_service.py`, `import_service.py`) were deliberately left alone — they represent a different bulk pattern, not the query-and-upsert pattern.
- **Evidence:** Handoff file "Intake scope vs. delivered scope" section notes 43% scope widening pre-implementation.
- **Applies when:** Any "migrate N call sites to helper Y" refactor. The intake's `Files` section is a starting point, never an acceptance grep.

### 2. `exists_cached` helper distinct from `get_cached`
- **Description:** 2 of 10 migrated call sites (`ghidra_service._is_analysis_complete`, `jadx_service._is_decompilation_complete`) only needed a presence probe, not the full result. Added `exists_cached` as a separate helper that selects `id` instead of `result` — avoids pulling multi-MB JSONB blobs for a boolean.
- **Evidence:** `backend/app/services/_cache.py:exists_cached`; compiled SQL contains `analysis_cache.id` without `analysis_cache.result` (verified in test_cache_module.py).
- **Applies when:** Any cache API where "is this cached?" is a distinct question from "what's the cached value?" and the value is large (JSONB, BLOB, multi-column SELECT).

### 3. Firmware-wide cache keys via `binary_sha256 IS NULL`
- **Description:** `firmware_metadata` and `component_map` cache whole-firmware state with no specific binary. PostgreSQL treats NULL as distinct in unique indexes, so these coexist with per-binary rows under the same `idx_cache_lookup`. Helper signature `binary_sha256: str | None = None` emits `binary_sha256 IS NULL` in WHERE when None, `binary_sha256 = :sha` otherwise — one function handles both cases.
- **Evidence:** `backend/app/services/_cache.py:get_cached/store_cached`; regression test `test_firmware_wide_key_uses_is_null` verifies the emitted SQL.
- **Applies when:** A JSONB cache table is shared between per-object and whole-parent entries, and the parent FK is enough to key the latter.

### 4. Docker cp + exec iteration between rebuilds
- **Description:** Per CLAUDE.md Rule #20, single-file code edits can be validated in the running backend container via `docker cp host:file container:/app/file` + `docker compose exec backend /app/.venv/bin/python -c "..."` without a full `docker compose up -d --build`. Session did ~15 cp-then-exec iterations across all 10 migration commits; one full rebuild at session end. Saved ~45 min vs. per-commit rebuilds.
- **Evidence:** Every migration commit block in the session transcript shows the cp-exec-commit sequence; single `docker compose up -d --build backend worker` at the end.
- **Applies when:** Pure-Python diffs that don't add/remove fields on cached class instances (Settings, @dataclass singletons, SQLAlchemy models). One class-shape change this session (`analysis_cache_retention_days: int = 30` in Settings) forced the end-of-session rebuild.

### 5. One-commit-per-sub-task (Rule #25) in practice
- **Description:** 14 commits averaging 30-50 LOC each instead of one omnibus. Per-site commits (`5808555 ghidra`, `b5f2432 cwe_checker`, etc.) are individually revertable; `git bisect` would land on the exact culprit sub-task if a regression appeared later.
- **Evidence:** `git log 3977a9c..HEAD` shows 14 granular commits; rollback paths in the handoff give per-sub-task revert commands.
- **Applies when:** Any migration with ≥3 independently-verifiable slices. Each slice should have its own acceptance grep or smoke check.

### 6. Evidence-first close-out of shipped intakes (Rule #19 applied)
- **Description:** Before starting Option B's 6-session campaign spin-out, grepped for MCP tool registrations (`backend/app/ai/tools/hardware_firmware.py:379-507`), queried the live DB for blob counts (797), and surveyed git log (`ac6a493..79e083e` — all 5 intake phases already shipped). Closed the intake with a Rule-19 evidence note instead of writing redundant code.
- **Evidence:** `.planning/intake/feature-android-hardware-firmware-detection.md` "Status: Completed" section; no new code written for Phase 6.
- **Applies when:** An intake or seed describes work against a condition that may have silently resolved. Always grep + DB-check before dispatching a campaign.

### 7. Registry + dispatch function instead of private-API rename
- **Description:** Intake prescribed renaming `_scan_credentials` → `scan_credentials` with backward-compat aliases. Instead, added a public `run_scan_subset(root, names, findings?)` dispatcher + `SCANNERS` dict keyed by canonical name. `assessment_service` passes strings `["credentials", "shadow", "crypto_material"]`; internal `_scan_*` stays private. No rename-with-alias dance, no deprecated-name rot.
- **Evidence:** Commit `2a27175` — 38 LOC added to security_audit_service, 13 LOC removed from assessment_service. Zero rename diff.
- **Applies when:** Cross-module API needs to expose a subset of private implementation functions. Beats rename+alias when the caller is better served by "dispatch by name" than by direct reference.

### 8. Per-commit invariant test
- **Description:** `docker compose exec backend python -c "from app.ai import create_tool_registry; print(len(create_tool_registry().get_anthropic_tools()))"` returning 172 ran after every migration commit. Would have caught any import-path breakage within ~2 seconds of the offending commit.
- **Evidence:** Audit log shows the 172-check in repeated exec calls across all 10 migration commits.
- **Applies when:** Refactor touches code paths that module-level import into a critical registry. Invariant must be cheap and deterministic.

### 9. Break cycle at the root via shared-extract, not function-local workaround
- **Description:** `kernel_service` had a function-local `from app.services.emulation_service import _validate_kernel_file` to dodge a module-level cycle. The helper actually lived in `emulation_constants` (re-exported by emulation_service for convenience). Moving `kernel_service` to import from `emulation_constants` directly broke the cycle at the root — which then enabled `emulation_service` to top-level-import `KernelService` without recreating it.
- **Evidence:** Commit `68ecb64`; function-local count dropped 40 → 37.
- **Applies when:** A cycle between two modules exists because one re-exports a symbol defined in a third. Import the symbol from its true home, not from the re-exporter.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| New `_cache.py` module (vs. extend model) | Separation of concerns: model describes shape; service describes access pattern | Clean — no direct AnalysisCache queries in 10 call sites |
| Firmware-wide `binary_sha256=None` support native in helpers | Two intake sites (firmware_metadata, component_map) need it; skipping = 2 un-migrated sites | Worked — `.is_(None)` + compiled-SQL regression test |
| `exists_cached` as distinct helper | Presence probes shouldn't pull multi-MB JSONB | 2 callers; cheap to maintain; explicit intent |
| Delete-then-insert unconditionally (vs. rely on unique constraint) | Idempotency without constraint coupling; fixes latent cwe_checker missing-delete bug | Bug fixed; no downside |
| cleanup_analysis_cache_job @ 06:00 UTC | Avoid collision with sync_kernel@03:00, cleanup_tmp_dumps@04:00, reconcile_firmware_storage@05:00 | Clean stagger, no contention |
| `run_scan_subset(names)` public vs. rename `_scan_*` | Preserves internal conventions; 1 function + 1 dict instead of 3 functions + 3 aliases; no deprecated-name rot | 2-line diff to assessment_service |
| Keep `GhidraAnalysisCache` class as thin shim (not remove) | Class has other responsibilities (concurrency guard, sha256 helper); full replacement not scoped | Appropriate — slimmed methods, kept structure |
| Close Option B via Rule-19 audit (no rewrite) | Phases 1-5 already shipped across 20+ commits; rewriting = dead code | ~6 sessions of redundant work avoided |
| Full backend+worker rebuild ONCE at session end | Rule #8 batch discipline; Rule #20 class-shape caveat for Settings field add | Clean post-rebuild gates; no intra-session stale-container issues |
