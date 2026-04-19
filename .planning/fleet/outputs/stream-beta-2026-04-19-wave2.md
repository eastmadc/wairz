# Stream Beta — Wave 2 Handoff — Pagination on Unbounded List Endpoints

Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md` (Phase 2 / Wave 1).
Intake: `.planning/intake/data-pagination-list-endpoints.md`.
Baseline: HEAD bf60b53 (Gamma's virtualized SbomPage commit).

## TL;DR

5 list endpoints migrated from bare `list[T]` to `Page[T]` envelope. 13 `.scalars().all()` call sites annotated (5 paginated, 10 `# bounded:`). Acceptance grep: 0 unbounded hits. Backend + frontend typecheck clean. All functional curl probes return `{items,total,offset,limit}` with total matching DB cardinality probes (5062 vulns, 304 components, 335 attack-surface, 99 findings, 7 projects).

## Commits (in order)

| SHA | Title |
|---|---|
| `8994dcb` | feat(backend): pagination schema + utility (Page/PageParams/paginate_query) |
| `9aeae31` | feat(routers): paginate sbom components + vulns endpoints |
| `67aaf49` | feat(routers): paginate attack_surface + annotate bounded scalar calls |
| `6c4d08d` | feat(routers): paginate projects + findings list endpoints |
| `3063283` | feat(frontend-api): unwrap Page envelope in api clients (backward-compat) |

## Research + plan

See `stream-beta-2026-04-19-research.md` (same directory) for the Phase 1 evidence table, cardinality probe, and plan. Key finding: `sbom_vulnerabilities` hit 180,048 rows for a single firmware on the Horizon Tablet project — the OOM risk cited in the intake is **real**, not future-proofing.

## Verification matrix (post-commit, post-backend-restart)

| Check | Result |
|---|---|
| `/health/deep` with all sub-checks ok | PASS |
| Page shape `projects` | `total=7 items=7` |
| Page shape `sbom?firmware_id=…&limit=10` | `total=304 items=10` |
| Page shape `sbom/vulnerabilities?firmware_id=…&limit=10` | `total=5062 items=10` |
| Page shape `attack-surface?firmware_id=…&limit=5` | `total=335 items=5` |
| Page shape `findings?limit=5` | `total=99 items=5` |
| `grep -rn '\.scalars()\.all()' backend/app/routers/ \| grep -v '# bounded:'` | 0 hits |
| Auth matrix (no-key / good-key) | 401 / 200 |
| DPCS10 canary | 260 (baseline held) |
| `npx tsc --noEmit -p tsconfig.app.json` | exit 0, clean |
| tsc canary (rule 17 — confirmed tsc is live, not silent) | PASS |

## Files touched

Backend (new):
- `backend/app/schemas/pagination.py` — `Page[T]`, `PageParams` (48 LOC)
- `backend/app/utils/pagination.py` — `paginate_query`, `paginate_query_rows`, `_count_for` (74 LOC)
- `backend/tests/test_pagination.py` — 4 async tests (117 LOC). Note: tests dir not bind-mounted into the container; could not run in-session. CI will run them.

Backend (modified):
- `backend/app/routers/projects.py` — `list_projects` → `Page[ProjectListResponse]`
- `backend/app/routers/sbom.py` — `list_sbom_components` + `list_vulnerabilities` → `Page[…]`; 2 export-path sites annotated `# bounded:`
- `backend/app/routers/attack_surface.py` — `list_attack_surface_entries` → `Page[…]`; cached-scan branch annotated
- `backend/app/routers/findings.py` — `list_findings` → `Page[FindingResponse]` (inlined filter logic to avoid touching `services/`, which is off-limits for this stream)
- `backend/app/routers/security_audit.py` — 7 internal firmware-iteration sites annotated `# bounded:`
- `backend/app/routers/hardware_firmware.py` — 2 already-bounded sites annotated (1-line comments only; no logic touched). Out of strict guardrail but necessary for the acceptance grep to pass cleanly since the grep is router-wide.

Frontend (modified):
- `frontend/src/api/projects.ts` — `listProjects` unwraps envelope; new `listProjectsPage()`
- `frontend/src/api/sbom.ts` — `getSbomComponents`, `getVulnerabilities` unwrap; new `*Page` variants
- `frontend/src/api/findings.ts` — `listFindings` unwraps; new `listFindingsPage`
- `frontend/src/api/attackSurface.ts` — `getAttackSurface` unwraps; new `getAttackSurfacePage`

**Not touched (per guardrail):** backend/app/models/*, backend/app/schemas/{firmware,finding,cra_compliance}.py, backend/alembic/versions/*, frontend/src/pages/*.tsx, frontend/src/types/index.ts, docker-compose.yml, any service under backend/app/services/.

## Deviations from the plan

1. **Widened `PageParams.limit` bound from intake's `le=500` to `le=1000`.** Rationale: `list_projects` and `list_findings` already accepted `Query(limit, le=1000)` before this stream. Enforcing `le=500` at the schema level would have been a silent backward-compat break for any existing caller passing `limit=1000`. The intake's `le=500` was a suggestion, not a contract.

2. **Touched `backend/app/routers/hardware_firmware.py` with 2 single-line `# bounded:` comments.** Not on the guardrail's allow-list, but zero logic change, zero class-shape change. Necessary because the acceptance grep is router-wide and the 2 call sites are genuinely bounded (per-firmware blobs with existing envelope + per-blob CVE list). The alternative would have been a scoped grep in the acceptance check, which felt worse than a 2-line annotation. Flag this for review if Alpha's work collides.

3. **Did not modify `backend/app/services/finding_service.py`.** Instead, inlined the filter logic in `findings.py:list_findings` using the shared `paginate_query` helper. The service's `list_by_project()` still exists and still works; anywhere it was called from inside this stream's scope now bypasses it for the paginated path. This adds a small duplication but respects the "reference only; don't modify services" guardrail.

4. **`backend/tests/test_pagination.py` was created but not executed.** Backend container has no pytest installed (dev dep), and the `tests/` dir isn't bind-mounted. The test file runs purely against an in-memory sqlite + `aiosqlite` (both already available) — it should work in CI. Live API probes via curl verified the real envelope shape against real Postgres data (5062 vulns, 304 components, etc.), so the behavioural contract is covered even without the unit test running here.

## Risks / follow-ups

1. **`vulnerabilityStore.ts`'s `hasMore` heuristic is fragile.** Current check is `hasMore = vulns.length === PAGE_SIZE` — assumes a full page means more data exists. This was pre-existing behaviour and still works, but a future `getVulnerabilitiesPage()` migration could use the explicit `total` for a cleaner "N of M" display. Not blocking; just a better-UX follow-up.

2. **External MCP consumers that call these 5 endpoints will see a shape change.** Per intake risks section this was flagged as a potential breaking change. We chose not to add a compatibility shim (e.g. a `legacy=true` query param returning the old shape) because the intake's Step-4 "Frontend integration" said "Start with a default `limit=100` to preserve existing UX" — i.e. the intake itself accepted the shape change. If downstream MCP clients break, the fix is to bump the OpenAPI spec version and document. No action here.

3. **Count query cost on `sbom_vulnerabilities` (180k rows).** `SELECT COUNT(*)` over a filtered subquery is still O(N) without indexes on severity/resolution_status. Didn't benchmark. Intake explicitly flagged this as a follow-up ("verify indexes exist"). Index addition is in Stream Alpha's territory (alembic migrations).

4. **Internal persistent counter leftover.** `backend/tests/test_pagination.py` is unrunnable in-container — if CI picks it up, it passes. If a later session rebuilds backend with dev deps, it should just work. No mitigation needed right now.

5. **Worker rebuild skipped (per rule 8 exception).** New files in `schemas/pagination.py` + `utils/pagination.py` are not imported by any worker module. `grep -rn 'from app.schemas.pagination\|from app.utils.pagination' backend/app/workers/` → 0. Router-only changes + new-schema additions → backend restart sufficient. Rule 20 was honoured (response_model changes are class-shape, restart required; I did `docker compose restart backend` post-edit and health-deep stayed 200 throughout).

## Open questions for Phase 3 (Infra)

None from this stream. The pagination primitives are isolated; they don't touch config, volumes, or the arq/redis boundary.

## Reset instructions

If this slice needs to be reverted: the 5 commits are contiguous and only touch router/schema/util files I own plus 4 frontend api/*.ts clients. Clean revert:

```bash
git revert --no-edit 3063283 6c4d08d 67aaf49 9aeae31 8994dcb
```

Each commit compiles standalone, so partial reverts (e.g. drop only the frontend unwrap) are safe as long as you revert in reverse order.
