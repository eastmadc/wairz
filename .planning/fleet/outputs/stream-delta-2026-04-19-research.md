# Stream Delta — Phase 3 Research (O1 + O2 + O3)

> Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md`
> Intake: `.planning/intake/infra-cleanup-migration-and-observability.md`
> Wave 2 baseline: HEAD `4cc5354` (Alpha's test commit after pagination+schema wave).
> Date: 2026-04-19

## Evidence-first baselines (Rule 19)

| Probe | Value | Meaning |
|---|---|---|
| `grep -rn 'cleanup_expired' backend/app/` | 2 defs (fuzzing + emulation), 0 callers | Both services defined but never called — confirmed orphan risk is real but purely future-proofing |
| `grep -rn 'cleanup_orphans' backend/app/` | 0 | Method does not exist; intake asks us to add it |
| `arq cron_jobs` in `arq_worker.py:361` | 1 entry (`sync_kernel_vulns_job`) | Cron infra already exists, 1 pre-existing daily job |
| `logging.getLogger` / `logger =` count | 88 sites | Bare Python logging everywhere |
| `import structlog` in container | ModuleNotFoundError | Not installed |
| `import prometheus_fastapi_instrumentator` | ModuleNotFoundError | Not installed |
| Emulation sessions by status | error=1, stopped=1 | No stale `running` rows |
| Fuzzing campaigns by status | 0 rows | Clean slate |
| Orphan containers (`label=wairz.type=emulation/fuzzing`) | 0 | No orphans in current state |

**Rule 19 verdict:** O1 is future-proofing (0 incident evidence). O2 is latent — advisory lock hides it. O3 is a pure gap. Still ship all three, but calibrate urgency: this is hardening, not incident response.

## Current call-graphs

### `cleanup_expired` (emulation)
- Defined at `backend/app/services/emulation_service.py:1594`
- Iterates `EmulationSession` rows with `status='running'`, compares `started_at + emulation_timeout_minutes` to `utcnow()`, calls `self.stop_session(session.id)` on each expired one.
- Callers: **none** (grep clean outside the defining file).

### `cleanup_expired` (fuzzing)
- Defined at `backend/app/services/fuzzing_service.py:983`
- Timeout-based: iterates `FuzzingCampaign(status='running')` rows, compares vs `fuzzing_timeout_minutes`, calls `self.stop_campaign()`.
- Callers: **none**.

### `cleanup_orphans` (fuzzing)
- Does not exist. Intake asks for a DB↔container reconciliation loop (label-based container list + DB row cross-reference). Scaffold in Phase 3 plan.

### Docker labels on emulation/fuzzing containers
- Fuzzing: `wairz.type=fuzzing`, `wairz.campaign_id`, `wairz.project_id` — fully labelled.
- Emulation: `wairz.mode`, `wairz.session_id`, `wairz.project_id` — note **no `wairz.type=emulation` label**. Reaper needs a different filter (use `wairz.session_id` existence) or we add the `type` label in a follow-up.

### Alembic migration execution paths
- `backend/entrypoint.sh:17` — `alembic upgrade head && python -m uvicorn ...` (backend).
- `docker-compose.yml:182` — `sh -c '.venv/bin/python -m alembic upgrade head && exec .venv/bin/arq ...'` (worker).
- Both race on fresh bring-up. Alembic's PG advisory lock serialises, but loser logs failure-looking output.

### Docker client usage (post Phase 1)
- `get_docker_client()` from `backend/app/utils/docker_client.py` used in 10+ sites across emulation/fuzzing/health. No remaining `docker.from_env()` in production code.
- **/health/deep already uses** `client.containers.list(limit=1)` since commit 29dba35 (Phase 1 regression fix). We keep that shape for `/ready` alias.

### Health endpoint shape (current)
- `GET /health` → 200 `{status,version,storage_root_exists}` — shallow.
- `GET /health/deep` → 200/503 with `{db,redis,docker,storage}` dict — deep.
- Both exempt from auth middleware at `asgi_auth.py:39-43`.

## Plan as designed

### O1 — arq cron for cleanup

**New file changes in `backend/app/workers/arq_worker.py`:**
1. Add `cleanup_emulation_expired` async function — creates own session via `async_session_factory()`, calls `EmulationService(db).cleanup_expired()`, commits.
2. Add `cleanup_fuzzing_orphans` async function — same pattern but calls the new `FuzzingService.cleanup_orphans()`.
3. Extend `cron_jobs` list by 2 entries: `cron(cleanup_emulation_expired, minute={5,35})`, `cron(cleanup_fuzzing_orphans, minute={10,40})`. Running every 30 min gives 2 reaps per hour without starving the worker.

**New method `FuzzingService.cleanup_orphans()`:**
- List containers with `filters={"label": "wairz.type=fuzzing"}` (include stopped ones via `all=True`).
- Fetch DB campaigns with `status='running'`.
- For each running DB campaign with no matching alive container → mark as `error` with `error_message="Container vanished (orphan reaper)"`.
- For each container with no matching DB campaign → remove it (`container.remove(force=True)`).
- Return `{db_fixed, containers_reaped}` counts.

### O2 — one-shot migrator service

**`docker-compose.yml` additions:**
```yaml
migrator:
  build: { context: ./backend, dockerfile: Dockerfile }
  command: ["sh", "-c", ".venv/bin/python -m alembic upgrade head"]
  env_file: .env
  environment:
    DATABASE_URL: postgresql+asyncpg://${POSTGRES_USER:-wairz}:${POSTGRES_PASSWORD:-wairz}@postgres:5432/${POSTGRES_DB:-wairz}
  depends_on:
    postgres: { condition: service_healthy }
  restart: "no"
```

**Strip `alembic upgrade head && ` from:**
- `backend/entrypoint.sh:17` → leaves `.venv/bin/python -m uvicorn ...`.
- `docker-compose.yml` worker entrypoint line 182 → leaves `exec .venv/bin/arq ...`.

**Add `depends_on.migrator: {condition: service_completed_successfully}`** to both backend and worker.

### O3 — structlog + prom + deeper /health

**Decision: keep /health + /health/deep unchanged, ADD /ready as alias + /metrics.**

Rationale: `/health/deep` is load-bearing in the verification battery, is actively used by other streams and Phase 1 end-conditions. Phase 7 maintenance sweep is the appropriate place to migrate probes to `/ready` (intake explicitly defers that). For now we ship both.

- `GET /health` → unchanged (shallow). Exempt from auth.
- `GET /health/deep` → unchanged (deep, 200/503). Exempt from auth.
- `GET /ready` → alias for `/health/deep` — same logic, same exempt. **Auth-exempt.**
- `GET /metrics` → prometheus-fastapi-instrumentator endpoint. **Auth-exempt** for standard Prom scraping convention. Document as a follow-up to gate it if operator requires.

**Move /health + /health/deep + /ready to a new `backend/app/routers/health.py`** to clean up `main.py`.

**Add `backend/app/logging_config.py`** with structlog JSON renderer, call `configure_logging()` at lifespan start.

**Add structlog + prometheus-fastapi-instrumentator to `pyproject.toml`.**

**Wire Instrumentator in `main.py`:**
```python
from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)
```

**Exempt /metrics and /ready from the API-key middleware.** Add to `_EXEMPT_HTTP_PATHS` in `asgi_auth.py`.

### Commit split

1. `feat(backend): add structlog + prometheus-fastapi-instrumentator deps + logging config`
2. `feat(backend): split /health + /health/deep into routers/health.py; add /ready alias + /metrics + expand auth exempt list`
3. `feat(services): FuzzingService.cleanup_orphans() — label-based DB<->container reconciliation`
4. `feat(workers): arq cron jobs for emulation timeout-reap + fuzzing orphan reconciliation`
5. `feat(infra): one-shot migrator service + strip alembic from backend/worker entrypoints`

All 5 require the full rebuild (rule 8 + 20) because dep add changes image, class-shape changes in main.py, new workers/arq_worker module, fuzzing_service method adds.

## Risks

1. **`/metrics` auth-exempt is a surface expansion.** Prometheus convention, but any attacker who can hit `/metrics` can enumerate routes + latencies. Mitigation note: document that `/metrics` should be bound to 127.0.0.1 or behind an ingress allow-list when exposed beyond the host.
2. **Migrator service on fresh `up -d` with never-migrated DB**: first boot needs both `postgres` healthy AND the dockerfile built. If `build` is skipped, backend hangs on `depends_on: {migrator: service_completed_successfully}` forever. Document as: `docker compose up -d --build migrator` on the first bring-up of a new checkout.
3. **Emulation container reaper lacks `wairz.type=emulation` label to filter on.** Current emulation common_labels only sets `wairz.mode`, `wairz.session_id`, `wairz.project_id`. For reaping by label we could filter on `label=wairz.session_id` (presence) but `docker` CLI doesn't filter on "label key exists without value" cleanly. Workaround: our `cleanup_expired` is timeout-based over DB rows, not label-based, so no new label is needed for the cron shape the intake specifies. The fuzzing `cleanup_orphans` is label-based; it's OK because fuzzing DOES have the type label.
4. **Worker must be rebuilt** — rule 8 is absolute for pyproject.toml dep changes. Backend + worker share image.
5. **Starlette exception handler pattern change.** The current `main.py` has an app-level `@app.get("/health")` and `@app.get("/health/deep")` — moving these to an `APIRouter` means they're picked up via `app.include_router()`. No route shape change.

## Open questions — none blocking

- Deciding the `unique=True` (default) for cron = if multiple workers (currently max_jobs=4, single process), only 1 claim per run. Good — matches intake intent.
