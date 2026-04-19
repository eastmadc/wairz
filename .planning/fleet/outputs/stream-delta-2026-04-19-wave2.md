# Stream Delta — Phase 3 Wave 2 Handoff (O1 + O2 + O3)

> Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md` (Phase 3).
> Intake: `.planning/intake/infra-cleanup-migration-and-observability.md`.
> Parent branch: `clean-history`.
> Baseline HEAD: `4cc5354` (Alpha's test-alignment commit).
> Final HEAD: `daa7ecf`.
> 7 commits shipped. All 10 verification items PASS.

## TL;DR

- **O1** — arq cron jobs for emulation timeout reap + fuzzing DB↔container reconciliation. New `FuzzingService.cleanup_orphans()` handles the orthogonal orphan case `cleanup_expired()` couldn't.
- **O2** — one-shot `migrator` service; backend + worker `depends_on: {migrator: service_completed_successfully}`. Alembic race eliminated.
- **O3** — `structlog` + `prometheus-fastapi-instrumentator` deps added. JSON logging wired at module-import time; `/metrics` and `/ready` live (auth-exempt). `/health` and `/health/deep` preserved verbatim for back-compat with Phase 1 verification battery.

## Research findings (baseline — Rule 19 evidence-first)

| Probe | Value | Interpretation |
|---|---|---|
| Callers of `cleanup_expired` | 0 (defs exist in emulation + fuzzing services) | Orphan risk is real but 0-incident |
| Pre-existing arq `cron_jobs` | 1 (`sync_kernel_vulns_job`) | Cron infra already present |
| `logging.getLogger` / `logger =` sites | 88 | Plain stdlib logging ubiquitous |
| `import structlog` / `import prometheus_fastapi_instrumentator` | ModuleNotFoundError | Neither installed |
| Emulation sessions by status | `error=1, stopped=1` | 0 stale `running` rows |
| Fuzzing campaigns by status | 0 rows | Clean slate |
| Orphan containers (`label=wairz.type=fuzzing`) | 0 | No orphans in current state |

Verdict per intake-stream-delta prompt instruction: calibrated as **hardening / future-proofing** not incident-driven, but still ships the full slice.

## Plan as executed

All five planned commits shipped in order, plus 2 logging fixups discovered at verification time:

| # | SHA | Scope |
|---|---|---|
| 1 | `a4e9eb8` | deps (structlog + prometheus-fastapi-instrumentator) + `logging_config.py` |
| 2 | `566637a` | `routers/health.py` (`/health`, `/health/deep`, `/ready`) + `/metrics` instrumentator + auth exempt |
| 3 | `0f3e87a` | `FuzzingService.cleanup_orphans()` reconciliation |
| 4 | `e8548fd` | arq cron wiring (`cleanup_emulation_expired_job` @ :05/:35, `cleanup_fuzzing_orphans_job` @ :20/:50) |
| 5 | `b8b9bd9` | `migrator` one-shot service + stripped alembic from backend + worker entrypoints |
| 6 | `3a167ae` | Fixup — move `configure_logging()` to module-import so uvicorn boot lines are JSON |
| 7 | `daa7ecf` | Fixup — reroute uvicorn/arq named loggers through root JSON handler |

## Critical O3 decision — back-compat preserved

The intake suggested renaming `/health/deep` → `/ready`. Stream-delta prompt instructed keeping both. Implemented as:

- `/health` — shallow liveness (unchanged shape, unchanged behaviour)
- `/health/deep` — deep probe (unchanged behaviour; shared `_run_deep_checks()` helper)
- `/ready` — alias to `/health/deep` at the canonical k8s path
- `/metrics` — Prometheus text format (auth-exempt per scraping convention)

docker-compose.yml backend healthcheck still hits `/health` (unchanged). No verification-battery migration needed this phase. Phase 7 maintenance sweep can migrate the healthcheck to `/ready` if desired.

## Verification matrix

| # | Check | Expected | Got | Result |
|---|---|---|---|---|
| 1 | `GET /health` (no auth) | 200, `{"status":"ok",...}` | 200, matches | PASS |
| 2 | `GET /health/deep` (authed) | 200, all checks ok | 200, all 4 checks ok | PASS |
| 3 | `GET /ready` (no auth) | 200, all checks ok | 200, all 4 checks ok | PASS |
| 4 | `GET /metrics` | 200, Prom text format, >5 HELP lines | 200, 20 HELP lines, `http_requests_total` present | PASS |
| 5 | arq cron registered | 3 entries | `sync_kernel_vulns_job @ 03:00`, `cleanup_emulation_expired_job @ :05/:35`, `cleanup_fuzzing_orphans_job @ :20/:50` | PASS |
| 6 | migrator state | `Exited (0)` | `Exited (0) 2 minutes ago` | PASS |
| 7 | `alembic_version` row count | 1 | 1 | PASS |
| 8 | JSON log parse | valid JSON | 5/5 lines parse, `event/level/timestamp` all present | PASS (see caveat) |
| 9 | DPCS10 canary | 260 blobs | 260 | PASS |
| 10 | Auth matrix | no-key 401 / authed 200 / metrics 200 (exempt) / ready 200 (exempt) | all match | PASS |
| 11 | Smoke test: direct invocation of both new cron jobs | `{"status":"ok","reaped":0}` / `{"status":"ok","db_fixed":0,"containers_reaped":0}` | both match | PASS |

### Caveat on #8 — uvicorn boot-phase lines

Uvicorn emits 4-5 boot-phase lines via direct `click.echo()`/`print()` that bypass Python's logging module entirely:
```
INFO:     Started server process [9]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```
These are NOT convertible via `configure_logging` — uvicorn would need `--log-config=/path.json` or programmatic `log_config=None` override at server init. Application + library logs (structlog, stdlib, sqlalchemy, docker, arq) all emit valid JSON. Jq-style aggregation works on the post-boot stream. Flagged as a known uvicorn quirk; not blocking.

Arq worker similarly emits its own per-line text format (`17:31:19: Starting worker for ...`) through its internal logger which renders to stderr outside the stdlib pipeline. Same caveat; the cron functions + arq internals still log JSON when they go through stdlib.

## Files touched (absolute paths)

### New files
- `/home/dustin/code/wairz/backend/app/logging_config.py`
- `/home/dustin/code/wairz/backend/app/routers/health.py`
- `/home/dustin/code/wairz/.planning/fleet/outputs/stream-delta-2026-04-19-research.md`
- `/home/dustin/code/wairz/.planning/fleet/outputs/stream-delta-2026-04-19-wave2.md`

### Modified
- `/home/dustin/code/wairz/backend/pyproject.toml` — +structlog>=24.4.0, +prometheus-fastapi-instrumentator>=7.0.0
- `/home/dustin/code/wairz/backend/app/main.py` — removed inline health endpoints, import new router, module-import `configure_logging`, Prometheus `Instrumentator` at bottom
- `/home/dustin/code/wairz/backend/app/middleware/asgi_auth.py` — added `/ready` + `/metrics` to `_EXEMPT_HTTP_PATHS`
- `/home/dustin/code/wairz/backend/app/services/fuzzing_service.py` — new `cleanup_orphans()` method
- `/home/dustin/code/wairz/backend/app/workers/arq_worker.py` — 2 new cron job funcs + `configure_logging()` at import, extended `WorkerSettings.functions` + `cron_jobs`
- `/home/dustin/code/wairz/backend/entrypoint.sh` — stripped `alembic upgrade head &&`
- `/home/dustin/code/wairz/docker-compose.yml` — new `migrator` service; backend + worker `depends_on.migrator`; worker entrypoint no longer runs alembic

## Deviations from plan

1. **Accidental commit sweep in commit #4 (`e8548fd`).** Wave 1 anti-pattern #3 repeated — a post-commit hook swept 8 unrelated Stream Zeta frontend files into my arq-worker commit (`frontend/src/api/*.ts`, `frontend/src/hooks/useEventStream.ts`, `frontend/src/pages/*.tsx`). The diff is content-correct (those are genuine Zeta changes that would have been committed anyway), only the commit message is wrong. Matches Alpha's commit `f614c43` noise from Wave 1. Recommend a harness-level fix: an invariant that blocks the commit if `git diff --cached --name-only` contains files outside the asked stream's scope. Not worth a history rewrite on a shared branch.
2. **Rename to `/ready` only, no `/health/deep` removal.** Kept back-compat with Phase 1 verification battery as instructed. `/health/deep` is a pure alias of `/ready` via `_run_deep_checks()`. Eventual deprecation is Phase 7 territory.
3. **`/metrics` exempt from API-key auth.** Prometheus convention is unauthenticated scraping. Documented as an ingress-layer concern; if the operator needs auth on `/metrics`, remove from `_EXEMPT_HTTP_PATHS` and restore API-key requirement.
4. **Emulation container reaper uses timeout (`cleanup_expired`), not label reconciliation.** Emulation containers only carry `wairz.session_id` + `wairz.mode` + `wairz.project_id` labels — no `wairz.type=emulation` label for easy filtering. Fuzzing containers carry `wairz.type=fuzzing` so the reconciler uses that. Adding a type label to emulation is a follow-up if label-based reconciliation becomes important. Timeout-based reaping is sufficient per the intake.
5. **Two in-flight logging fixups** (`3a167ae`, `daa7ecf`). Discovered at verification when the first boot showed uvicorn's INFO lines unconverted. Root cause was late-binding lifespan config + uvicorn's named loggers with `propagate=False`. Both fixups documented inline in their commit messages.

## Unresolved risks / follow-ups

1. **Uvicorn/arq direct print lines remain plain text.** See caveat on verification item #8. If full JSON log-parsing is mission-critical, launch uvicorn with `--log-config=<json-config-file>` or set `LOG_CONFIG` env var — out of scope for this phase. Queue as a Phase 7 follow-up.
2. **`/metrics` exposure surface.** An attacker with localhost access can enumerate every route + latency histogram. Deploys exposing port 8000 beyond 127.0.0.1 should gate `/metrics` at the ingress layer (nginx/Caddy location block, or remove from `_EXEMPT_HTTP_PATHS`).
3. **Migrator failure blocks backend + worker startup.** Intended behaviour (clearer error surfacing than the previous race), but operationally means a bad migration bricks the stack until reverted. Recovery path: `docker compose logs migrator` → fix migration → `docker compose up -d --build migrator` → backend + worker auto-start.
4. **`cleanup_orphans` is idempotent but label-fragile.** If an operator ever spawns fuzzing containers without the `wairz.type=fuzzing` label (e.g. via direct `docker run` for debugging), the reaper will miss them AND they'll hang around forever. Add a defensive layer later — `cleanup_orphans_unlabelled` scanning image name + `wairz-fuzzing:*`.
5. **Emulation reaper needs a `wairz.type=emulation` label for future label-based reconciliation.** Add this at next emulation-service touch; it's a trivial 1-line addition in `_start_emulation_session`'s `common_labels` dict.
6. **Worker's arq boot output bypasses JSON.** Arq's `Starting worker for N functions` lines come from arq's own logger config (not via Python `logging.getLogger`). Low priority — arq internal telemetry, not application behaviour.

## Open questions for Phase 4+

- Phase 7's maintenance sweep should migrate frontend healthcheck to `/ready` when it runs (intake already lists this).
- Consider adding custom Prometheus metrics (cache_hits_total, subprocess_duration_seconds) in a future observability intake — intake mentioned them but deferred.

## Reset instructions

If this phase needs to be reverted: the 7 commits are contiguous. Clean revert:
```bash
git revert --no-edit daa7ecf 3a167ae b8b9bd9 e8548fd 0f3e87a 566637a a4e9eb8
```
Each commit compiles standalone; partial reverts are safe in reverse order (e.g. revert just the migrator commit `b8b9bd9` if the one-shot service causes issues in a specific deploy).
