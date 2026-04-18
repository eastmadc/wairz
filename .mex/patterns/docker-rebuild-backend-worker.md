---
name: docker-rebuild-backend-worker
description: Correctly rebuild backend + worker together after Python code or dependency changes. Prevents the #1 recurring bug in this project (stale image / stuck worker).
triggers:
  - "rebuild"
  - "docker compose"
  - "worker stale"
  - "changes didn't take effect"
  - "restart backend"
edges:
  - target: context/setup.md
    condition: for the full compose command surface and environment variable overrides
  - target: context/conventions.md
    condition: for the Verify Checklist items on rebuild parity
last_updated: 2026-04-17
---

# Docker Rebuild — Backend + Worker

## Context
`backend` and `worker` services share the SAME Dockerfile and codebase in `docker-compose.yml`. The worker runs `alembic upgrade head && arq app.workers.arq_worker.WorkerSettings` as its entrypoint. If you rebuild only one, the two drift: the worker can't see new migrations or code, and arq jobs silently stall (no ERROR log — just no progress). This is Learned Rule #8, the most frequent failure in session history.

## Steps

1. After any backend code or `pyproject.toml` change, run:
   ```
   docker compose up -d --build backend worker
   ```
   Both services named. Not just `backend`.

2. If you added a Python dependency:
   - Update `backend/pyproject.toml` in the same commit.
   - Rebuild as above.
   - Verify the import: `docker compose exec backend python -c "import <module>"`.

3. If you added an Alembic migration:
   - The worker applies it at entrypoint. Rebuild the worker with `--build`.
   - Watch logs: `docker compose logs -f worker`. Look for `INFO  [alembic.runtime.migration] Running upgrade ...`.
   - If the worker logs show "Can't locate revision", the image is stale. Rebuild with `--build`.

4. Reconnect MCP clients (e.g. `/mcp` in Claude Code) — the `wairz-mcp` process is long-lived and needs to be re-spawned to pick up new tool registrations.

5. Tail both services for a minute to catch startup errors:
   ```
   docker compose logs -f backend worker
   ```

## Gotchas

- **`docker compose restart backend`** reuses the old image. It restarts the container with the same built layer. Always use `up -d --build`.
- **Rebuilding only backend** leaves a stale worker. Jobs queued to Redis sit in arq forever with no ERROR. Check with `docker compose exec redis redis-cli LLEN arq:queue`.
- **Frontend image is separate.** If you also changed frontend, include it: `docker compose up -d --build backend worker frontend` (or run Vite locally).
- **`wairz_emulation_net` external network missing** after a `docker network prune` — backend panics on boot. Recreate: `docker network create wairz_emulation_net`.
- **Sidecar images (emulation, fuzzing, system-emulation)** use `profiles: ["build"]` and don't rebuild with a plain `up`. Run `docker compose --profile build build emulation fuzzing system-emulation` after changing their Dockerfiles.
- **`DOCKER_GID` mismatch:** if the host's docker socket group id changes, the backend user inside the container can't access the socket. Re-set `DOCKER_GID` in `.env` (`stat -c %g /var/run/docker.sock`) and rebuild.

## Verify

- [ ] Command run was `docker compose up -d --build backend worker` (both named).
- [ ] `docker compose logs worker | tail -50` shows a successful Alembic upgrade line on startup.
- [ ] `docker compose logs backend | tail -50` shows `Application startup complete`.
- [ ] For a dependency change: `docker compose exec backend python -c "import <X>"` returns silently.
- [ ] For a migration: `docker compose exec backend alembic current` shows the new head.
- [ ] MCP client has been reconnected if tool registrations changed.

## Debug

- **Background jobs stuck / never complete:** stale worker. Rebuild both.
- **`ModuleNotFoundError` inside the container:** dep missing from `pyproject.toml`, or build cache stale. Force a clean build: `docker compose build --no-cache backend worker`.
- **`alembic.util.exc.CommandError: Can't locate revision`:** worker image doesn't contain the new migration. Rebuild worker.
- **Backend starts but immediately exits:** check `docker compose logs backend`. Common causes: `emulation_net` missing, `DOCKER_GID` mismatch, `DATABASE_URL` points at a down postgres.

## Update Scaffold
- [ ] If you discovered a new rebuild gotcha, append it here.
- [ ] If a new service joined the compose file, mention it in `context/architecture.md` + this pattern's command list.
