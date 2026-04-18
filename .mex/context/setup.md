---
name: setup
description: Dev environment setup and commands for the Wairz Docker Compose stack plus the host-side UART/device bridges. Load when setting up the project for the first time or when environment issues arise.
triggers:
  - "setup"
  - "install"
  - "environment"
  - "getting started"
  - "how do I run"
  - "local development"
  - "docker compose"
  - "bridge"
edges:
  - target: context/stack.md
    condition: when specific technology versions or library details are needed
  - target: context/architecture.md
    condition: when understanding how components connect during setup (why bridges, why socket mounts)
last_updated: 2026-04-17
---

# Setup

## Prerequisites

- **Docker Engine + Docker Compose v2** (recent enough to support `additional_contexts`, `healthcheck`, and `extra_hosts: host.docker.internal:host-gateway`).
- **Python 3.12** and **`uv`** — only if running `./launch.sh` for local (non-Docker) backend dev.
- **Node.js + npm** — for the frontend when running outside Docker (`frontend/package.json` uses `npm`, not `pnpm`, despite the root `pnpm-lock.yaml`).
- **`adb`** on PATH — if you plan to use the device acquisition bridge.
- **`pyserial`** (pip) — if you plan to use the UART bridge.
- **Linux host:** iptables access for the bridge rules. `sysctl vm.overcommit_memory=1` is recommended for Redis background saves.

## First-time Setup

1. Clone and `cp .env.example .env`. Set `DOCKER_GID` to match your docker socket group: `stat -c %g /var/run/docker.sock`.
2. If `wairz_emulation_net` does not already exist, create it once: `docker network create wairz_emulation_net`. (Compose declares it `external: true`.)
3. Build the on-demand sidecar images (they have `profiles: ["build"]` so they don't auto-start): `docker compose --profile build build emulation fuzzing system-emulation`.
4. Start the core stack: `docker compose up -d --build`. Postgres + Redis health-check, backend + worker come up after, Alembic migrations run automatically on worker entrypoint.
5. Visit `http://localhost:3000` (frontend) and `http://localhost:8000/docs` (FastAPI Swagger).
6. For MCP: in your MCP client config (e.g. Claude Code `mcp.json`), register `wairz-mcp --project-id <uuid>` pointing at a project you've created via the UI.
7. (Optional) Start host-side bridges when you need hardware access:
   - `python3 scripts/wairz-uart-bridge.py --bind 0.0.0.0 --port 9999`
   - `python3 scripts/wairz-device-bridge.py --bind 0.0.0.0 --port 9998`
   - Add iptables rules (see Common Issues).

## Environment Variables

Required:
- `DATABASE_URL` — e.g. `postgresql+asyncpg://wairz:wairz@postgres:5432/wairz` (compose injects this for the backend).
- `REDIS_URL` — e.g. `redis://redis:6379/0`.
- `STORAGE_ROOT` — where firmware and extracted trees live on disk (backend uses `/data/firmware` in the container; `./launch.sh` uses `./data/firmware` locally).
- `DOCKER_GID` — group id of `/var/run/docker.sock`; used at image build time so the backend user can reach the socket.

Port conflict overrides (optional):
- `POSTGRES_HOST_PORT` (default 5432) — host-side mapping for postgres. On hosts with existing Postgres, use e.g. 5434.
- `REDIS_HOST_PORT` (default 6379) — host-side mapping for Redis. Use e.g. 6380 if 6379 is busy.

Bridges (required only if used):
- `UART_BRIDGE_HOST=host.docker.internal`, `UART_BRIDGE_PORT=9999`.
- `DEVICE_BRIDGE_HOST=host.docker.internal`, `DEVICE_BRIDGE_PORT=9998`.

Tuning / optional:
- `MAX_UPLOAD_SIZE_MB` (default 2048) — firmware upload cap.
- `MAX_TOOL_OUTPUT_KB` (default 30) — MCP truncation (see `app/utils/truncation.py`).
- `GHIDRA_TIMEOUT` (default 120) — decompilation timeout seconds.
- `GHIDRA_PATH` / `GHIDRA_SCRIPTS_PATH` — baked into the backend image, override only if needed.
- `EMULATION_IMAGE`, `EMULATION_NETWORK`, `FUZZING_IMAGE`, `SYSTEM_EMULATION_IMAGE` — image/name overrides.
- `NVD_API_KEY` — raises NVD rate limits during CVE scans.
- `CORS_ORIGINS` — comma-separated list; default `http://localhost:3000,http://127.0.0.1:3000`.

## Common Commands

- **Full rebuild:** `docker compose up -d --build backend worker` (both together — Learned Rule #8).
- **Logs:** `docker compose logs -f backend` or `... worker`.
- **Shell into backend:** `docker compose exec backend bash`.
- **Generate migration:** `docker compose exec backend alembic revision --autogenerate -m "add X"`. Applied automatically on next worker boot.
- **Apply migrations manually:** `docker compose exec backend alembic upgrade head`.
- **Frontend dev (hot reload):** `cd frontend && npm run dev` (port 5173). The compose frontend runs on 3000.
- **Frontend lint + type check:** `cd frontend && npm run lint && npm run build` (build includes `tsc -b`).
- **Playwright E2E:** `cd frontend && npm run test:e2e`.
- **Local Python dev (no Docker):** `./launch.sh` creates `.env` (if missing), brings up postgres + redis containers, `uv sync`, `alembic upgrade head`, starts uvicorn + Vite.
- **Rebuild sidecars:** `docker compose --profile build build emulation fuzzing system-emulation`.

## Common Issues

- **Backend code changes "don't take effect":** You used `docker compose restart backend`. That reuses the old image. Use `docker compose up -d --build backend worker` instead (Learned Rule #1).
- **Alembic failure / background jobs silently stuck:** The worker image is stale after a backend code change. Rebuild both together (Learned Rule #8).
- **`ImportError` for a newly added Python dep in Docker:** You forgot to update `backend/pyproject.toml`. Add the dep, rebuild backend, verify with `docker compose exec backend python -c "import <module>"` (Learned Rule #2).
- **Bridge unreachable ("connection refused" to UART/device bridge):**
  1. `UART_BRIDGE_HOST` must be `host.docker.internal`, not `localhost`.
  2. iptables: `sudo iptables -I INPUT -i docker0 -p tcp --dport 9999 -j ACCEPT` (and 9998 for device bridge).
  3. Restart backend after `.env` changes: `docker compose restart backend` + reconnect MCP client (`/mcp` in Claude Code).
- **Port 5432/6379 in use:** Set `POSTGRES_HOST_PORT=5434` / `REDIS_HOST_PORT=6380` in `.env`.
- **`wairz_emulation_net` not found:** The network is external. `docker network create wairz_emulation_net`.
- **Frontend shows blank page after backend enum change:** A new backend source value isn't in a frontend `Record<SourceType, ...>` map. Grep for `Record<` in `frontend/src/` (Learned Rule #9).
- **Firmware path errors after unpack:** A sync `os.walk` inside an async handler stalled the event loop. Wrap in `run_in_executor` (Learned Rule #5). Use `safe_walk` to follow firmware symlinks.
