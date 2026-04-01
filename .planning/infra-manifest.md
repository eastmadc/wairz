# Infrastructure Manifest

> Generated: 2026-03-31
> Project: Wairz (firmware reverse engineering platform)

## Current Systems

### PostgreSQL 16 -- Primary Data Store
- **Type**: database
- **Product**: PostgreSQL 16 Alpine
- **Config**: `docker-compose.yml:2-16`, `backend/app/config.py:15`
- **Connection**: Pooled via SQLAlchemy 2.0 async engine (`asyncpg` driver)
- **Used by**: All routers via `get_db` dependency, background tasks via `async_session_factory`
- **Schema mgmt**: Alembic (`backend/alembic.ini`, auto-runs on container start)
- **Health check**: `pg_isready` every 5s
- **Credentials**: Hardcoded in compose (`wairz/wairz`), configurable via `DATABASE_URL` env var
- **Port**: `127.0.0.1:5432` (localhost-bound after PR #16)

### Redis 7 -- Provisioned but Unused
- **Type**: cache/queue (provisioned)
- **Product**: Redis 7 Alpine
- **Config**: `docker-compose.yml:18-28`, `backend/app/config.py:16`
- **Connection**: `redis_url` configured in Settings but **never imported or used** anywhere in the application code
- **Used by**: Nothing — the backend depends on it at startup but never connects
- **Health check**: `redis-cli ping` every 5s
- **Port**: `127.0.0.1:6379` (localhost-bound after PR #16)

### Docker Engine -- Container Orchestrator
- **Type**: container runtime
- **Product**: Docker (host socket mounted)
- **Config**: `docker-compose.yml:59` (`/var/run/docker.sock`)
- **Connection**: Docker SDK (`docker.from_env()`) in emulation and fuzzing services
- **Used by**: `emulation_service.py`, `fuzzing_service.py` — creates/starts/stops/inspects containers dynamically
- **Security note**: Full socket access, root-equivalent on host

### QEMU (via wairz-emulation container) -- Firmware Emulation
- **Type**: compute (emulation)
- **Product**: QEMU system + user mode (ARM, MIPS, MIPSel, AArch64)
- **Config**: `emulation/Dockerfile`, managed dynamically by backend
- **Connection**: Docker SDK creates containers on `emulation_net` (internal network)
- **Used by**: `emulation_service.py`, `emulation.py` router
- **Limits**: 1024MB RAM, 1.0 CPU, 256 PIDs per container

### AFL++ (via wairz-fuzzing container) -- Fuzz Testing
- **Type**: compute (fuzzing)
- **Product**: AFL++ with QEMU mode (ARM, MIPS, MIPSel, AArch64, x86_64)
- **Config**: `fuzzing/Dockerfile`, managed dynamically by backend
- **Connection**: Docker SDK creates containers on default network
- **Used by**: `fuzzing_service.py`, `fuzzing.py` router
- **Limits**: 2048MB RAM, 2.0 CPU, 256 PIDs per container

### Ghidra 11.3.1 -- Binary Analysis
- **Type**: compute (analysis)
- **Product**: Ghidra headless (NSA), JDK 21
- **Config**: `backend/Dockerfile` (installed in backend container), `ghidra/Dockerfile` (standalone)
- **Connection**: `asyncio.create_subprocess_exec` runs Ghidra headless in-process
- **Used by**: `ghidra_service.py` — decompilation, disassembly, function listing
- **Cache**: Results cached in `analysis_cache` DB table (keyed by binary SHA256 + function)

### NVD API -- Vulnerability Database
- **Type**: external API
- **Product**: NIST NVD REST API v2.0 (`services.nvd.nist.gov`)
- **Config**: `backend/app/config.py:24` (`nvd_api_key`, optional)
- **Connection**: Synchronous `requests.get` in thread executor
- **Used by**: `vulnerability_service.py` — CVE lookups for SBOM components
- **Rate limit**: 0.6 req/s without API key, 6 req/s with key

### UART Bridge -- Serial Hardware Proxy
- **Type**: hardware interface
- **Product**: Custom TCP-to-serial bridge (`scripts/wairz-uart-bridge.py`, pyserial)
- **Config**: `config.py:38-39` (`uart_bridge_host`, `uart_bridge_port`)
- **Connection**: TCP:9999 from backend container to host via `host.docker.internal`
- **Used by**: `uart_service.py` — proxies serial I/O to physical UART adapters
- **Runs on**: Host machine (not in Docker — USB passthrough limitation)

### Nginx -- Frontend Reverse Proxy
- **Type**: web server
- **Product**: Nginx Alpine
- **Config**: `frontend/Dockerfile`, `frontend/nginx.conf.template`
- **Connection**: Serves static React build, proxies `/api` to backend:8000
- **Port**: `0.0.0.0:3000`

## Connection Graph

```
                    ┌─────────────┐
                    │   Browser   │
                    └──────┬──────┘
                           │ :3000
                    ┌──────┴──────┐
                    │    Nginx    │
                    │  (frontend) │
                    └──────┬──────┘
                           │ /api proxy
                    ┌──────┴──────┐          ┌──────────────┐
                    │   FastAPI   │──pool────▶│ PostgreSQL 16│
                    │  (backend)  │          └──────────────┘
                    │   :8000     │          ┌──────────────┐
                    │             │──config──▶│  Redis 7     │ (unused)
                    │             │          └──────────────┘
                    │             │          ┌──────────────┐
                    │             │──Docker──▶│ QEMU (emu)   │
                    │             │  SDK     └──────────────┘
                    │             │          ┌──────────────┐
                    │             │──Docker──▶│ AFL++ (fuzz) │
                    │             │  SDK     └──────────────┘
                    │             │          ┌──────────────┐
                    │             │──subprocess──▶│ Ghidra  │
                    │             │              └──────────┘
                    │             │          ┌──────────────┐
                    │             │──HTTPS──▶│  NVD API     │
                    │             │          └──────────────┘
                    │             │          ┌──────────────┐
                    │             │──TCP:9999──▶│UART Bridge │──serial──▶ /dev/ttyUSB0
                    └─────────────┘          └──────────────┘
                                                 (host)
```

## Access Patterns

- **Read-heavy on analysis cache**: Ghidra results (30-120s per run) are cached in `analysis_cache` table, read frequently via `_get_cached()` — `ghidra_service.py`
- **Request/response with real-time streaming**: WebSocket connections for emulation terminal (`emulation.py:495`) and PTY terminal (`terminal.py:141`)
- **Background tasks via `asyncio.create_task`**: Firmware unpacking runs as fire-and-forget background task (`firmware.py:121`), frontend polls for completion
- **External API with rate limiting**: NVD queries use synchronous `requests` in thread executor with manual sleep-based rate limiting (`vulnerability_service.py:521-537`)
- **Docker SDK for container lifecycle**: Emulation/fuzzing containers created, started, stopped, inspected via Docker SDK — no queue, direct synchronous management

## Opportunities

### 1. Redis is Provisioned but Unused -- Wire It or Remove It
- **Signal**: `redis_url` in config, Redis container in compose with health check, backend depends on it — but zero imports of Redis client anywhere in application code
- **System**: Already deployed (Redis 7)
- **Impact**: Currently wastes ~30MB RAM. Could serve as: analysis cache (replace DB-based `analysis_cache` table), pub/sub for WebSocket broadcast, session store, rate limiter for NVD API
- **Effort**: low (already running, just needs a client)

### 2. No Job Queue for Background Tasks
- **Signal**: `asyncio.create_task()` for firmware unpacking (`firmware.py:121`), frontend polls every 2s. Ghidra analysis (30-120s) blocks a worker. NVD scanning is long-running with manual rate limiting.
- **System**: Redis + Celery/ARQ/Dramatiq, or Bull/BullMQ
- **Impact**: Better reliability (tasks survive restarts), observability (task status in queue), concurrency control, retry logic
- **Effort**: medium — Redis is already deployed, need task framework + worker process

### 3. No Connection Pooling Configuration
- **Signal**: `create_async_engine()` in `database.py:13` with no `pool_size`, `max_overflow`, or `pool_timeout` args — uses SQLAlchemy defaults (pool_size=5, max_overflow=10)
- **System**: SQLAlchemy pool configuration or PgBouncer
- **Impact**: Under concurrent analysis requests (Ghidra + emulation + fuzzing), 5+10=15 connections could be exhausted. Explicit pool sizing tied to expected concurrency.
- **Effort**: low — add `pool_size=20, max_overflow=10` to engine creation

### 4. Synchronous `requests` Library in Async Codebase
- **Signal**: `vulnerability_service.py:521` imports `requests` (synchronous) and runs in thread executor. The rest of the codebase is fully async.
- **System**: Replace with `httpx` (async-native HTTP client)
- **Impact**: Eliminates thread pool consumption during NVD scans, enables proper async rate limiting with `asyncio.sleep` instead of `time.sleep`
- **Effort**: low — drop-in replacement, `httpx.AsyncClient` has same API

### 5. Dual Ghidra Installations (JDK Version Mismatch)
- **Signal**: `backend/Dockerfile` installs Ghidra + JDK 21. `ghidra/Dockerfile` installs Ghidra + JDK 17 (Temurin). Same Ghidra version (11.3.1), different JDKs.
- **System**: Standardize on one Dockerfile or use the ghidra container from the backend
- **Impact**: Consistency, reduced image sizes, single point of Ghidra upgrades
- **Effort**: low — pick one JDK version, update both Dockerfiles

## Multi-Repo Considerations

This is a single-repo project. No cross-repo dependencies detected. The UART bridge script (`scripts/wairz-uart-bridge.py`) runs on the host outside Docker but is part of this repo. No `/workspace` coordination needed.
