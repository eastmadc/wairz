---
name: agents
description: Always-loaded project anchor. Read this first. Contains project identity, non-negotiables, commands, and pointer to ROUTER.md for full context.
last_updated: 2026-04-17
---

# Wairz

## What This Is
A browser-based firmware reverse-engineering and security-assessment platform (FastAPI + React + MCP) that unpacks firmware, runs binary/SBOM/emulation/fuzzing analyses, and exposes 65+ analysis tools to MCP-compatible AI agents.

## Non-Negotiables
- Every filesystem access inside extracted firmware MUST be validated via `app/utils/sandbox.py` (`validate_path` / `ToolContext.resolve_path`). Never open a user-supplied path directly.
- Never execute firmware binaries on the host — emulation runs in the QEMU sidecar, fuzzing in the AFL++ sidecar, both with memory/CPU/PID limits.
- MCP tool handlers use `context.db.flush()` — never `commit()`. The outer MCP dispatch owns the transaction.
- Never `asyncio.gather()` coroutines that share a single `AsyncSession`. Use sequential `await` or create a fresh session per task via `async_session_factory()`.
- After a backend code change, `docker compose up -d --build backend worker` — rebuild BOTH, never just `backend` (stale worker breaks Alembic + all background jobs).

## Commands
Backend (in Docker):
- Up: `docker compose up -d --build backend worker`
- Logs: `docker compose logs -f backend`
- Shell: `docker compose exec backend bash`
- Migration: `docker compose exec backend alembic revision --autogenerate -m "msg"` (applied on container start)

Frontend (`cd frontend`):
- Dev: `npm run dev` (Vite, port 5173 locally / 3000 in compose)
- Build: `npm run build` (tsc + vite build)
- Lint: `npm run lint`
- E2E: `npm run test:e2e` (Playwright)

Full-stack dev: `./launch.sh` (starts postgres+redis containers, runs backend via `uv`, frontend via Vite).

## Scaffold Growth
After every task: if no pattern exists for the task type you just completed, create one. If a pattern or context file is now out of date, update it. The scaffold grows from real work, not just setup. See the GROW step in `ROUTER.md` for details.

## Navigation
At the start of every session, read `ROUTER.md` before doing anything else.
For full project context, patterns, and task guidance — everything is there.
