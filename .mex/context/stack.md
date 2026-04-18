---
name: stack
description: Technology stack and library choices for Wairz backend (Python 3.12 + FastAPI async) and frontend (React 19 + Vite + TS). Load when working with specific technologies or making decisions about libraries and tools.
triggers:
  - "library"
  - "package"
  - "dependency"
  - "which tool"
  - "technology"
  - "pyproject"
  - "package.json"
edges:
  - target: context/decisions.md
    condition: when the reasoning behind a tech choice is needed
  - target: context/conventions.md
    condition: when understanding how to use a technology in this codebase
  - target: context/architecture.md
    condition: when a library's role depends on how components connect
last_updated: 2026-04-17
---

# Stack

## Core Technologies

- **Python 3.12** — backend language (`requires-python = ">=3.12"` in `backend/pyproject.toml`). Async everywhere.
- **FastAPI 0.115+** — REST API framework. Lifespan-managed via `asynccontextmanager`. Routers under `/api/v1/projects/{project_id}/...`.
- **SQLAlchemy 2.0 + asyncpg** — async ORM. Uses `Mapped`/`mapped_column` style (not legacy declarative). Alembic 1.14 for migrations.
- **PostgreSQL 16 (alpine)** — primary store. JSONB for `analysis_cache`.
- **Redis 7 (alpine)** — arq job queue + SSE event bus.
- **React 19 + TypeScript 5.9 + Vite 6** — frontend. Strict TS with `tsc -b` in the build pipeline.
- **Node (pnpm workspace detected, but frontend uses `npm`)** — `frontend/package.json` scripts are `npm run dev/build/lint`. Root `pnpm-lock.yaml` exists for top-level tooling only.
- **Docker Compose** — orchestrates postgres, redis, backend, worker, emulation, fuzzing, system-emulation, vulhunt, clamav, frontend.

## Key Libraries

### Backend
- **mcp[cli] >=1.2.0** — Model Context Protocol SDK. `wairz-mcp` entry point at `app.mcp_server:main`.
- **arq >=0.26.0** (not Celery) — Redis-backed async job queue. Worker entrypoint: `arq app.workers.arq_worker.WorkerSettings`.
- **docker >=7** — Python SDK used to launch QEMU/AFL++ sidecars.
- **androguard 4.1+ / mobsfscan / semgrep** — APK static analysis (`android.py`, `android_bytecode.py`, `android_sast.py` tools).
- **yara-python / clamd** — YARA rule scanning + ClamAV daemon integration.
- **pyelftools / lief / pefile / capstone** — binary parsing and disassembly.
- **nvdlib + packageurl-python** — CVE scanning (NVD) and PURL generation for SBOM.
- **weasyprint + pypdf** — PDF export of findings/reports.
- **scapy** — pcap analysis for emulation network captures.
- **pydantic-settings** — config via `app/config.py` (env-driven). `@lru_cache`'d `get_settings()`.

### Frontend
- **Zustand 5** (not Redux, not Context) — shared state in `src/stores/`: `projectStore`, `explorerStore`, `vulnerabilityStore`.
- **React Router DOM 7** — routing in `App.tsx`.
- **Axios 1.13** — API client in `src/api/client.ts` (single instance with interceptors).
- **Monaco Editor (@monaco-editor/react)** — binary/text/hex viewer in the file explorer.
- **@xyflow/react + @dagrejs/dagre** — component dependency graph (`ComponentMapPage`).
- **xterm + addon-fit** — terminal UI for emulation interaction (`terminal.ts` API).
- **react-arborist** — virtualised file tree (firmware can have 10K+ files).
- **shadcn/ui + radix-ui + Tailwind 4** — component primitives + design system.
- **Playwright** — E2E tests (`npm run test:e2e`).

## What We Deliberately Do NOT Use

- **No Celery** — arq is lighter, async-native, fits the FastAPI async model. Worker and backend share the same codebase; queue messages are typed Python.
- **No raw psycopg2 / raw SQL in app code** — always SQLAlchemy 2.0 async sessions. Raw SQL only appears in Alembic migrations.
- **No unittest** — `pyproject.toml` pins `asyncio_mode = "auto"` for pytest. Tests are async-first.
- **No Redux / no React Context for shared state** — Zustand only. Component-local `useState` is fine.
- **No class components** in frontend. Hooks only.
- **No CRA / Webpack** — Vite 6 only.
- **No raw `subprocess`** — always `asyncio.create_subprocess_exec` so the event loop is not blocked (Ghidra, radare2, binwalk3, unblob, docker CLI calls).
- **No inline Pydantic models in router files** — request/response schemas live in `app/schemas/<name>.py` (9/10 routers follow this; see Learned Rule #12 in CLAUDE.md).
- **No router function names that shadow service function imports** — suffix router endpoints with `_endpoint` (Learned Rule #10).

## Version Constraints

- **Python 3.12** required (not 3.11) — some dependencies and type syntax assume 3.12.
- **React 19** — concurrent features are available; `react-dom/server` APIs have changed since 18.
- **Vite 6 / TS 5.9** — `tsc -b` project-references build. If you add a new top-level package inside `frontend/`, update `tsconfig.*.json` references.
- **binwalk v3** (not v2) — flag surface differs; Learned Rule #6 requires grepping all flags before any version bump.
