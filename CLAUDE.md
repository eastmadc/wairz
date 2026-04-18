# CLAUDE.md — Wairz Codebase Guide

This file is for AI agents (Claude Code, etc.) working on the Wairz codebase. It describes the architecture, conventions, and patterns you need to follow when making changes.

**What is Wairz?** An open-source, browser-based firmware reverse engineering and security assessment platform. Users upload firmware, the tool unpacks it, and provides a unified interface for filesystem exploration, binary analysis, emulation, fuzzing, and security assessment — augmented by an AI assistant connected via MCP (Model Context Protocol). See `README.md` for user-facing documentation.

---

## Architecture Overview

```
Claude Code / Claude Desktop
        │
        │ MCP (stdio)
        ▼
┌─────────────────┐     ┌──────────────────────────────────┐
│   wairz-mcp     │────▶│         FastAPI Backend           │
│  (MCP server)   │     │                                    │
│  65+ tools      │     │  Services: firmware, file,         │
│                 │     │  analysis, emulation, fuzzing,     │
│  Entry point:   │     │  sbom, uart, finding, export...    │
│  wairz-mcp CLI  │     │                                    │
└─────────────────┘     │  Ghidra headless · QEMU · AFL++    │
                        └──────────┬───────────────────────┘
                                   │
┌──────────────┐    ┌──────────────┼──────────────┐
│   React SPA  │───▶│  PostgreSQL  │  Redis       │
│  (Frontend)  │    │              │              │
└──────────────┘    └──────────────┴──────────────┘

Host machine (optional):
  wairz-uart-bridge.py ←─ TCP:9999 ─→ Docker backend
```

- **Frontend:** React 19 + Vite + TypeScript, shadcn/ui + Tailwind, Monaco Editor, ReactFlow, xterm.js, Zustand
- **Backend:** Python 3.12 + FastAPI (async), SQLAlchemy 2.0 (async) + Alembic, pydantic-settings
- **MCP Server:** `wairz-mcp` CLI entry point (`app.mcp_server:main`), stdio transport, 65+ tools
- **Database:** PostgreSQL 16 (JSONB for analysis cache)
- **Containers:** Docker Compose — backend, postgres, redis, emulation (QEMU), fuzzing (AFL++)

---

## Directory Structure

```
wairz/
├── backend/
│   ├── pyproject.toml           # Entry point: wairz-mcp
│   ├── alembic/versions/        # Database migrations (auto-run on container start)
│   └── app/
│       ├── main.py              # FastAPI app + router registration
│       ├── config.py            # Settings via pydantic-settings
│       ├── database.py          # Async engine, session factory, get_db dependency
│       ├── mcp_server.py        # MCP server with dynamic project switching
│       ├── models/              # SQLAlchemy ORM models
│       ├── schemas/             # Pydantic request/response schemas
│       ├── routers/             # FastAPI REST endpoint routers
│       ├── services/            # Business logic layer
│       ├── workers/             # Background tasks (firmware unpacking)
│       ├── ai/
│       │   ├── __init__.py      # Tool registry factory — registers all tool categories
│       │   ├── tool_registry.py # ToolContext + ToolRegistry framework
│       │   ├── system_prompt.py # MCP system prompt for Claude
│       │   └── tools/           # Tool handlers by category
│       └── utils/
│           ├── sandbox.py       # Path traversal prevention (CRITICAL)
│           └── truncation.py    # Output truncation (30KB max)
├── frontend/
│   └── src/
│       ├── pages/               # Route pages, registered in App.tsx
│       ├── components/          # UI components organized by feature
│       ├── api/                 # Axios API client functions
│       ├── stores/              # Zustand state management
│       └── types/               # TypeScript type definitions
├── ghidra/
│   ├── Dockerfile
│   └── scripts/                 # Custom Java analysis scripts for headless Ghidra
├── emulation/
│   ├── Dockerfile               # QEMU + kernels (ARM, MIPS, MIPSel, AArch64)
│   └── scripts/                 # start-user-mode.sh, start-system-mode.sh, serial-exec.sh
├── fuzzing/
│   └── Dockerfile               # AFL++ with QEMU mode
└── scripts/
    └── wairz-uart-bridge.py     # Host-side serial bridge (standalone, pyserial only)
```

---

## How to Add Things

### Adding a New MCP Tool

1. Create or edit a handler in `backend/app/ai/tools/<category>.py`:
   ```python
   async def _handle_my_tool(input: dict, context: ToolContext) -> str:
       # Available on context: project_id, firmware_id, extracted_path, db
       path = context.resolve_path(input.get("path", "/"))  # validates against sandbox
       # ... do work ...
       return "result string (max 30KB, truncated automatically)"
   ```
2. Register in the same file's `register_<category>_tools(registry)` function:
   ```python
   registry.register(name="my_tool", description="...", input_schema={...}, handler=_handle_my_tool)
   ```
3. If it's a new category file, import and call `register_<category>_tools(registry)` in `backend/app/ai/__init__.py`.

### Adding a New REST Endpoint

1. Create router: `backend/app/routers/<name>.py`
   ```python
   router = APIRouter(prefix="/api/v1/projects/{project_id}/<name>", tags=["<name>"])
   ```
2. Register in `backend/app/main.py`: `app.include_router(<name>.router)`
3. Create Pydantic schemas in `backend/app/schemas/<name>.py` (use `from_attributes=True` for ORM compatibility)
4. Create service in `backend/app/services/<name>_service.py`

### Adding a Database Table

1. Create model in `backend/app/models/<name>.py`:
   - Use SQLAlchemy `Mapped`/`mapped_column` style
   - UUID primary key with dual defaults: `default=uuid.uuid4` + `server_default=func.gen_random_uuid()`
   - Foreign keys with `cascade="all, delete-orphan"` on relationships
2. Create Alembic migration: `alembic revision --autogenerate -m "description"`
3. Migrations run automatically on container startup

### Adding a Frontend Page

1. Create page component in `frontend/src/pages/<Name>Page.tsx`
2. Register route in `frontend/src/App.tsx`
3. Create API client functions in `frontend/src/api/<name>.ts`
4. Use Zustand stores (`frontend/src/stores/`) for shared state
5. UI components from shadcn/ui + Tailwind

---

## Critical Rules

### Security

1. **Path traversal prevention is mandatory.** Every file access must be validated via `app/utils/sandbox.py` (`os.path.realpath()` + prefix check against the extracted root). The MCP `ToolContext.resolve_path()` method handles this — always use it. REST endpoints that serve filesystem paths (e.g. `GET /hardware-firmware/{blob_id}/download`) must also `realpath` BOTH sides before comparison so symlinks placed inside the sandbox that point outside are rejected. See `test_symlink_to_outside_is_rejected` in `test_hardware_firmware_router.py` for the canonical test shape.
2. **Never execute firmware binaries on the host.** Emulation runs inside an isolated QEMU Docker container. Fuzzing runs inside an isolated AFL++ Docker container. Both have resource limits (memory, CPU).
3. **No API keys stored in the backend.** The Anthropic API key is user-provided via their Claude Code/Desktop configuration and never touches Wairz.

### Performance

1. **Cache Ghidra decompilations** — each run takes 30-120s. Cached by binary hash + function name in the `analysis_cache` table.
2. **Cache radare2 analysis** — `aaa` can take 10-30s. LRU session caching in the analysis service.
3. **Lazy-load the file tree** — firmware can have 10K+ files. Load children on expand, never the full tree at once.
4. **Truncate MCP tool outputs** — keep under 30KB (`app/utils/truncation.py`). Large outputs break MCP clients.
5. **Firmware unpacking is non-blocking** — the unpack endpoint returns 202 and runs `asyncio.create_task()`. The frontend polls every 2s until status changes from "unpacking".

### Conventions

- **Backend:** Async everywhere (SQLAlchemy async sessions, `asyncio.create_subprocess_exec` for subprocesses). Use `async_session_factory` from `database.py` for DB access outside request context (e.g., background tasks).
- **Frontend:** Zustand for state, API functions in `src/api/`, pages poll with `useEffect` + `setInterval` for long-running operations (see EmulationPage, FuzzingPage, ProjectDetailPage for the pattern).
- **Docker:** Backend has access to Docker socket for managing emulation/fuzzing containers. Emulation containers run on an internal `emulation_net` network.

### Learned Rules (from `.planning/knowledge/`)

These rules were extracted from recurring bugs and failures across 30+ development sessions:

1. **Use `docker compose up -d` not `restart` after code changes.** `restart` reuses the old container image. `up -d` recreates it with the new build. This mistake has caused false "it works locally" debugging in multiple sessions.
2. **Add new Python dependencies to `pyproject.toml` immediately.** Code that imports a new package must update `pyproject.toml` in the same commit. Verify in Docker: `docker compose exec backend python -c "import <module>"`.
3. **Use `flush()` not `commit()` in MCP tool handlers.** The outer MCP dispatch in `mcp_server.py` owns the transaction. Tool handlers should use `context.db.flush()` so writes are visible within the session but rollback works on exceptions.
4. **Match Pydantic response schemas to ORM model fields exactly.** When adding a new backend service for an existing MCP endpoint, read the response schema first and construct the return dict to match. Schema/model mismatches cause silent 500 errors.
5. **Wrap sync filesystem I/O in `run_in_executor()` inside async handlers.** Large firmware (10K+ files) stalls the uvicorn event loop. CPU-bound or filesystem-heavy operations must use `await loop.run_in_executor(None, sync_fn, args)`.
6. **Verify CLI tool flags when upgrading versions.** Before swapping any CLI tool (e.g., binwalk v2→v3), grep the codebase for ALL flags used and verify each exists in the new version's `--help`. Test with real data.
7. **Never `asyncio.gather()` on coroutines sharing a SQLAlchemy `AsyncSession`.** `AsyncSession` is not safe for concurrent coroutine access. Gather'd coroutines that share a session cause state corruption, lost writes, or runtime exceptions. Use sequential `await` calls, or create independent sessions per task via `async_session_factory()`.
8. **Rebuild `worker` whenever you rebuild `backend`.** They share the same Dockerfile and codebase. A stale worker image causes Alembic migration failures (worker can't find new revisions) and silently blocks ALL background jobs (unpack, Ghidra, vuln scan). Use `docker compose up -d --build backend worker`, never just `backend` alone.
9. **When adding new backend enum/source values, update all frontend `Record<Type, ...>` lookups.** TypeScript `Record<UnionType, Config>` maps are exhaustive — a new backend value not present in the map returns `undefined`, crashing React with a blank page. Grep for `Record<{TypeName},` across the frontend before deploying. Add `?? fallback` to strict lookups as defense in depth.
10. **Never name a router endpoint function the same as an imported service function.** Python silently rebinds the name: the `def` at module scope overwrites the import. Callers of the "service function" get the router function instead, with completely wrong parameter types. Convention: suffix router functions with `_endpoint` (e.g., `run_clamav_scan_endpoint`) when they share a conceptual name with a service import.
11. **After splitting a large file, verify all module-level constants are accessible.** `py_compile` and import checks pass even when a method references a constant that was left in the original file. The `NameError` only surfaces at runtime when the method is actually called. Always run an API call or integration test against the split code before deploying.
12. **Pydantic response models go in `schemas/`, not in routers.** 9/10 Wairz routers import models from `app/schemas/`. Defining models inline in router files causes forward reference issues and violates the project convention.
13. **For Android firmware analysis, detect platform signing via manifest heuristics, not certificate negation.** Equating "not debug-signed AND in priv-app" with "platform-signed" is a false equivalence. Use the 3-tier heuristic in `_has_signature_or_system_protection()`: declared signatureOrSystem permissions, requested platform-only permissions, system shared UIDs.
14. **When checking firmware paths, match partition prefixes, not bare directory names.** `"priv-app" in path.split(os.sep)` matches too broadly. Check `system/priv-app`, `product/priv-app`, `vendor/priv-app`, `system_ext/priv-app` as partition/directory pairs. Use `is_priv_app_path()` from `_android_helpers.py`.
15. **When reusing DB columns for new data types, verify value lengths.** Java class names with inner classes and synthetic lambdas (`$$ExternalSyntheticLambda0`) commonly reach 150+ characters. The `analysis_cache.operation` column needed VARCHAR(512), not VARCHAR(100), for JADX cache keys.
16. **When walking a Firmware extraction, always use `get_detection_roots(firmware)`, never `firmware.extracted_path` alone.** The `extracted_path` column stores ONE rootfs the unpacker chose; scatter-zip uploads, multi-archive medical firmware, and nested unblob output produce sibling directories that `extracted_path` misses entirely. Helper in `app/services/firmware_paths.py` returns the complete list, cached in `device_metadata["detection_roots"]` JSONB. Per-binary flows (emulation/fuzzing/sandbox) may still use `extracted_path` since they need a single binary path — filesystem walks must use the helper. Originally uncovered by the DPCS10 Android bug (md1dsp.img invisible) and reproduced on the RespArray ZIP (0 blobs before fix, 11+ after).
17. **Canary a silent CLI exit before trusting it.** `tsc -b`, incremental build tools, and some linters exit 0 with no output when their cache says nothing changed — indistinguishable from "didn't run at all." If a non-trivial change produced zero output, feed the tool a known-bad input (e.g. write a one-line TS file with `const x: number = "str"` and re-run). If the canary ALSO passes silently, the tool is not actually checking. Applies to any verification step whose success criterion is "exit 0."
18. **After an Android scatter extraction, the extraction container itself is a detection root when it holds raw images at top level.** `_relocate_scatter_subdirs` moves `.img`/`.bin` files from `extracted/<version>/` into `extracted/`. `firmware_paths._compute_roots_sync` only scans SUBDIRECTORIES of the container for qualifying children; top-level files would be invisible to detection unless the container itself is promoted. The fix in `_compute_roots_sync` uses `_dir_has_raw_image(container)` (strict extension list, non-recursive) so the container is added only when it genuinely holds firmware blobs. Regression uncovered by DPCS10 upload 0ed279d8 losing 14 MTK blobs (lk / tee / gz / preloader / scp / sspm / spmfw / md1dsp / modem / cam_vpu×3 / dtbo). See `test_post_relocation_layout_includes_container` and `test_linux_rootfs_only_container_not_included` in `test_firmware_paths.py` for the contract.
19. **Evidence-first before writing remediation code.** When an intake, seed, or spec prescribes a backfill / cleanup / migration for "legacy rows that look like X", measure the condition first — a single SQL `COUNT(*)` or `grep` usually settles it in one second. If the count is zero, close the thread with a documented no-op; don't write a dormant utility "for safety." Spec-driven coding against a condition that's already been silently resolved produces dead abstractions that rot into maintenance burden. Originally applied to the A.3 null-tier CVE backfill seed item — spec said 2,918 null-tier rows/firmware; live DB showed 0; fix was a doc note, not 50 LOC. The discipline is: the spec describes intent, the DB describes truth — trust the DB.
20. **When iterating a single-file change against a stale running container, use `docker cp` + in-container tool, not a full rebuild.** A running backend/worker container with no dev bind mount (typical: containers from a previous session) won't see host-side new files. If the change is a single file added under an existing mount point — e.g. a new alembic migration at `backend/alembic/versions/NNNN_*.py` — copy it in with `docker cp host/path.py <container>:/app/…/path.py` and run the tool via `docker compose exec -T -w /app -e PYTHONPATH=/app backend /app/.venv/bin/<tool>`. `PYTHONPATH=/app` + `-w /app` are both required for alembic to import `app.database`. This turns a 3–5 min rebuild (CLAUDE.md rule #8) into a <30 s iteration. Still rebuild backend+worker before trusting for the next session — the `docker cp` is for validation speed, not durable state.

---

## MCP Server

Entry point: `wairz-mcp = "app.mcp_server:main"` (defined in `pyproject.toml`)

The server uses a mutable `ProjectState` dataclass so all project context (project_id, firmware_id, extracted_path) can be switched dynamically via the `switch_project` tool without restarting the MCP process.

### Tool Categories (65+)

| Category | File | Tools |
|----------|------|-------|
| Project | `tools/filesystem.py` | `get_project_info`, `switch_project`, `list_projects` |
| Filesystem | `tools/filesystem.py` | `list_directory`, `read_file`, `search_files`, `file_info`, `find_files_by_type`, `get_component_map`, `get_firmware_metadata`, `extract_bootloader_env` |
| Strings | `tools/strings.py` | `extract_strings`, `search_strings`, `find_crypto_material`, `find_hardcoded_credentials` |
| Binary | `tools/binary.py` | `list_functions`, `disassemble_function`, `decompile_function`, `list_imports`, `list_exports`, `xrefs_to`, `xrefs_from`, `get_binary_info`, `check_binary_protections`, `check_all_binary_protections`, `find_string_refs`, `resolve_import`, `find_callers`, `search_binary_content`, `get_stack_layout`, `get_global_layout`, `trace_dataflow`, `cross_binary_dataflow` |
| Security | `tools/security.py` | `check_known_cves`, `analyze_config_security`, `check_setuid_binaries`, `analyze_init_scripts`, `check_filesystem_permissions`, `analyze_certificate`, `check_kernel_hardening`, `scan_with_yara` |
| SBOM | `tools/sbom.py` | `generate_sbom`, `get_sbom_components`, `check_component_cves`, `run_vulnerability_scan` |
| Emulation | `tools/emulation.py` | `start_emulation`, `run_command_in_emulation`, `stop_emulation`, `check_emulation_status`, `get_emulation_logs`, `enumerate_emulation_services`, `diagnose_emulation_environment`, `troubleshoot_emulation`, `get_crash_dump`, `run_gdb_command`, `save_emulation_preset`, `list_emulation_presets`, `start_emulation_from_preset` |
| Fuzzing | `tools/fuzzing.py` | `analyze_fuzzing_target`, `generate_fuzzing_dictionary`, `generate_seed_corpus`, `generate_fuzzing_harness`, `start_fuzzing_campaign`, `check_fuzzing_status`, `stop_fuzzing_campaign`, `triage_fuzzing_crash`, `diagnose_fuzzing_campaign` |
| Comparison | `tools/comparison.py` | `list_firmware_versions`, `diff_firmware`, `diff_binary`, `diff_decompilation` |
| UART | `tools/uart.py` | `uart_connect`, `uart_send_command`, `uart_read`, `uart_send_break`, `uart_send_raw`, `uart_disconnect`, `uart_status`, `uart_get_transcript` |
| Reporting | `tools/reporting.py` | `add_finding`, `list_findings`, `update_finding`, `read_project_instructions`, `list_project_documents`, `read_project_document` |
| Android | `tools/android.py` | `analyze_apk`, `list_apk_permissions`, `check_apk_signatures`, `scan_apk_manifest` |
| Android Bytecode | `tools/android_bytecode.py` | `scan_apk_bytecode` |
| Android SAST | `tools/android_sast.py` | `scan_apk_sast` |
| Code | `tools/documents.py` | `save_code_cleanup` |

---

## UART Bridge Architecture

The bridge runs on the host (not in Docker) because USB serial adapters can't easily pass through to containers.

**How it works:**
- **Host:** `scripts/wairz-uart-bridge.py` is a standalone TCP server (only requires pyserial). It listens on TCP 9999 and proxies serial I/O.
- **Docker:** `uart_service.py` in the backend container connects to the bridge via `host.docker.internal:9999`
- **Protocol:** Newline-delimited JSON, request/response matched by `id` field
- **Important:** The bridge does NOT take a serial device path or baudrate on its command line. Those are specified by the MCP `uart_connect` tool at connection time.

**Starting the bridge:**
```bash
python3 scripts/wairz-uart-bridge.py --bind 0.0.0.0 --port 9999
```
The bridge will print "UART bridge listening on ..." when ready. It waits for connection commands from the backend.

**Connecting via MCP:** Call `uart_connect` with the `device_path` (e.g., `/dev/ttyUSB0`) and `baudrate` (e.g., 115200). The backend sends these to the bridge, which opens the serial port.

**Common setup issues (Bridge unreachable):**
1. `UART_BRIDGE_HOST` in `.env` must be `host.docker.internal` (NOT `localhost` — `localhost` inside Docker refers to the container, not the host)
2. An iptables rule is required to allow Docker bridge traffic to reach the host:
   ```bash
   sudo iptables -I INPUT -i docker0 -p tcp --dport 9999 -j ACCEPT
   ```
3. After changing `.env`, restart the backend: `docker compose restart backend`
4. After restarting the backend, reconnect MCP (e.g., `/mcp` in Claude Code)

---

## Device Acquisition Bridge

Similar to the UART bridge, the device bridge runs on the host to access ADB-connected Android devices.

**How it works:**
- **Host:** `scripts/wairz-device-bridge.py` is a standalone TCP server (only requires `adb` on PATH). Listens on TCP 9998.
- **Docker:** `device_service.py` connects to the bridge via `host.docker.internal:9998`
- **Protocol:** Same as UART bridge — newline-delimited JSON, request/response matched by `id` field
- **Commands:** `list_devices`, `get_device_info`, `dump_partition`, `dump_all`, `get_dump_status`, `cancel_dump`, `resume_dump`
- **Frontend:** 4-step wizard at `/projects/{id}/device` — Connect → Select Device → Dump Progress → Summary/Import

**Starting the bridge:**
```bash
python3 scripts/wairz-device-bridge.py --bind 0.0.0.0 --port 9998
```

**Mock mode (for development without a real device):**
```bash
python3 scripts/wairz-device-bridge.py --mock --port 9998
```

**Setup (same pattern as UART bridge):**
1. `DEVICE_BRIDGE_HOST` in `.env` must be `host.docker.internal`
2. iptables rule: `sudo iptables -I INPUT -i docker0 -p tcp --dport 9998 -j ACCEPT`
3. Restart backend after `.env` changes

---

## Environment Variables

See `.env.example` for defaults. Key variables:

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string (asyncpg) |
| `REDIS_URL` | Redis connection string |
| `POSTGRES_HOST_PORT` | Host-side port for PostgreSQL (default 5432, change if port conflicts) |
| `REDIS_HOST_PORT` | Host-side port for Redis (default 6379, change if port conflicts) |
| `DOCKER_GID` | Docker socket GID for container access (run `stat -c %g /var/run/docker.sock`) |
| `STORAGE_ROOT` | Where firmware files are stored on disk |
| `MAX_UPLOAD_SIZE_MB` | Maximum firmware upload size (default 2048) |
| `MAX_TOOL_OUTPUT_KB` | MCP tool output truncation limit (default 30) |
| `GHIDRA_PATH` / `GHIDRA_SCRIPTS_PATH` | Ghidra headless installation paths |
| `GHIDRA_TIMEOUT` | Decompilation timeout in seconds (default 120) |
| `EMULATION_IMAGE` / `EMULATION_NETWORK` | Docker image and network for QEMU containers |
| `FUZZING_IMAGE` / `FUZZING_TIMEOUT_MINUTES` | Docker image and timeout for AFL++ containers |
| `UART_BRIDGE_HOST` / `UART_BRIDGE_PORT` | Host-side UART bridge connection |
| `DEVICE_BRIDGE_HOST` / `DEVICE_BRIDGE_PORT` | Host-side device acquisition bridge (default: host.docker.internal:9998) |
| `NVD_API_KEY` | Optional, for higher NVD rate limits during CVE scanning |

---

## Testing Firmware

Good images for development and testing:

- **OpenWrt** (MIPS, ARM) — well-structured embedded Linux with lots of components
- **DD-WRT** — similar to OpenWrt
- **DVRF** (Damn Vulnerable Router Firmware) — intentionally vulnerable, great for security tool testing

---

## Citadel Harness

This project uses the [Citadel](https://github.com/SethGammon/Citadel) agent
orchestration harness. Configuration is in `.claude/harness.json`.
