# Campaign: Automated System Emulation (FirmAE)

**Status:** active
**Created:** 2026-04-05
**Seed:** `.planning/seeds/system-emulation-firmae.yaml`
**Estimated Sessions:** 3-4
**Baseline Typecheck Errors:** TBD (Phase 1)

## Direction

Add FirmAE-style automated full system emulation to Wairz by wrapping FirmAE as a
privileged sidecar Docker container with a thin Flask API shim, orchestrated by the
existing backend via Docker SDK. Users boot entire consumer router firmware images
and interact with running firmware network services (web UI, SSH, telnet) from the
browser with no manual steps.

## Phases

### Phase 1: Research — FirmAE Internals & Docker Integration Strategy
**Type:** research
**Status:** completed
**Estimated effort:** 1 sub-agent

**Scope:**
- Clone/inspect FirmAE repository: understand script pipeline (run.sh → inferNetwork.sh → makeNetwork.sh)
- Map FirmAE's kernel selection heuristics and supported architectures
- Identify FirmAE's PostgreSQL dependency and how the Flask shim should wrap it
- Determine Docker-in-Docker requirements: does FirmAE need --privileged, NET_ADMIN, or just specific caps?
- Identify which FirmAE scripts need modification for structured JSON output
- Survey FirmAE's pre-built kernels for ARM, MIPS, MIPSel
- Check FirmAE's license compatibility (MIT/GPL)

**End Conditions:**
| Condition | Type | Target |
|-----------|------|--------|
| Research brief written | file_exists | `.planning/research/firmae-integration-brief.md` |
| Flask shim API design documented | file_exists | `.planning/research/firmae-shim-api.md` |

**Deliverable:** Research brief with: FirmAE pipeline map, Docker requirements, shim API design, risk assessment.

---

### Phase 2: Build — FirmAE Sidecar Container + Flask API Shim
**Type:** build
**Status:** completed
**Estimated effort:** 1 sub-agent

**Scope:**
- Create `system-emulation/Dockerfile` — install FirmAE + deps, Python/Flask, QEMU system binaries, pre-built kernels
- Create `system-emulation/shim/app.py` — Flask API shim with `/start`, `/status`, `/ports`, `/stop` endpoints
- Shim wraps FirmAE pipeline: extraction → arch detection → kernel selection → network setup → boot → verify
- Internal ephemeral PostgreSQL for FirmAE state (started/stopped by shim)
- JSON progress events emitted at each pipeline stage
- Port discovery: nmap/ss scan after boot, return discovered services
- Add `system-emulation` service to `docker-compose.yml`
- Config vars: `SYSTEM_EMULATION_IMAGE`, `SYSTEM_EMULATION_TIMEOUT`, `SYSTEM_EMULATION_IDLE_TIMEOUT`

**End Conditions:**
| Condition | Type | Target |
|-----------|------|--------|
| Dockerfile exists | file_exists | `system-emulation/Dockerfile` |
| Flask shim exists | file_exists | `system-emulation/shim/app.py` |
| Docker Compose updated | command_passes | `grep -q 'system-emulation' docker-compose.yml` |
| Container builds | command_passes | `docker build -t wairz-system-emulation system-emulation/` |

**Dependencies:** Phase 1 research brief (FirmAE pipeline map, Docker requirements)

---

### Phase 3: Build — Backend Integration (Service, REST, DB Migration, MCP Tools)
**Type:** build
**Status:** completed
**Estimated effort:** 1-2 sub-agents

**Scope:**
- Extend `EmulationSession` model: add `discovered_services` JSONB, `system_emulation_stage`, `kernel_used`, `firmware_ip`, `nvram_state` JSONB, `idle_since`
- Create Alembic migration for new columns
- Add `SystemEmulationService` (or extend `EmulationService`) in services layer:
  - `start_system_emulation()` — create sidecar container, mount STORAGE_ROOT ro, call shim /start
  - `poll_system_status()` — poll shim /status, update DB with stage progress
  - `get_firmware_services()` — call shim /ports, return discovered services
  - `stop_system_emulation()` — call shim /stop, cleanup container
  - 1-per-project concurrency enforcement
  - 10-min pipeline timeout, 30-min idle timeout
  - Auto-cleanup on failure
- Add REST endpoints in `routers/emulation.py`:
  - `POST /api/v1/projects/{id}/emulation/system` — start system emulation
  - `GET /api/v1/projects/{id}/emulation/system/{session_id}` — status + services
  - `DELETE /api/v1/projects/{id}/emulation/system/{session_id}` — stop
- Add Pydantic schemas for system emulation requests/responses
- Register 8 MCP tools in `ai/tools/emulation.py`:
  - `start_system_emulation`, `system_emulation_status`, `list_firmware_services`
  - `run_command_in_firmware`, `stop_system_emulation`
  - `capture_network_traffic`, `get_nvram_state`, `interact_web_endpoint`
- Extend WebSocket proxy in `routers/terminal.py` — add TCP port forwarding endpoint for SSH/telnet

**End Conditions:**
| Condition | Type | Target |
|-----------|------|--------|
| Migration exists | file_exists | `backend/alembic/versions/*system_emulation*.py` |
| Service file exists | file_exists | `backend/app/services/system_emulation_service.py` |
| 8 MCP tools registered | command_passes | `grep -c 'start_system_emulation\|system_emulation_status\|list_firmware_services\|run_command_in_firmware\|stop_system_emulation\|capture_network_traffic\|get_nvram_state\|interact_web_endpoint' backend/app/ai/tools/emulation.py` (count >= 8) |
| REST endpoints exist | command_passes | `grep -c 'system' backend/app/routers/emulation.py` (count >= 3) |
| WebSocket TCP proxy | command_passes | `grep -q 'tcp_proxy\|system.*ws' backend/app/routers/terminal.py` |

**Dependencies:** Phase 2 (sidecar container must exist for service to orchestrate)

---

### Phase 4: Build — Frontend Mode Toggle + Service Discovery UI
**Type:** build
**Status:** completed
**Estimated effort:** 1 sub-agent

**Scope:**
- Add User Mode / System Mode toggle to EmulationPage
- Extend SessionCard for system emulation sessions (show stage progress, discovered services)
- Service discovery panel: list discovered services with:
  - HTTP services: clickable links opening in new tabs
  - SSH/telnet services: inline xterm.js terminal widget (connect via backend WS proxy)
- Stage progress display during FirmAE pipeline (extracting → detecting arch → selecting kernel → networking → booting → verifying)
- Error/failure display with logs and retry option
- Update TypeScript types for system emulation sessions and services
- Update API client with system emulation endpoints

**End Conditions:**
| Condition | Type | Target |
|-----------|------|--------|
| Mode toggle exists | command_passes | `grep -q 'System Mode\|system_mode\|systemMode' frontend/src/pages/EmulationPage.tsx` |
| Service list component | command_passes | `grep -q 'discovered_services\|ServiceList\|FirmwareServices' frontend/src/` -r` |
| Types updated | command_passes | `grep -q 'system_emulation\|SystemEmulation' frontend/src/types/index.ts` |
| TypeScript compiles | command_passes | `cd frontend && npx tsc --noEmit` |

**Dependencies:** Phase 3 (REST endpoints and schemas must exist for frontend to consume)

---

### Phase 5: Verify — End-to-End Testing with Real Firmware
**Type:** verify
**Status:** pending
**Estimated effort:** 1 sub-agent (may be blocked on firmware images)

**Scope:**
- Download test firmware: OpenWrt ARM, OpenWrt MIPS, DD-WRT MIPSel
- Boot each via system emulation, verify services exposed
- Test web UI reachability via browser link
- Test SSH/telnet via xterm.js terminal
- Test all 8 MCP tools against running sessions
- Test pipeline timeout (simulated hang)
- Test idle timeout
- Test auto-cleanup on failure
- Test 1-per-project concurrency limit

**End Conditions:**
| Condition | Type | Target |
|-----------|------|--------|
| 3 firmware images boot | manual | OpenWrt ARM + OpenWrt MIPS + DD-WRT MIPSel all reach running state |
| Web UI reachable | manual | At least one firmware HTTP interface accessible via browser |
| Terminal accessible | manual | At least one SSH/telnet session via xterm.js |
| MCP tools functional | manual | All 8 tools return valid output |
| Timeouts enforce | manual | Pipeline timeout at 10min, idle at 30min |

**Dependencies:** All prior phases

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-05 | Sidecar container, not reimplementation | Cleanest separation, easiest to maintain, preserves FirmAE's battle-tested heuristics |
| 2026-04-05 | Raw firmware blob to FirmAE | Don't fight FirmAE's assumptions about input format — its extraction is coupled to kernel selection |
| 2026-04-05 | Flask API shim (not log parsing) | Structured JSON endpoints beat fragile log parsing |
| 2026-04-05 | Extend existing EmulationPage (mode toggle) | Unified UX, no feature fragmentation |
| 2026-04-05 | Backend WS proxy (not ttyd in sidecar) | Reuses existing terminal.py pattern, no new dependencies |
| 2026-04-05 | Dynamic port mapping (not backend HTTP proxy) | Same proven pattern as user-mode emulation |
| 2026-04-05 | Ephemeral Postgres in sidecar | Fully isolated, no schema conflicts with Wairz DB |
| 2026-04-05 | AArch64 deferred | FirmAE doesn't support it — v2 feature |

## Feature Ledger

| Feature | Phase | Status | Notes |
|---------|-------|--------|-------|
| FirmAE research brief | 1 | completed | 419-line brief + 790-line shim API design |
| Sidecar Dockerfile | 2 | completed | Ubuntu 22.04, FirmAE, QEMU, Flask/gunicorn, internal Postgres |
| Flask API shim | 2 | completed | 7 endpoints: /start, /status, /ports, /stop, /health, /events, /output |
| DB migration | 3 | completed | 6 new columns on emulation_sessions |
| System emulation service | 3 | completed | 8 methods, Docker SDK + httpx shim client |
| REST endpoints | 3 | completed | 7 endpoints under /emulation/system |
| 8 MCP tools | 3 | completed | All 8 registered in register_emulation_tools() |
| WebSocket TCP proxy | 3 | completed | system_ws_router, TCP bridge to sidecar |
| Frontend mode toggle | 4 | completed | User Mode / System Mode tabs on EmulationPage |
| Service discovery UI | 4 | completed | FirmwareServicesPanel with clickable links + connect buttons |
| xterm.js SSH/telnet | 4 | completed | Connect via backend WS proxy, reuses EmulationTerminal |
| E2E firmware testing | 5 | pending | |

## Active Context

Phase 1 complete. Research produced:
- FirmAE pipeline map (4-phase: extract → arch detect → image prep → QEMU launch)
- Docker: needs --privileged, NET_ADMIN, SYS_ADMIN, /dev/net/tun, /dev/kvm
- Kernels: v2.6 (MIPS) + v4.1 (MIPS+ARM), vmlinux/zImage formats
- PostgreSQL: 5 tables, psycopg2 throughout — must keep Postgres
- NVRAM: LD_PRELOAD libnvram.so, tmpfs-backed
- License: MIT
- Flask shim: 9 endpoints designed, 15 pipeline event types

Phase 2 complete. Sidecar container built with:
- Dockerfile (Ubuntu 22.04 + FirmAE + QEMU + Flask/gunicorn + internal Postgres)
- Flask shim (7 endpoints, PipelineManager with stdout parsing, timeout watchdog)
- Entrypoint (Postgres init → gunicorn)
- Docker Compose integration + config settings

Phase 3 complete. Backend fully integrated:
- Alembic migration (6 columns), model updated
- SystemEmulationService (8 methods, Docker SDK + httpx)
- 7 REST endpoints
- 8 MCP tools
- WebSocket TCP proxy for SSH/telnet
- Router registered in main.py

Direction check (phase 2 of 3 build phases): Aligned — all architecture decisions from interview being followed.

Phase 4 complete. Frontend integrated:
- Mode toggle (User Mode / System Mode tabs)
- SystemEmulationPanel (4 states: idle, pipeline, running, error)
- FirmwareServicesPanel (service list, HTTP links, SSH/telnet connect)
- SessionCard extended for system mode metadata
- TypeScript compiles clean (0 errors)

Phases 1-4 all complete. Phase 5 (E2E verification) requires running Docker and real firmware images — blocked on runtime environment.

## Continuation State

```
current-phase: 5
current-step: blocked-on-runtime
checkpoint-phase-4: none
```

## Review Queue

(empty)
