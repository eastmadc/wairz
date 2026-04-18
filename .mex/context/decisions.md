---
name: decisions
description: Key architectural and technical decisions with reasoning. Load when making design choices or understanding why something is built a certain way.
triggers:
  - "why do we"
  - "why is it"
  - "decision"
  - "alternative"
  - "we chose"
edges:
  - target: context/architecture.md
    condition: when a decision relates to system structure
  - target: context/stack.md
    condition: when a decision relates to technology choice
  - target: context/mcp-tools.md
    condition: when the decision concerns the MCP dispatch model or tool registry
last_updated: 2026-04-17
---

# Decisions

## Decision Log

### Expose analysis via MCP stdio server (not a custom HTTP/websocket AI protocol)
**Date:** 2025 (initial design)
**Status:** Active
**Decision:** The AI surface is a `wairz-mcp` stdio CLI (`app.mcp_server:main`) implementing the Model Context Protocol. Any MCP-compatible client (Claude Code, Claude Desktop, Cursor, OpenCode, Codex, Gemini CLI, Windsurf, VS Code Copilot) can plug in unchanged.
**Reasoning:** Interoperability. MCP already has an ecosystem; building a proprietary protocol would tie users to one AI vendor. Stdio keeps the transport dependency-free.
**Alternatives considered:** Custom `/ai/chat` HTTP endpoint in FastAPI with Anthropic SDK (rejected — requires backend-stored API keys and couples to one vendor); gRPC (rejected — extra protocol surface for no MCP clients).
**Consequences:** Backend never stores an `ANTHROPIC_API_KEY`. All tool handlers must fit the MCP contract (JSON input schema, text content output ≤ 30KB). Tool state is per-client-process; cross-client coordination goes through PostgreSQL.

### Mutable `ProjectState` dataclass for MCP project switching
**Date:** 2025
**Status:** Active
**Decision:** `wairz-mcp` holds a single `ProjectState` dataclass whose fields are mutated in place by the `switch_project` tool. All tool handler closures reference the same instance.
**Reasoning:** Restarting the MCP process per project breaks long-running MCP client sessions (especially Claude Desktop). Mutating shared state keeps the stdio connection alive.
**Alternatives considered:** Per-tool `project_id` parameter (rejected — adds 1 required arg to every tool); child-process pool keyed by project (rejected — complexity, lost caches on switch).
**Consequences:** Tool handlers read project context from `ToolContext`, which reads from the shared `ProjectState`. Adding new project-scoped fields means updating the dataclass + `switch_project` side effects.

### Cache Ghidra decompilations and radare2 analysis by SHA256 in `analysis_cache` (JSONB)
**Date:** 2025
**Status:** Active
**Decision:** Decompilations and per-binary analyses are cached in a `analysis_cache` table keyed by `(binary_sha256, operation, VARCHAR(512))` with a JSONB result column.
**Reasoning:** Ghidra headless takes 30–120s per function. Rerunning on every MCP query destroys UX and wastes CPU. JSONB lets us cache arbitrary tool shapes without schema churn.
**Alternatives considered:** Redis cache (rejected — not durable across restarts; SBOM/CVE results need permanence); filesystem cache (rejected — harder to query/evict).
**Consequences:** `operation` was originally VARCHAR(100); JADX class names with inner classes + `$$ExternalSyntheticLambda0` hit 150+ chars → widened to 512 (Learned Rule #15). Any new cached operation key must fit in 512 chars or use a hash.

### arq (Redis) for background jobs, not Celery
**Date:** 2025
**Status:** Active
**Decision:** The `worker` container runs `arq app.workers.arq_worker.WorkerSettings` for firmware unpacking, Ghidra prefill, and vuln scanning.
**Reasoning:** arq is async-native, matches FastAPI's async idiom, and has no RabbitMQ/Kombu surface. Serialisation is typed Python.
**Alternatives considered:** Celery (rejected — sync worker model, broker complexity), FastAPI BackgroundTasks only (rejected — no durability across restarts, no retries).
**Consequences:** `worker` and `backend` share the same Dockerfile/image. Both must be rebuilt together — a stale worker breaks Alembic migrations and silently blocks ALL jobs (Learned Rule #8).

### Host-side TCP bridges for USB hardware (UART + ADB), not Docker passthrough
**Date:** 2025
**Status:** Active
**Decision:** `scripts/wairz-uart-bridge.py` (TCP 9999) and `scripts/wairz-device-bridge.py` (TCP 9998) run on the host. The backend reaches them via `host.docker.internal` with newline-delimited JSON + id correlation.
**Reasoning:** USB serial and ADB passthrough to Docker is fragile across Linux distros and udev. Host-side bridges with `pyserial`-only / `adb`-on-PATH dependencies are portable.
**Alternatives considered:** `--device=/dev/ttyUSB0` in compose (rejected — device may come and go); privileged container with udev (rejected — security surface).
**Consequences:** `UART_BRIDGE_HOST` and `DEVICE_BRIDGE_HOST` must be `host.docker.internal` (never `localhost`). Requires iptables rule `INPUT -i docker0 -p tcp --dport {9998,9999} -j ACCEPT` on Linux hosts. Documented in CLAUDE.md setup.

### Emulation and fuzzing run in isolated sibling containers launched via the Docker socket
**Date:** 2025
**Status:** Active
**Decision:** `wairz-emulation` (QEMU), `wairz-fuzzing` (AFL++), `wairz-system-emulation` (FirmAE) are built with `profiles: ["build"]` and spawned on-demand by the backend through `/var/run/docker.sock`. They attach to the `wairz_emulation_net` external network, mount `firmware_data:/data/firmware:ro`, and have memory + PID cgroup limits.
**Reasoning:** Never execute firmware on the host. Sibling-container isolation gives cgroup limits per run, reproducible images, and clean teardown. Read-only firmware mount prevents tampering.
**Alternatives considered:** In-process QEMU subprocess (rejected — no isolation); Kubernetes jobs (rejected — overkill, not everyone has a cluster).
**Consequences:** Backend needs Docker socket access (`DOCKER_GID` env var must match host socket group). The `emulation_net` network is declared `external: true` and must be created before first compose up, or backend panics on boot.

### Schemas in `app/schemas/`, never inline in routers
**Date:** 2025
**Status:** Active
**Decision:** All Pydantic request/response models live under `app/schemas/<resource>.py`. Routers import them.
**Reasoning:** 9/10 existing routers follow this. Inline models cause forward-reference issues with SQLAlchemy relationships and violate project convention.
**Alternatives considered:** Inline models per router (rejected — the 10th case broke at runtime — Learned Rule #12).
**Consequences:** New resources must create `schemas/<name>.py` up front. Response model declared on the route decorator.
