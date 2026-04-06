# Patterns: Automated System Emulation (FirmAE)

> Extracted: 2026-04-05
> Campaign: .planning/campaigns/system-emulation-firmae.md
> Postmortem: none

## Successful Patterns

### 1. Ouroboros Interview Before Architecture Decisions
- **Description:** Used a 12-question Socratic interview (Ouroboros MCP) to crystallize requirements before writing any code. Each answer was routed through PATH 1 (code confirmation), PATH 2 (human judgment), or PATH 3 (both) to minimize user burden while maximizing decision quality.
- **Evidence:** Ambiguity dropped from 0.40 to 0.18 across 12 rounds. All 8 architecture decisions in the Decision Log trace directly to interview answers. Zero rework from unclear requirements.
- **Applies when:** Starting any large feature with multiple integration points or unclear tradeoffs. Most valuable when the feature wraps an external tool (FirmAE, FirmADyne, etc.) where assumptions about integration approach are costly to change.

### 2. Sidecar Container with API Shim Pattern
- **Description:** Wrapped a complex third-party tool (FirmAE, bash scripts + internal PostgreSQL) in a Docker sidecar with a thin Flask API shim, rather than reimplementing or deeply integrating. The shim translates REST requests into FirmAE pipeline operations.
- **Evidence:** All build phases completed without rework. The sidecar approach isolated FirmAE's dependencies (PostgreSQL, cross-compilers, binwalk) from Wairz's stack. Backend communicates via httpx to structured JSON endpoints.
- **Applies when:** Integrating any tool that has: complex native dependencies, its own state management, shell-script-based workflows, or assumptions about running as root. Pattern: Docker sidecar + REST/WebSocket shim + Docker SDK orchestration from the backend.

### 3. Research Phase Before Build Phases
- **Description:** Dedicated Phase 1 to deep research (1,200 lines) covering FirmAE's pipeline map, Docker requirements, pre-built kernels, PostgreSQL usage, network setup, and NVRAM emulation. This research directly informed the shim API design and Dockerfile.
- **Evidence:** Research brief identified 4 high risks and 5 medium risks. Critical finding: FirmAE hardcodes user "firmadyne" with password "firmadyne" — discovered in research, would have been a debugging nightmare otherwise. Flask shim API was designed with full understanding of FirmAE's 4-phase pipeline.
- **Applies when:** Any campaign integrating an external open-source tool. The research phase pays for itself by preventing cascading debugging sessions during build phases.

### 4. Extend Existing Model with Nullable Columns
- **Description:** Extended the existing `EmulationSession` model with 6 new nullable JSONB/string columns instead of creating a separate table. This preserved the unified session management UI and avoided join complexity.
- **Evidence:** Migration `b5c6d7e8f9a0` applied cleanly to production DB with existing rows. Frontend SessionCard conditionally displays system emulation metadata when present. Zero schema conflicts.
- **Applies when:** Adding a new "mode" to an existing feature where the data model is 70%+ shared. Nullable columns are cheaper than a new table + joins when the UI already renders the base entity.

### 5. Docker Compose Network Visibility
- **Description:** Connected the backend container to both `default` and `emulation_net` networks in docker-compose.yml, so the backend can reach sidecar containers by their Docker network IP.
- **Evidence:** First attempt failed with `httpx.ConnectTimeout` because backend was only on `wairz_default` (172.20.x.x) while sidecars were on `wairz_emulation_net` (172.21.x.x). Adding `networks: [default, emulation_net]` to the backend service resolved it immediately.
- **Applies when:** Any service that needs to communicate with dynamically-created containers on a separate Docker network. Always verify network membership before assuming containers can talk.

### 6. Iterative Dockerfile Debugging via Sidecar Output Endpoint
- **Description:** The Flask shim's `/output` endpoint (pipeline stdout lines) was invaluable for debugging FirmAE failures inside the sidecar. Each missing dependency was identified by checking the output endpoint rather than guessing.
- **Evidence:** Identified 5 missing dependencies in sequence: python-magic, bc, file, bash-static, and the firmadyne PostgreSQL role. Each was found via `/output` returning the exact error.
- **Applies when:** Any sidecar that wraps a complex pipeline. Always include a "raw output" endpoint for debugging — it's the equivalent of `docker logs` but filtered to the active pipeline.

### 7. Patch Script Instead of Inline Sed in Dockerfile
- **Description:** After struggling with escaped sed commands in the Dockerfile `RUN` block (shell escaping + Docker layering = fragile), moved all FirmAE patches to a separate `patches/docker-compat.sh` script. The Dockerfile simply copies and runs it.
- **Evidence:** First attempt at inline sed in Dockerfile failed due to dollar-sign escaping in `${DEVICE}`. The patch script ran cleanly on first try.
- **Applies when:** Any Dockerfile that needs to patch files from an upstream repository. Always use a separate script file instead of inline sed/awk in RUN commands.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Sidecar container, not reimplementation | Cleanest separation, preserves FirmAE's heuristics | Worked — 4 phases completed, no rework |
| Raw firmware blob to FirmAE | FirmAE's extraction is coupled to kernel selection | Worked — extraction + arch detection succeeded |
| Flask API shim (not log parsing) | Structured JSON beats fragile log parsing | Worked — all endpoints functional |
| Extend existing EmulationPage (mode toggle) | Unified UX, no feature fragmentation | Worked — TypeScript clean, 0 errors |
| Backend WS proxy (not ttyd in sidecar) | Reuses existing terminal.py pattern | Worked — no new dependencies |
| Dynamic port mapping | Same proven pattern as user-mode emulation | Worked — ports mapped correctly |
| Ephemeral Postgres in sidecar | Fully isolated, no schema conflicts | Worked — but required creating "firmadyne" role |
| AArch64 deferred | FirmAE doesn't support it | Correct — avoided scope creep |
| Raw ext2 image (no partition table) | kpartx loop devices don't work in Docker | Worked — mke2fs + mount -o loop succeeded |
| 30-min pipeline timeout on RPi | Cross-arch QEMU emulation is slow | Appropriate — pipeline reached network inference in ~7min |
