# Patterns: Automated System Emulation (FirmAE)

> Extracted: 2026-04-05 (updated 2026-04-06 with Phase 5 E2E findings)
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

### 8. Phase-Aware Timeout Watchdog
- **Description:** Modified the pipeline timeout watchdog to exit (stop enforcing) once the pipeline reaches RUNNING or CHECKING phase. Startup timeouts protect against stuck pipelines; once firmware boots, the user interacts until explicit stop. Idle-timeout is a separate concern managed by the backend.
- **Evidence:** First successful E2E test was killed by a flat timeout despite firmware running perfectly. After the fix, firmware ran indefinitely until explicitly stopped. Pattern: startup-timeout + operational-no-timeout + idle-timeout as three separate mechanisms.
- **Applies when:** Any system where a process transitions from startup (can fail/hang) to operational (should run indefinitely). Monitoring agents, QEMU emulation, long-running services. Never apply a startup timeout to an operational phase.

### 9. Read Third-Party Tool Source Before Writing Parsers
- **Description:** Before writing output-parsing regex for FirmAE, read the actual `run.sh` script to find exact `echo` statements used as markers. Matched patterns against real strings (`[*] Extract done!!!`, `[+] Start emulation!!!`) instead of guessing generic patterns.
- **Evidence:** The initial implementation guessed 6 patterns, all wrong. After reading `run.sh`, rewrote to match actual markers — 100% hit rate. Also discovered that `makeNetwork.py` output is redirected to log files (not stdout), preventing false assumptions about what appears on stdout.
- **Applies when:** Parsing stdout/stderr of ANY third-party tool. Always read the source first, run the tool once to capture actual output, then write patterns. This is non-negotiable for tools that have no documented output format.

### 10. Filesystem-Based State Discovery for Long-Running Pipelines
- **Description:** FirmAE writes state to files in `scratch/<IID>/` (architecture, ip, ping, web). Instead of only reading these after the pipeline exits (which in run mode means never), poll the filesystem on phase transitions during the monitoring loop.
- **Evidence:** Architecture was never detected during live sessions because `_discover_from_filesystem` only ran after `_monitor_output` returned (which blocks on QEMU stdout). Adding filesystem reads on phase transitions detected arch, IP, and reachability during the pipeline.
- **Applies when:** Wrapping long-running tools that write intermediate state to files rather than stdout. Don't defer filesystem reads to process exit — poll during execution at natural breakpoints (phase transitions, timer intervals).

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
| Targeted nmap (15 ports) over top-1000 | Top-1000 scan too slow in cross-arch QEMU | Worked — 12s scan found SSH/HTTP/HTTPS |
| Watchdog exits at RUNNING phase | "Run" mode QEMU blocks indefinitely by design | Worked — firmware stays up until explicit stop |
| Config timeout over schema default | Frontend sends schema default (600s), config has 1800s | Worked — router reconciles, prefers config |
