# Patterns: Full Architecture Review (Session 8)

> Extracted: 2026-04-03
> Source: Full-repo 5-pass review (6 parallel agents, 188 files, ~114K lines)
> Commit: 66ba5f4

## Successful Patterns

### 1. Parallel Agent Review Decomposition
- **Description:** Split the full-repo review into 6 agents by subsystem (backend core, services, routers, MCP tools, frontend, infrastructure). Each ran the full 5-pass protocol independently.
- **Evidence:** All 6 agents completed in ~3 minutes total (vs. sequential would have been 15+). No overlap or conflicting findings.
- **Applies when:** Reviewing codebases with >50 files. Decompose by architectural layer, not by pass type.

### 2. Research Before Architecture Decisions
- **Description:** For the terminal sandboxing fix (S1), ran a dedicated research agent evaluating 5 options (bubblewrap, unshare+chroot, Docker spawn, namespaces, Landlock) with web sources before choosing an approach. Discovered Landlock was blocked by kernel config.
- **Evidence:** Research eliminated 3 options and confirmed Docker spawn as optimal. Would have wasted time implementing Landlock only to discover `CONFIG_SECURITY_LANDLOCK is not set`.
- **Applies when:** Fixing architectural security issues with multiple viable approaches. Always check host constraints first.

### 3. Reuse Existing Codebase Patterns for Security Fixes
- **Description:** The Docker-based terminal sandbox reused the exact same container+exec+socket pattern from `emulation_service.py` and `routers/emulation.py`. Zero new infrastructure.
- **Evidence:** Terminal rewrite was ~230 lines mirroring the emulation WebSocket, vs. hundreds of lines for bubblewrap/namespace approaches. Path resolution via existing `_resolve_host_path` logic.
- **Applies when:** Adding security boundaries. Check if the codebase already has a container spawn pattern before inventing new sandboxing.

### 4. Module-Level State for Background Task Persistence
- **Description:** Fixed device service singleton race by moving `_dump_state` from instance attribute to module-level dict. Per-request service instances read/write the shared state.
- **Evidence:** The singleton pattern (`_service_instance._db = db`) was unsafe under concurrent requests. Module-level state is safe in single-worker async (uvicorn default).
- **Applies when:** Background tasks (asyncio.create_task) need state that persists across HTTP requests. Use module-level dicts, not instance attributes on request-scoped objects.

### 5. Strict Input Validation at Trust Boundaries
- **Description:** Added `^[a-zA-Z0-9_-]+$` regex for ADB partition names, `_validate_output_dir()` for file paths, `shlex.quote()` for shell interpolation, `validate_path()` for symlink resolution.
- **Evidence:** 4 separate injection vectors (S2/S3/S4/S11) all followed the same pattern: user-controlled strings interpolated into shell commands or filesystem paths without validation.
- **Applies when:** Any data flowing from TCP clients, REST parameters, or MCP tool inputs into shell commands, file paths, or SQL. Defense-in-depth: validate at every layer even if the caller "should" have validated.

### 6. flush() vs commit() in Tool Handlers
- **Description:** Replaced 13 `context.db.commit()` calls in MCP tool handlers with `flush()`. The outer dispatch in mcp_server.py handles the final commit, allowing proper rollback on partial failures.
- **Evidence:** Double-commit prevented rollback in the except block at mcp_server.py:559. Some tool handlers committed midway then continued, making partial writes permanent.
- **Applies when:** Any layered architecture where an outer scope manages transactions. Inner code should flush (make writes visible within the session) but never commit (that's the transaction owner's job).

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Docker container for terminal sandbox | Only option needing zero new capabilities, proven pattern in codebase, full namespace isolation | Implemented successfully, ~230 lines |
| Bind ports to 127.0.0.1 | Backend has no auth — exposing to network is full compromise | Simple, low-risk change |
| CORS default to localhost:3000 | Wildcard + credentials is spec-violating and risky | Minimal breakage risk since frontend is always localhost |
| Bulk DELETE for finding cleanup | N+1 delete loaded all findings then deleted one-by-one | Single SQL statement, same behavior |
| shlex.quote for shell interpolation | binary_path flows from user through DB to shell command in fuzzing container | Defense-in-depth even though container is isolated |
