# Anti-patterns: S30 Backlog Refactoring Sprint

> Extracted: 2026-04-10
> Session: S30 — R1/R2/R3/R8/R9 backlog items

## Failed Patterns

### 1. Service Methods Calling commit() Instead of flush()
- **What was done:** `cra_compliance_service.py` (4 locations) and `system_emulation_service.py` (1 location) used `await self.db.commit()` in service methods. These services are called from both MCP tool handlers and REST routers.
- **Failure mode:** When called from MCP context, `commit()` breaks the outer transaction in `mcp_server.py`. If a later tool in the same MCP conversation fails, the committed data cannot be rolled back. Partial state persists.
- **Evidence:** Audit found 5 service commit() calls that should be flush(). CRA compliance service was the worst offender (4 commits created during S22).
- **How to avoid:** Services MUST use `flush()`, never `commit()`. Only transaction owners (get_db, MCP dispatch, background task session) call `commit()`. Add this to code review checklist.

### 2. Redundant commit() in Routers Using get_db
- **What was done:** 15 router endpoints called `await db.commit()` even though `get_db()` auto-commits after yield. This was done "for safety" but is actually harmful.
- **Failure mode:** If an error occurs AFTER the manual `commit()` but before the response is sent, `get_db`'s `except` block calls `rollback()` — but the earlier committed data is already persisted. Result: partial state.
- **Evidence:** Found in 7 router files (security_audit 6x, fuzzing 5x, emulation 5x, sbom 2x, firmware 1x, component_map 1x). Pattern dates back to earliest router implementations.
- **How to avoid:** Routers using `get_db` should use `flush()` for visibility within the request, never `commit()`. The `get_db` dependency handles the final commit.

### 3. Docker Image Without ARM64 Check Blocking All Builds
- **What was done:** ClamAV was added to docker-compose.yml as a standard service (S25). `clamav/clamav:latest` only publishes amd64 images.
- **Failure mode:** `docker compose up -d --build` fails entirely on ARM64 (RPi) even with `--scale clamav=0` — Docker tries to pull the image before scaling.
- **Evidence:** Build failure in S30. Required adding `profiles: ["clamav"]` to gate the service.
- **How to avoid:** When adding Docker services, check if the image supports all target architectures (especially ARM64 for RPi development). Use profiles for optional/x86-only services.
