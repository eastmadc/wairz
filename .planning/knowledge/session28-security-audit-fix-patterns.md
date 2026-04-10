# Patterns: Session 28 — Security Audit Fix

> Extracted: 2026-04-10
> Campaign: none (ad-hoc bug fix)
> Postmortem: none

## Successful Patterns

### 1. Debug Logging Injection for Docker Production Bugs
- **Description:** When a bug reproduces via API endpoint but not via manual Python script inside the same container, inject debug logging directly into the running container's code, restart the service, and trigger the endpoint again. This reveals runtime state that manual reproduction misses.
- **Evidence:** The `run_clamav_scan` shadowing bug only manifested when called through FastAPI's request lifecycle. Manual script called the correct (imported) function because Python's module-level scope was different. Injecting `_dbg.warning('all_findings has %d entries')` and `_dbg.error('BAD ENTRY [%d]')` into the Docker container's router file revealed the exact bad entries: Pydantic model field tuples.
- **Applies when:** Bug reproduces via HTTP but not via direct Python invocation in the same container. Indicates the issue is in name resolution, middleware, or request context — not in the core logic.

### 2. Checking File Hashes Between Docker and Local
- **Description:** Before assuming code divergence, compare `md5sum` of source files between Docker container and local filesystem. Eliminates stale-container hypotheses quickly.
- **Evidence:** `md5sum` confirmed identical files, ruling out Docker cache staleness as the cause.
- **Applies when:** Debugging any Docker-deployed bug where "works locally" is suspected.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Rename endpoint to `run_clamav_scan_endpoint` | Matches existing convention (`run_abusech_scan_endpoint`, `run_known_good_scan_endpoint`) | Fix confirmed — 13 findings persisted, 0 bad entries |
| Use `_endpoint` suffix convention for router functions that share names with service imports | Prevents Python name shadowing in module scope | Consistent with 2 of 3 existing threat intel endpoints (the 3rd was the bug) |
