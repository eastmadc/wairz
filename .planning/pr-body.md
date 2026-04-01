## Summary

Addresses 58 findings from a structured 5-pass code review (correctness, security, performance, readability, consistency) across the entire codebase.

### Critical Security Fixes (6)
- **Path traversal** in `_find_cert_files` — user-supplied `search_path` joined with `lstrip('/')` instead of `validate_path()`, allowing escape from firmware root
- **Authorization bypass** on 10 emulation router endpoints — session/preset operations accepted any valid ID regardless of project ownership
- **Command injection** in fuzzing service — `extra_env` values and `arguments` interpolated into shell commands without `shlex.quote()`
- **Race condition** in ghidra_service concurrency guard — fragile `event = None` pattern replaced with explicit boolean flag
- **Transaction bug** in vulnerability_service — explicit `db.commit()` conflicted with `get_db` transaction management
- **Docker socket** exposure documented as accepted risk

### Security Hardening (8 warnings)
- Container hardening: `USER` directives added to emulation/fuzzing Dockerfiles
- `pids_limit: 256` on emulation/fuzzing containers (fork bomb prevention)
- Emulation container removed from default network (was able to reach postgres/redis)
- Postgres/Redis ports bound to `127.0.0.1` (were exposed to all interfaces)
- CORS origins now configurable via `CORS_ORIGINS` env var (was hardcoded `*`)
- Internal `storage_path`/`extracted_path` removed from API response schemas
- System prompt no longer exposes internal `extracted_path` to AI model
- UART bridge now validates device paths against `/dev/tty*` and `/dev/serial/*`

### Performance Fixes (6 warnings)
- Blocking sync calls in `firmware_service.py` wrapped with `run_in_executor`
- Sync `subprocess.run` in fuzzing AI tool replaced with `asyncio.create_subprocess_exec`
- Firmware metadata reads capped at 16MB (was reading entire file up to 500MB)
- N+1 queries in emulation/fuzzing list endpoints (kept sequential — AsyncSession is not safe for concurrent access)
- Bulk `DELETE` replaces one-by-one loop in SBOM rescan
- Pagination added to `list_vulnerabilities` and `list_findings` endpoints

### Frontend Fixes (6)
- Polling intervals stabilized with refs in FuzzingPage and EmulationPage (were torn down/recreated every cycle)
- ESLint suppression removed, proper dependency array added in EmulationPage SessionCard
- `useMemo` added to ComparisonPage computed arrays
- SessionCard + EmulationTerminal extracted from EmulationPage (1030 -> 647 lines)
- CampaignCard + CampaignDetail extracted from FuzzingPage (856 -> 396 lines)
- Shared error extraction utility created (`frontend/src/utils/error.ts`)

### Code Cleanup (14 info)
- Shared SHA256 utility (`utils/hashing.py`) replaces 4 duplicate implementations
- Shared `resolve_firmware` dependency (`routers/deps.py`) replaces 5 duplicate helpers
- `asyncio.get_event_loop()` replaced with `get_running_loop()` in 7+ locations
- `datetime.utcnow()` replaced with `datetime.now(timezone.utc)` in sbom router
- Zip-slip check now also rejects backslashes in import_service
- Content-Disposition filenames sanitized with `re.sub` in findings/export routers
- Shell script hardening: `set -euo pipefail` + socat cleanup trap in start-system-mode.sh
- Docker Compose: `profiles: [build]` on emulation/fuzzing services

### Post-Review Regression Fix (commit 2)
- Reverted `asyncio.gather` in list endpoints — SQLAlchemy AsyncSession is not safe for concurrent coroutine access
- Restored lock acquisition in ghidra_service `finally` block
- Moved inline `delete` import to module level in sbom router
- Removed dead `extracted_path` parameter from `build_system_prompt`

## New Files (7)
- `backend/app/utils/hashing.py` — shared SHA256
- `backend/app/routers/deps.py` — shared router dependencies
- `frontend/src/utils/error.ts` — shared error extraction
- `frontend/src/components/emulation/SessionCard.tsx`
- `frontend/src/components/emulation/EmulationTerminal.tsx`
- `frontend/src/components/fuzzing/CampaignCard.tsx`
- `frontend/src/components/fuzzing/CampaignDetail.tsx`

## Test Plan
- [ ] `docker compose up --build` starts without errors
- [ ] Emulation session CRUD scoped to correct project
- [ ] Fuzzing campaign with custom env/arguments doesn't inject shell commands
- [ ] UART bridge rejects device paths outside `/dev/tty*` and `/dev/serial/*`
- [ ] Frontend polling stable (no interval thrashing)
- [ ] SBOM rescan deletes and regenerates correctly
- [ ] Postgres/Redis bound to 127.0.0.1
- [ ] `validate_path` does not throw on non-existent but valid paths in security.py
