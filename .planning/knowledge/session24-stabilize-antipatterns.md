# Anti-patterns: Session 24 — S24 Stabilize

> Extracted: 2026-04-09 (updated 2026-04-10 with worker incident)
> Commit: 4f262ea on clean-history

## Failed Patterns

### 1. Hardcoded Count Assertions in Tests
- **What was done:** `test_security_audit_service.py` asserted `result.checks_run == 8` as an exact equality. When S20-S21 added 4 new scan categories (network deps, update mechanisms, ShellCheck, Bandit), these tests broke silently.
- **Failure mode:** Tests that passed in session 19 failed in session 24 with `assert 12 == 8`. The failure was invisible because these tests weren't re-run between sessions.
- **Evidence:** 3 tests in `TestRunSecurityScan` class, all asserting exact count.
- **How to avoid:** Use `>=` for additive counters (check counts, tool counts). Reserve `==` for values that should never change. Add a comment explaining the minimum: `assert result.checks_run >= 8  # base checks, grows as new scanners are added`.

### 2. Import Chain Contamination in Tests
- **What was done:** `test_hardcoded_ips.py` imported `ToolContext` at module level, which triggered the full tool registry import chain (`ai/__init__.py` → all tool files → all service files → lief).
- **Failure mode:** `ModuleNotFoundError: No module named 'lief'` — test collection fails entirely, preventing ALL tests in the file from running.
- **Evidence:** Existing `conftest.py` already uses deferred import for `ToolContext` (inside the fixture function), but the new test file didn't follow this pattern.
- **How to avoid:** Never import from `app.ai` at module level in tests. Use deferred imports inside test methods or fixtures. For unavoidable dependencies, use `try/except` + `pytestmark = pytest.mark.skipif()`.

### 3. Testing Against Implementation Details Instead of Behavior
- **What was done:** `test_network_deps.py` initially tested for NFS client mounts in `/etc/fstab`, but the scanner actually checks for NFS exports with `no_root_squash` and CIFS mounts with inline credentials.
- **Failure mode:** Test fixture didn't match what the scanner actually detects. Test passed 0 findings when it expected >= 1.
- **Evidence:** Had to read the actual `_scan_network_dependencies` source to understand it scans `/etc/exports` and CIFS credential patterns, not NFS client entries in fstab.
- **How to avoid:** Read the service implementation before writing test fixtures. Don't guess at detection patterns from the function name — check the actual regexes and file paths being scanned.

### 4. README Drift Over 10 Sessions
- **What was done:** README was last updated in early sessions when there were ~60 tools. 10 development sessions later, the tool count had grown to 162 but README still said "60+".
- **Failure mode:** Documentation was severely misleading — the product had 2.7x more capability than documented. Features like RTOS, UEFI, CRA compliance, attack surface scoring were completely absent from README.
- **Evidence:** README update required touching 8 sections and adding 15+ new feature descriptions.
- **How to avoid:** Update README when adding major features (new tool categories, new firmware type support, new compliance frameworks). Don't defer to a "stabilize" session — the drift compounds. Consider adding a check: "Does README mention the feature I just built?"

### 5. Stale Worker Container Blocks All Background Jobs
- **What was done:** After committing CRA compliance tables (migration `e0c33cf2204e`) and rebuilding the backend, the worker container was NOT rebuilt. Its entrypoint runs `alembic upgrade head` before starting arq — Alembic couldn't find the revision because the old container image didn't have the migration file.
- **Failure mode:** Worker enters a restart loop (`FAILED: Can't locate revision identified by 'e0c33cf2204e'`), arq never starts, ALL background jobs (unpack, Ghidra, vuln scan, YARA) silently queue forever. Frontend shows firmware stuck at "unpacking" indefinitely. No error visible in the backend logs — only the worker logs show the Alembic crash.
- **Evidence:** `docker logs wairz-worker-1` showed repeated `Can't locate revision identified by 'e0c33cf2204e'` / `FAILED`. Worker status: `Restarting (255)`. Firmware record had `extracted_path: null` after 50 minutes.
- **How to avoid:** **Always rebuild both `backend` AND `worker` together** — they share the same Dockerfile and codebase. Use `docker compose up -d --build backend worker` not just `docker compose up -d --build backend`. This is the same root cause as CLAUDE.md learned rule #1 ("Use `docker compose up -d` not `restart`") but applied to the worker service specifically.

### 6. Silent Queue Accumulation With No User-Facing Error
- **What was done:** When the worker is down, firmware upload succeeds (HTTP 202) and the unpack job is enqueued in Redis. The frontend polls for status and sees "unpacking" forever. There's no timeout, no error message, and no health check that surfaces the dead worker.
- **Failure mode:** User waits indefinitely for unpacking that will never complete. The only way to diagnose is to check `docker logs wairz-worker-1` — not discoverable from the UI or backend logs.
- **Evidence:** Unpack job sat in Redis queue for 3032 seconds (50 min) before the worker was rebuilt and picked it up.
- **How to avoid:** Consider adding a worker health check (arq heartbeat via Redis key) and surfacing worker-down status in the frontend. At minimum, add a job timeout so stale jobs fail rather than queue forever.
