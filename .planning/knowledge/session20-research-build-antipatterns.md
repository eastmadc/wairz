# Anti-patterns: Session 20 (Research + Build)

> Extracted: 2026-04-08
> Session: S20 — cwe_checker, binwalk3, YARA Forge, hardcoded IPs, fuzzy daemons

## Failed Patterns

### 1. Docker CLI Subprocess in Backend Container
- **What was done:** Initial cwe_checker service used `asyncio.create_subprocess_exec("docker", "run", "--rm", ...)` to run containers.
- **Failure mode:** Backend container has Docker socket mounted but no `docker` binary installed. `FileNotFoundError` at runtime.
- **Evidence:** `cwe_check_status` returned "Docker check failed: [Errno 2] No such file or directory" after first deploy.
- **How to avoid:** Always use the Python docker SDK (`docker.from_env()` / `client.containers.run()`). Check existing patterns in `emulation_service.py` and `fuzzing_service.py` before writing new Docker integrations.

### 2. Assuming External Tool CLI Flag Compatibility
- **What was done:** Changed `"binwalk"` to `"binwalk3"` in `firmware_metadata_service.py` but kept the `--csv` flag.
- **Failure mode:** Binwalk v3 removed `--csv` entirely. The service would have returned empty metadata for all firmware scans.
- **Evidence:** `binwalk3 --csv` returned "error: unexpected argument '--csv' found". Caught during testing, not at deploy time.
- **How to avoid:** Before swapping any CLI tool version, grep for ALL flags/options used in the codebase and verify each one exists in the new version's `--help`. Test with real data, not just import checks.

### 3. YARA Forge Download URL Assumption
- **What was done:** Initial Dockerfile and MCP tool assumed YARA Forge distributes rules as a bare `.yar` file at `releases/latest/download/yara-forge-rules-core.yar`.
- **Failure mode:** The actual distribution is a `.zip` file containing `packages/core/yara-rules-core.yar`. Got HTTP 404.
- **Evidence:** `curl -fsSL` returned exit code 22 (HTTP 404). Had to query GitHub API for actual asset URL.
- **How to avoid:** Always verify external download URLs before hardcoding them. Use `curl -sI` or the GitHub API to check the actual release asset format. Never assume file extensions from documentation without verification.

### 4. Polling Background Agents Instead of Waiting
- **What was done:** Repeatedly polled background agent output files in a loop, parsing JSONL for result types, wasting context and user attention.
- **Failure mode:** Multiple polling cycles with "Still running" output added noise without value. Agents complete and notify automatically.
- **Evidence:** 8+ polling attempts across 3 research agents before they completed naturally.
- **How to avoid:** Launch background agents and move on to other work. The system notifies when agents complete. Only check status if the user asks or if there's a genuine dependency blocking the next step.

### 5. Hot-Deploy Without Full Rebuild Causes Stale Container Issues
- **What was done:** Used `docker cp` to deploy updated Python files into the running backend container instead of a full `docker compose build`.
- **Failure mode:** The frontend container still had the old code from the last full build, causing "1 error" across all security scan types for the user. The mismatch between backend and frontend was not obvious.
- **Evidence:** User reported errors on security scan page that didn't match any current frontend code. Root cause: stale Docker container from a previous session's hot-deploy.
- **How to avoid:** Hot-deploy (`docker cp` + restart) is fine for iterating during development, but always do a full `docker compose build` before marking work as done or before ending a session. The feedback memory "always deploy test" exists for this reason.
