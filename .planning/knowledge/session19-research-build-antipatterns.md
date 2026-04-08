# Anti-patterns: Session 19 — Deep Research + Parallel Build

> Extracted: 2026-04-08
> Source: Session 19 (research-first approach, no formal campaign)

## Failed Patterns

### 1. Assuming System PATH for Venv-Installed CLI Tools
- **What was done:** Added `bandit>=1.7` to pyproject.toml and used `shutil.which("bandit")` to check availability. Docker uses uv + venv, so bandit binary lands in `/app/.venv/bin/` not on system PATH.
- **Failure mode:** `shutil.which("bandit")` returns None even though bandit is fully installed. Both the MCP tool handler and the audit service silently skip bandit scanning.
- **Evidence:** Fresh --no-cache Docker build, all tests pass except bandit. `docker exec wairz-backend-1 pip show bandit` returns "not found" but `/app/.venv/bin/bandit` exists.
- **How to avoid:** Always use `shutil.which(tool) or shutil.which(tool, path="/app/.venv/bin")` for any Python-packaged CLI tool in Docker. Or add `/app/.venv/bin` to the container's PATH in the Dockerfile.

### 2. Trusting Docker Layer Cache for pyproject.toml Changes
- **What was done:** Added bandit to pyproject.toml, ran `docker compose build backend` (with cache). Expected the COPY + uv sync layers to invalidate.
- **Failure mode:** Docker layer caching sometimes preserves the pip/uv install layer even when pyproject.toml changes, especially on RPi where layer hashing is slower. The dependency was present in the file but not installed.
- **Evidence:** First cached build didn't install bandit. Had to manually `pip install bandit` in the running container. Fresh `--no-cache` build resolved it.
- **How to avoid:** When adding dependencies, always run `--no-cache` build for verification. Or use `docker compose build --build-arg VENV_CACHE_BUST=$(date +%s)` to force venv rebuild.

### 3. Test Script JSON Parsing Fragility
- **What was done:** Wrote inline Python JSON parsing in bash test scripts using `echo "$VAR" | python3 -c "import json; ..."`. ShellCheck output contains control characters (tab, newline) that break JSON parsing when piped through echo.
- **Failure mode:** `json.JSONDecodeError: Invalid control character` in test 6 even though ShellCheck works perfectly.
- **Evidence:** Test 6 showed FAIL but manual curl + file redirect + python parse worked fine.
- **How to avoid:** Write API responses to temp files (`curl -o /tmp/result.json`) then parse with `python3 -c "... open('/tmp/result.json')"`. Never pipe large JSON through echo in bash.

### 4. Ouroboros Ambiguity Threshold Frustration
- **What was done:** Completed 10-round interview resolving all material questions. Interview said "no material ambiguity remains" but ambiguity score stayed at 0.23 (threshold 0.2). Multiple attempts to reduce it failed due to earlier answer truncation.
- **Failure mode:** Could not generate seed spec via `ouroboros_generate_seed`. Had to write the spec manually.
- **Evidence:** Interview rounds 8-10 all returned "Cannot complete yet — ambiguity score exceeds threshold" despite the interview itself saying all questions were resolved.
- **How to avoid:** Keep Ouroboros interview answers SHORT (under 500 chars) to avoid truncation. Truncated answers create phantom ambiguity that can't be resolved. If stuck above threshold, write the spec manually — the interview conversation has all the information needed.
