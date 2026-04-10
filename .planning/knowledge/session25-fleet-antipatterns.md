# Anti-patterns: S25 Fleet — CI/CD + E2E + Threat Intel

> Extracted: 2026-04-10
> Campaign: .planning/fleet/session-s25-cicd-e2e-threatintel.md

## Failed Patterns

### 1. Docker exec resolves system Python, not venv
- **What was done:** Used `docker compose exec backend python -m pytest` to run tests
- **Failure mode:** `/usr/local/bin/python` (system Python) was resolved instead of `/app/.venv/bin/python`, which has all project dependencies. SQLAlchemy, clamd, and other packages were "missing" despite being installed in the venv.
- **Evidence:** 5 failed attempts to run tests before discovering PATH issue. `which python` returned `/usr/local/bin/python`, `import sqlalchemy` failed, but `/app/.venv/bin/python -c "import sqlalchemy"` succeeded.
- **How to avoid:** Always use `docker compose exec backend bash -c 'export PATH="/app/.venv/bin:$PATH" && python ...'` for running Python commands in the backend container. The Dockerfile sets `ENV PATH="/app/.venv/bin:$PATH"` but `docker compose exec` may not inherit it for all shells.

### 2. New pyproject.toml dependency not picked up by Docker build
- **What was done:** Added `clamd>=1.0.2` to `pyproject.toml` and ran `docker compose up -d --build`
- **Failure mode:** Docker build used cached layers for the `uv sync` step, so `clamd` was never installed. Had to manually `pip install clamd` in the running container.
- **Evidence:** `import clamd` failed after rebuild; `pip install clamd` succeeded
- **How to avoid:** When adding a new dependency, after `docker compose up -d --build`, verify it's installed: `docker compose exec backend bash -c 'export PATH="/app/.venv/bin:$PATH" && python -c "import <module>"'`. If cached, run `docker compose build --no-cache backend` or install manually.

### 3. uv sync --no-dev removes manually installed test deps
- **What was done:** Ran `uv pip install pytest` then `uv sync --no-dev`
- **Failure mode:** `uv sync --no-dev` removed pytest because it wasn't in the lockfile's non-dev dependencies. The order matters: sync first, then install extras.
- **Evidence:** pytest disappeared after `uv sync --no-dev`
- **How to avoid:** Always install test dependencies AFTER `uv sync`. Run: `uv sync --no-dev && uv pip install pytest pytest-asyncio`

### 4. Tool registration test set becomes stale after adding tools
- **What was done:** Added `detect_rtos`, `analyze_raw_binary`, `analyze_binary_format`, `list_binary_capabilities` in previous sessions without updating `test_binary_tools.py::test_all_tools_registered`
- **Failure mode:** The explicit set assertion in the test fails when new tools are registered but not added to the expected set. Similarly, `test_all_tools_require_binary_path` failed because `detect_rtos` uses `path` not `binary_path`.
- **Evidence:** Pre-existing test failure with "Extra items in the left set"
- **How to avoid:** When adding new tools to any tool category, immediately check if there's a test file with an explicit tool name set and update it. Grep for the category's register function name in tests/.
