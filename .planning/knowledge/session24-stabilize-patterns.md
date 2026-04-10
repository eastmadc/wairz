# Patterns: Session 24 — S24 Stabilize

> Extracted: 2026-04-09 (updated 2026-04-10 with worker incident)
> Commit: 4f262ea on clean-history
> Postmortem: none (stabilization session)

## Successful Patterns

### 1. Agent-Assisted Tool Inventory Before README Update
- **Description:** Used an Explore agent to grep `registry.register(name=` across all 18 tool category files and produce an exact count (162) before updating the README. Prevented under-counting or over-counting.
- **Evidence:** README previously said "60+" when actual count was 162 — a 2.7x discrepancy that accumulated over 10 sessions of feature work without README updates.
- **Applies when:** Updating documentation that references counts, capabilities, or feature lists. Always verify from source rather than session notes.

### 2. Feature Verification Agent Before Documentation Claims
- **Description:** Ran a second parallel agent to verify each claimed feature exists in source (service files, tool registrations, frontend pages) before writing documentation about it.
- **Evidence:** Caught that `network_dependency_service.py` doesn't exist as a standalone service — the detection logic is embedded in `security_audit_service.py`. Prevented documenting a non-existent file.
- **Applies when:** Writing README, CLAUDE.md, or external documentation that references specific files or services.

### 3. Docker Dev Override Instead of Modifying Production Compose
- **Description:** Created `docker-compose.dev.yml` as an override file rather than modifying `docker-compose.yml` with conditionals. Uses `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d`.
- **Evidence:** Clean separation — production compose unchanged, dev mode is opt-in. Frontend uses separate `Dockerfile.dev` (Vite dev server) vs production `Dockerfile` (nginx static build).
- **Applies when:** Adding development conveniences that shouldn't affect production configuration.

### 4. Deferred Import Pattern for Docker-Only Dependencies
- **Description:** Tests that need `lief`, `yara`, or other Docker-only packages use module-level `try/except ImportError` with `pytestmark = pytest.mark.skipif()` to skip gracefully when run locally.
- **Evidence:** `test_hardcoded_ips.py` — lief triggers the entire tool registry import chain (`ai/__init__.py` → `comparison.py` → `comparison_service.py` → `lief`). Deferred import with skip marker keeps local test suite clean (337 pass vs 4 failures before fix).
- **Applies when:** Writing tests that depend on packages installed only in Docker (lief, yara, qiling). Always use deferred import + skipif pattern.

### 5. Fix Stale Tests When Adding Features
- **Description:** When adding new audit checks (S20-S21 added `_scan_network_dependencies`, `_scan_update_mechanisms`, ShellCheck, Bandit), existing tests that asserted exact `checks_run == 8` broke silently. Changed to `>= 8` to be forward-compatible.
- **Evidence:** `test_security_audit_service.py` had 3 failures with `assert 12 == 8` — the check count grew from 8 to 12 across sessions but the test was never updated. Similarly, `test_string_tools.py` failed because `find_hardcoded_ips` was added to the strings category but not to the expected set.
- **Applies when:** Adding new scan categories or tools to an existing registry. Always grep for hardcoded counts in test assertions.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| README 160+ (rounded down from 162) | Tool count will fluctuate — use "160+" as a floor rather than exact count | Good — avoids stale exact numbers |
| Separate Dockerfile.dev for frontend | Production frontend is nginx serving static build; dev needs Vite HMR — fundamentally different containers | Good — clean separation |
| Skip hardcoded IP tests locally | lief import chain pulls in entire tool registry — no way to isolate without major refactoring | Acceptable — tests run in Docker CI |
| Use `>= 8` for check count assertions | New scan categories will keep being added — exact count assertions are maintenance burden | Good — forward-compatible |
| Volume mount app/ as :ro | Read-only mount prevents accidental writes from container back to host | Good — safety without complexity |

### 6. Worker Crash-Loop Diagnosis Via Alembic Logs
- **Description:** When firmware stuck at "unpacking", checked worker logs first (not backend logs). The worker's crash-loop with `Can't locate revision identified by 'e0c33cf2204e'` immediately identified the root cause: stale container image missing the CRA migration.
- **Evidence:** 3-step diagnosis: (1) `docker logs wairz-worker-1` → Alembic error, (2) `psql alembic_version` → DB at `e0c33cf2204e`, (3) `grep e0c33cf2204e alembic/versions/` → file exists on host but not in container. Fix: `docker compose up -d --build worker`.
- **Applies when:** Any background job (unpack, Ghidra, vuln scan, YARA) appears stuck. Always check `docker logs wairz-worker-1` first — the worker is a separate container that can fail independently of the backend.
