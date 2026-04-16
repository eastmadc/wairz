# Patterns: Session 38 Fleet — Project Maturity Wave

> Extracted: 2026-04-15
> Source: Fleet wave 1 — 3 parallel agents (CI/CD, tests, frontend bugs)
> Postmortem: none (single-wave fleet, no failures)

## Successful Patterns

### 1. Fleet Agents Producing Directly Mergeable Changes
- **Description:** All three agents ran in isolated worktrees and produced changes that merged cleanly with zero conflicts. Scopes were strictly non-overlapping: `.github/` + `backend/pyproject.toml`, `backend/tests/`, `frontend/src/`.
- **Evidence:** Three commits merged sequentially with no conflict resolution needed.
- **Applies when:** Decomposing parallel work — enforce strict scope separation at the directory level, not just file level.

### 2. Targeted Test File Creation Over Broad Coverage
- **Description:** Test agent focused on 4 critical untested services (finding, file, firmware, export) rather than writing 1-2 tests per service across all 46 untested services. Produced 121 deep tests instead of shallow coverage.
- **Evidence:** 44 tests for file_service alone — covering path traversal, virtual roots, symlinks, binary detection. Deep coverage found real patterns (ZIP slip prevention, symlink rewriting).
- **Applies when:** Test expansion work — deep coverage of critical services beats shallow coverage of many.

### 3. Frontend Bug Audit as Systematic Page-by-Page Sweep
- **Description:** Agent audited all 14 pages + 3 stores systematically, looking for specific bug categories (unhandled rejections, missing try/catch, stale state, SSE leaks). Found 12 real issues.
- **Evidence:** Issues were consistent across pages (3 pages had the same `listFirmware()` unhandled rejection), suggesting a systemic pattern rather than isolated bugs.
- **Applies when:** Frontend quality passes — sweep by bug category across all pages, not by page across all categories.

### 4. Ruff Config With Project-Specific Suppressions
- **Description:** CI agent added ruff with S (security) rules but suppressed S603/S607 (subprocess checks) because the firmware analysis backend legitimately invokes dozens of CLI tools. Per-file ignores exempt tests from security rules and alembic from style rules.
- **Evidence:** Config matches project reality — no false positives on legitimate subprocess usage.
- **Applies when:** Adding linters to projects with unusual security profiles (security tools that invoke other tools).

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Single wave (no Wave 2) | All 3 streams were fully independent | Correct — no cross-stream dependencies discovered |
| Test agent targeted top 4 services | Finding, file, firmware, export are the most user-facing and data-critical | 121 tests, all passing |
| Frontend agent fixed bugs in-place | Small, targeted fixes rather than refactoring | 12 fixes, typecheck clean |
| Both ruff AND bandit in CI | Ruff catches issues at lint speed, bandit provides deeper analysis | Complementary — different strengths |
