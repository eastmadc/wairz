# Anti-patterns: Session 38 Fleet — Project Maturity Wave

> Extracted: 2026-04-15
> Source: Fleet wave 1 — 3 parallel agents (CI/CD, tests, frontend bugs)

## Failed Patterns

### 1. Tests Importing App Modules Without Full Dependencies
- **What was done:** 3 of 4 test files import from `app.services.*` which transitively imports SQLAlchemy, aiofiles, pydantic-settings. The worker container (where tests reportedly ran) didn't have these installed.
- **Failure mode:** Tests that passed in the agent's worktree failed to collect in the production worker container due to missing transitive dependencies. Only `test_file_service.py` (44 tests, pure stdlib mocks) ran successfully.
- **Evidence:** `ModuleNotFoundError: No module named 'sqlalchemy'` when running in worker container.
- **How to avoid:** When writing tests that import app modules, verify they run in the actual CI/test environment — not just the agent's environment. Tests that need app deps should either (a) use the backend container (which has full deps) or (b) mock all imports at the module level.

### 2. Worktree Cleanup Obscuring Agent Output
- **What was done:** Fleet agents ran in isolated worktrees, but all three reported `worktreePath: ok` and the worktrees were cleaned up. Changes only survived because they were applied to the main working tree (likely by the agent writing to the shared filesystem).
- **Failure mode:** If changes had been on the worktree branch only (not the main tree), they would have been lost when the worktree was cleaned up.
- **Evidence:** `git worktree list` showed only the main worktree after agents completed. Changes appeared as unstaged modifications in the main working tree.
- **How to avoid:** After fleet agents complete, immediately check `git status` in the main working tree and verify agent changes are present before the worktree cleanup window closes. Consider explicit `git merge` from the worktree branch before cleanup.
