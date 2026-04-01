# Anti-patterns: review-fixes

> Extracted: 2026-03-31
> Campaign: .planning/fleet/session-review-fixes.md

## Failed Patterns

### 1. asyncio.gather with shared SQLAlchemy AsyncSession
- **What was done:** Wave 2 agent converted sequential `for` loops calling `svc.get_status()` into `asyncio.gather()` for concurrent execution — a standard N+1 fix pattern.
- **Failure mode:** All gather'd coroutines shared the same `db: AsyncSession` via the service instance. AsyncSession is not thread-safe and not safe for concurrent coroutine access. Could cause session state corruption, lost writes, or exceptions at runtime.
- **Evidence:** Caught by post-review agent (commit 2). Reverted to sequential awaits.
- **How to avoid:** Never use `asyncio.gather()` on coroutines that share a SQLAlchemy AsyncSession. Either use sequential awaits, or create independent sessions per task via `async_session_factory()`.

### 2. Unused imports in extracted components
- **What was done:** Wave 3 agent extracted CampaignCard from FuzzingPage.tsx and copied imports from the parent file, including `Loader2` which was used in the parent but not in the extracted component.
- **Failure mode:** TypeScript build failed with `TS6133: 'Loader2' is declared but its value is never read`.
- **Evidence:** `docker compose up --build` failed on the first attempt. Required a 4th commit to fix.
- **How to avoid:** When extracting components, verify each import is actually used in the extracted file. Run `tsc --noEmit` on extracted files before committing. Consider adding a typecheck step to fleet agents that create new TypeScript files.

### 3. CLAUDE.md changes leaking into upstream PRs
- **What was done:** During `/do setup`, appended a "Citadel Harness" section to CLAUDE.md. This local-only change was included in the first commit and pushed to the PR branch.
- **Failure mode:** Would have modified the upstream project's CLAUDE.md with local tooling references.
- **Evidence:** Required a separate revert commit (`revert: remove local CLAUDE.md changes`).
- **How to avoid:** Exclude CLAUDE.md from automated fix commits, or check `git diff --name-only` for config files before committing. Setup changes should be on a separate branch or excluded from PR branches.
