# Patterns: review-fixes

> Extracted: 2026-03-31
> Campaign: .planning/fleet/session-review-fixes.md
> Postmortem: none

## Successful Patterns

### 1. Review-first, fix-second workflow
- **Description:** Ran a full 5-pass code review across the entire project (172 files, 39K lines) using 5 parallel domain-specific review agents, then used the structured findings as the input spec for a fleet fix campaign.
- **Evidence:** All 58 findings were addressable because each had file:line references and specific fix instructions. Zero ambiguity in the fix phase.
- **Applies when:** Any large codebase cleanup, security audit, or quality improvement initiative.

### 2. Domain-scoped parallel agents with non-overlapping files
- **Description:** Split the 58 fixes into 9 agents across 3 waves, where each agent owned distinct files. No two agents in the same wave touched the same file.
- **Evidence:** 0 merge conflicts across all 3 waves, 9 agents. All worktree merges were clean.
- **Applies when:** Any fleet campaign. File-scope isolation is the key constraint.

### 3. Post-review self-correction commit
- **Description:** After the main fix commit, ran a targeted review of just the diff (`git diff HEAD~1`). This caught 2 critical regressions (asyncio.gather on shared AsyncSession) and 3 minor issues. Fixed in a separate commit.
- **Evidence:** Commit 2 (`fix: address post-review regressions`) caught the AsyncSession concurrency bug before it shipped.
- **Applies when:** After any large automated fix campaign. Always review the bot's work.

### 4. Wave ordering: critical security → performance → cleanup
- **Description:** Structured waves so critical security fixes landed first (wave 1), performance fixes second (wave 2), and readability/cleanup last (wave 3). Wave 3 agents received discovery briefs from waves 1-2 so they knew which files were already modified.
- **Evidence:** Wave 3 agents (deps.py extraction, component extraction) successfully worked around wave 1-2 changes without conflicts.
- **Applies when:** Any multi-wave fleet campaign with mixed severity findings.

### 5. Shared utility extraction as a dedicated agent
- **Description:** Gave one wave-3 agent the sole task of extracting duplicated code (SHA256, resolve_firmware, Docker client). This agent touched many files but ran in its own wave after all other modifications were complete.
- **Evidence:** Successfully extracted 3 shared utilities, updated 14 files, zero regressions.
- **Applies when:** Deduplication/refactoring work that touches many files should be isolated to its own wave after functional changes.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Revert asyncio.gather to sequential awaits | SQLAlchemy AsyncSession is not safe for concurrent coroutine access — gather'd coroutines sharing one session cause state corruption | Correct — prevented runtime bugs |
| Keep uart.py's local _resolve_firmware | Its signature differs from the shared one (no firmware_id param, no extracted_path check) | Correct — avoided breaking behavior change |
| Use 404 (not 403) for auth bypass checks | Prevents information leakage about resource existence in other projects | Standard security practice |
| Cap firmware metadata reads at 16MB | U-Boot env and MTD partitions are always in early portion of firmware, 500MB reads were wasteful | Correct — no functional impact |
| Remove storage_path from API schemas | Internal server paths leaked to clients | Correct — may need migration if any frontend code relied on these fields |
| Add profiles:build to emulation/fuzzing compose services | These services exist only for image building, shouldn't start with `docker compose up` | Needs verification — old containers from before the change still running |
