# Patterns: Full Session (setup → review → fleet → infra → tests)

> Extracted: 2026-03-31
> Sources: Fleet sessions review-fixes, infra-improvements, test-gen; infra-audit; /learn review-fixes

## Successful Patterns

### 1. Review → Fleet → PR pipeline
- **Description:** Full project review (5 parallel domain agents) produces structured findings with file:line references. These become the spec for a fleet campaign (3 waves, 9 agents). Each finding maps directly to an agent task with zero ambiguity.
- **Evidence:** 58 findings → 44 files changed, 0 merge conflicts, all tests pass.
- **Applies when:** Any codebase-wide quality improvement. The review is the requirements doc.

### 2. Post-fix review catches regressions before shipping
- **Description:** After the fleet fix campaign, ran a targeted diff review (`git diff HEAD~1`) that caught 2 critical regressions (asyncio.gather on shared AsyncSession, ghidra lock removal) plus 3 minor issues.
- **Evidence:** Commit 2 fixed regressions before they reached the PR.
- **Applies when:** Always. Every fleet campaign should be followed by a diff review before committing.

### 3. Infra-audit before building features
- **Description:** Ran `/infra-audit` which discovered Redis was provisioned but unused, pool was undersized, and Ghidra Dockerfile was dead code. This informed 4 focused PRs.
- **Evidence:** Without the audit, we'd have added Redis without knowing it was already there, or missed the pool sizing issue.
- **Applies when:** Before any infrastructure work. Map what exists before adding new things.

### 4. Research scouts before build agents
- **Description:** Fleet wave 1 used read-only research agents to investigate pool sizing, httpx migration, and Ghidra JDK. Wave 2 build agents received research findings as context — no wasted work, no wrong assumptions.
- **Evidence:** httpx research confirmed it was already a dependency (zero install cost). Pool research quantified exact demand (40-50 connections). Ghidra research revealed dead code.
- **Applies when:** Any fleet campaign where the right approach isn't obvious. Research is cheap, bad builds are expensive.

### 5. Test generation targeting security fixes
- **Description:** Generated tests specifically for the code paths that were security-fixed (auth bypass, command injection, path traversal). 89 tests in 3 parallel agents.
- **Evidence:** All 89 pass. The auth bypass tests verify that mismatched project_ids return 404 — the exact behavior the fix added.
- **Applies when:** After any security fix. Tests lock in the fix and prevent regression.

## Anti-patterns

### 1. Committing local config to upstream PRs
- **Description:** CLAUDE.md Citadel harness section was committed in the main fix commit, then had to be reverted in a separate commit.
- **How to avoid:** Exclude CLAUDE.md, .claude/, .planning/ from PR branches. Check `git diff --name-only` for config files before committing.

### 2. Mega-commit with 44 files
- **Description:** First commit had 44 files — too large for meaningful review. The infra work was properly split into 4 PRs, but the review-fixes should have been split similarly.
- **How to avoid:** Plan PR boundaries BEFORE the fleet campaign. Each wave could map to a PR.

### 3. Working tree changes lost during branch switching
- **Description:** Infra fleet agents wrote to the working tree. When switching branches to create separate PRs, unstaged changes were lost and had to be recreated manually.
- **How to avoid:** Commit all agent work immediately after each wave before switching branches. Or use `git stash` carefully with named stashes.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| 5 PRs instead of 1 mega-PR | Reviewer fatigue, independent mergeability, proper git history | Correct — each PR is self-contained and reviewable |
| arq over Celery for job queue | Async-native, Redis-backed, lightweight, no broker config | Good fit for the project's async architecture |
| Redis as cache, not primary store | Analysis data must survive Redis restarts, PG is authoritative | Correct — cache failures are invisible to users |
| Tests on security branch, not per-infra-PR | Security fixes are highest risk, tests lock them in as a group | Pragmatic — one test PR covers the most critical paths |
