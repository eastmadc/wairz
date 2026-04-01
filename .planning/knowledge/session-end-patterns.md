# Patterns: Session End — Stabilization & Clean History

> Extracted: 2026-04-01
> Source: Final phase of session (commit squash, test integration, PR cleanup)

## Successful Patterns

### 1. Squash fix-on-fix chains before pushing
- **Description:** 25 raw commits included 4 Grype model-alignment fixes, 2 Finding source fixes, and other iterative corrections. Squashed into 8 logical commits grouped by feature area with detailed messages.
- **Evidence:** 25 commits → 8 clean commits. Each commit is a reviewable, revertable unit.
- **Applies when:** End of every working session before pushing. Never push raw fix-on-fix history.

### 2. Know when to stop building and stabilize
- **Description:** After 25 commits of features and fixes, chose to stop adding features and instead: add tests to clean branch, verify everything passes, push clean history, close stale PRs. The "ouroboros loop" and "more features" were tempting but would have added complexity to an already-dense session.
- **Evidence:** The last few commits before stabilization were fix-on-fix chains (grype_service needed 4 fixes). That's a fatigue signal.
- **Applies when:** When fix-on-fix chains appear, or when the session has been long. Stabilize before adding more.

### 3. Tests must travel with the code they protect
- **Description:** 89 tests were generated on a separate branch but not included in the clean squashed history. Had to explicitly cherry-pick them before pushing. Tests that aren't in the same history as the code they test are effectively lost.
- **Evidence:** Tests were on `tests/critical-path-coverage` branch but missing from `clean-history` until explicitly added.
- **Applies when:** Always. When squashing commits, include test files in the clean history.

### 4. Close stale PRs when history is rewritten
- **Description:** Force-pushing a squashed history to fork invalidated all existing PRs (#16-#20) because their branches referenced old commit SHAs. Closed all 5 with explanation.
- **Evidence:** PRs #16-#20 closed with "superseded by clean commit history"
- **Applies when:** Any time you force-push rewritten history that affects open PRs.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Stabilize instead of building more | Fix-on-fix chains = fatigue signal; diminishing returns | Correct — clean exit point |
| Squash 25 → 8 commits | Raw history was noisy (fix-fix-fix); squashed by feature area | Clean, reviewable history |
| Include tests in clean history | Tests on separate branch would be orphaned | Tests now protect the code permanently |
| Close all stale PRs | Force-pushed history invalidated old branches | Clean PR state, ready for fresh PRs |
| Contribution strategy: accumulate locally | Don't PR until changes are tested and stable | Avoids premature upstream noise |
