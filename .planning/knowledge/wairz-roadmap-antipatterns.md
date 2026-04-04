# Anti-patterns: Wairz Full Roadmap

> Extracted: 2026-04-04
> Campaign: .planning/campaigns/completed/wairz-roadmap.md

## Failed Patterns

### 1. Building Without Verifying Existence First
- **What was done:** Created a 12-phase archon campaign and spawned 8 parallel agents to "build" features that already existed in the codebase.
- **Failure mode:** All 8 agents returned "already exists" — wasted ~$4 in agent costs and 5 minutes of wall time on pure verification.
- **Evidence:** Every agent (SPDX, kernel config, capa, Dependency-Track, androguard, auth, arq) found pre-existing code.
- **How to avoid:** Before spawning a build agent for any roadmap item, run a quick grep for the key function/tool/endpoint name. If it exists, mark done and skip. A 2-second grep prevents a 2-minute agent.

### 2. Stale Roadmap Treated as Source of Truth
- **What was done:** The master plan listed 25 items as "to do" but they were all completed incrementally across prior sessions. The plan was never updated after each session.
- **Failure mode:** Archon decomposed the stale roadmap into phases and delegated work that was already done.
- **Evidence:** Master plan dated "Updated: 2026-04-03" but features were built across sessions 1-8 without updating completion status.
- **How to avoid:** Update the master plan's completion status at the END of every session. Mark items as done with the file paths where they were implemented.

### 3. Checkpoint Stash Conflicts with Telemetry Files
- **What was done:** `git stash push --include-untracked` captured telemetry/hook files that were being actively modified.
- **Failure mode:** `git stash pop` failed repeatedly due to merge conflicts in `.planning/telemetry/*.jsonl` and `.claude/circuit-breaker-state.json`.
- **Evidence:** Three consecutive `git stash pop` failures requiring manual conflict resolution.
- **How to avoid:** Exclude telemetry and hook state files from checkpoints: `git stash push --include-untracked -- ':!.planning/telemetry/' ':!.claude/circuit-breaker-state.json'`. Or skip checkpoints entirely for verification-only campaigns.
