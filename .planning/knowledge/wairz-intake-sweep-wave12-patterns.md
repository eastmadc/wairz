# Patterns: Wairz Intake Sweep — Wave 1 + Wave 2 (session 435cb5c2)

> Extracted: 2026-04-19
> Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md`
> Waves: Cross-phase parallel dispatch (6 streams, 28 commits, 6 intakes closed)

## Successful patterns

### 1. Cross-phase file-disjoint wave planning beats phase-by-phase serialisation

- **Context:** Campaign's original plan ordered work by domain phase (1: security → 2: data → 3: infra → 4: frontend → 5: refactor → 6: features → 7: maintenance). Daemon would chain 1 session per phase.
- **Pattern:** Pre-computed a file-disjointness map at session start — grouped 10 of 17 remaining intake items into 6 "groups" (A-G) where within-group work shared files (alembic chains, docker-compose) but cross-group was truly disjoint. Then scheduled 2 waves of 3 streams each, pulling from different groups (and therefore different phases) per wave.
- **Result:** 6 intakes closed in one session vs. the natural daemon pace of 2-3 per session. Wave 1 spanned Phase 2 (Alpha + Beta) + Phase 4 (Gamma) simultaneously. Wave 2 spanned Phase 3 (Delta) + Phase 6 (Epsilon) + Phase 4 (Zeta).
- **Why it works:** Phase boundaries are organisational (thematic grouping for humans), not technical. A frontend code-split doesn't depend on an alembic migration; they just happened to be in different phases because they're different subsystems. File-disjointness is the actual constraint for parallel work.
- **When to apply:** After Phase 1 or whenever ≥6 intake items remain. Rebuild the disjointness map at session start — it changes as intakes close.

### 2. Deep-research phase (Rule 19) as the first step of every stream prompt

- **Context:** Intake specifications tend to drift between filing (days-to-weeks ago) and execution. Code ships, DB state changes, other sessions touch the same surfaces.
- **Pattern:** Every stream prompt starts with a mandatory "Phase 1 — Deep Research" block that includes specific SQL COUNT queries, `grep -rn` audits, and `curl` probes. The agent writes research output to `.planning/fleet/outputs/stream-{name}-YYYY-MM-DD-research.md` BEFORE the plan phase. The research MUST answer: does the intake's premise match live state?
- **Result this session:** Rule 19 caught 4 stale conditions across the 6 streams — D1 backfill was 0-row no-op, D2 was 1 field not 2, A2 was already solved, A3 was already patched. Estimated saved work: 30-60 minutes of implementation + review + test cycles.
- **Why it works:** The research output is a 2-3 minute investment (fast queries, small greps) that gates the rest of the stream. If the premise is wrong, the agent documents the no-op and moves on. If the premise holds, the agent has better context for implementation than the intake alone provided.
- **When to apply:** Universally for any build/data migration/refactor stream. Skip for trivial cosmetic changes (e.g., typo fixes) where the premise is self-evident.

### 3. Commit-small-commit-often with sub-task granularity within a stream

- **Context:** Each stream had 1-7 sub-tasks bundled. Large single commits make rollback coarse and bisect painful.
- **Pattern:** Commit each sub-task individually with a scoped message. Alpha's 7 sub-tasks (D1/D2/D3/I1/I2/I3/I4) → 8 commits (plus test_schemas). Delta's 3 sub-sections (O1 cron / O2 migrator / O3 observability) → 7 commits. Beta's pagination migration → 5 commits, one per endpoint family.
- **Result:** Individual `git revert` on any sub-task works cleanly. Cross-stream commit interleaving (the worktree-sharing issue) was less destructive because only one sub-task's worth of context went into any mixed commit. Each commit passed its own slice of verification before the agent moved to the next.
- **Why it works:** The agent's internal gating loop (edit → test → commit) surfaces issues at the smallest possible granularity. If D1 migration fails, D2/D3 are still clean commits. If the alembic chain breaks at revision N+2, `alembic downgrade -1` recovers cleanly.
- **When to apply:** Any stream with ≥3 sub-tasks. For single-task streams, one commit is fine.

### 4. Global `/health/deep` + DPCS10 canary as the anti-regression guard in every stream

- **Context:** Phase 1 anti-pattern #2 — Stream D (docker-socket-proxy) passed its own verification but regressed `/health/deep` because that surface wasn't in its battery.
- **Pattern:** Every Wave 1+2 stream's verification included the FULL global battery — `/health` + `/health/deep` + auth matrix (401/200) + DPCS10 canary (260 blobs) — even if the stream's changes didn't touch those surfaces. Stream-local checks (alembic upgrade head for Alpha, Page envelope shape for Beta, bundle size for Gamma, /metrics + /ready for Delta, MCP tool count for Epsilon, tsc-b-force + acceptance grep for Zeta) ran in addition to the global battery.
- **Result:** Zero /health or DPCS10 regressions across 6 streams. The one close call (Delta's /health refactor — extracting /health to a new router) was caught by the pre-commit verification and adjusted before merge (Delta kept /health/deep verbatim for back-compat and added /ready as an alias).
- **Why it works:** The shared surfaces (auth middleware, docker proxy, DB connection, firmware detection roots) are cross-cutting enough that ANY stream could inadvertently touch them. A cheap 5-second battery at the end of each stream catches 90% of anti-pattern-#2-class regressions.
- **When to apply:** Universally. DPCS10 is the wairz-specific integrity canary; `/health/deep` is the cross-cutting dep check. Both should be in every stream's verification regardless of scope.

### 5. Rule 17 canary for silent-pass CLI tools (concrete instance: tsc -b --force)

- **Context:** `tsc --noEmit` exits 0 without checking when tsconfig uses `files: []` + references. Looks identical to "no errors."
- **Pattern:** Before trusting ANY "green" typecheck, run a canary: write a deliberately-broken one-line TypeScript file, run the command, confirm it fails. If the canary passes, the command is not checking and must be adjusted.
- **Result:** Gamma discovered `--noEmit` silent-pass on its first typecheck. Canary-ed, switched to `tsc -b --force`, all subsequent checks were real. Zeta was instructed on this in its prompt and passed cleanly.
- **Why it works:** It's a 3-second sanity check that localises "the command is broken" vs. "there are actually no errors." Rule 17 exists precisely for this case.
- **When to apply:** Any time a verification step's success criterion is "exit 0" AND the output is short/empty. Critical for: tsc, lint, format-check, cache-enabled builds.

### 6. Multi-commit feature ledger over single-commit "PR"

- **Context:** Traditional GitHub PR model is one branch → one merge commit.
- **Pattern:** Wave 1+2 shipped 28 individually-verified commits directly to `clean-history`. Each commit is a complete feature-slice (not a WIP). Reviewers can bisect on any slice. Rollback is `git revert <sha>` per slice.
- **Result:** 28 commits, 6 feature-level changes across 6 subsystems, in one session. If a future session finds a regression, `git log -S<symbol>` + `git bisect` both surface the exact introducing commit in <10 operations.
- **Why it works:** Wairz is a solo-dev project with no PR gate. The single-session commit rate is bounded by reviewer capacity (which is zero — commits merge as they pass CI). Multi-commit shipping gives all the benefits of per-slice verification without the overhead of branch + review + merge ceremonies.
- **When to apply:** Solo-dev or trusted-small-team projects with strong CI. Avoid for regulated / review-mandatory codebases.

## Candidate Learned Rules (proposed for future CLAUDE.md integration)

- **#23 candidate:** "When dispatching Fleet waves with `isolation: \"worktree\"`, instruct each sub-agent to `git checkout -b feat/stream-{name}-{date}` BEFORE any file writes. `worktreePath: ok` sentinel does NOT provide working-tree isolation — it's a post-hoc marker and agents share the on-disk checkout."

- **#24 candidate:** "For frontend typecheck in wairz, use `npx tsc -b --force`, never `tsc --noEmit`. The tsconfig uses `files: []` + project references; `--noEmit` exits 0 silently without checking."

- **#25 candidate:** "When implementing an intake with ≥3 sub-tasks, commit each sub-task as its own commit. Rule-8 class-shape rebuild happens once at the end of the stream. Individual `git revert` per sub-task is trivial; a bundled commit forces all-or-nothing rollback."
