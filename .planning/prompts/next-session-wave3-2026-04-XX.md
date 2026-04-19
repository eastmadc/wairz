# Next-session starter prompt — Wave 3 (paste as first message)

> Generated: 2026-04-19 end-of-session 435cb5c2
> Campaign: `wairz-intake-sweep-2026-04-19` (Phases 1+2 COMPLETE; 3:1/3; 4:2/3; 6:1/3)
> Post-Wave-2 HEAD: `bdc5745` (28 feature commits + 1 docs close-out)
> Daemon: running (budget $40 @ $2/session; 2 sessions remain in budget)

---

## Copy-paste prompt

```
Resume campaign wairz-intake-sweep-2026-04-19 at Wave 3. Daemon running.
Session 435cb5c2 cleared 6 intakes via Wave 1+2 cross-phase dispatch;
9-10 actionable items remain (see below — one may already be done).

Read in order:

  1. .planning/campaigns/wairz-intake-sweep-2026-04-19.md
     — Active Context + Continuation State + Wave-3-recommendation section.
  2. .planning/knowledge/wairz-intake-sweep-wave12-antipatterns.md
     — CRITICAL: anti-pattern #1 (Fleet worktree isolation is broken).
       Apply per-stream `git checkout -b` discipline in dispatch prompts.
  3. .planning/knowledge/wairz-intake-sweep-wave12-patterns.md
     — 6 patterns + 3 candidate Learned Rules.
  4. .planning/knowledge/handoff-2026-04-19-session-435cb5c2-end.md
  5. CLAUDE.md rules 1-22 canonical.

Current state (verified at 435cb5c2 handoff):
  - HEAD=bdc5745. All containers healthy.
  - /health+/ready+/health/deep=200, /metrics=200 (Prom text).
  - Auth 401/200. Alembic head 123cc2c5463a. DPCS10 canary=260.
  - MCP tools=172. arq cron=3. Migrator Exited(0). alembic_version=1 row.
  - 28 commits shipped across Phases 2/3/4/6.

Remaining intake inventory (deep-research audit 2026-04-19):

  NEEDS-RULE-19-VERIFY (may already be done):
    - apk-scan-deep-linking — body says "Status: Completed" but YAML
      header has no status. Grep git log + behavioural check first.

  PHASE 3 remaining (both touch docker-compose.yml — SERIAL within group):
    - infra-secrets-and-auth-defaults (partial) — remaining scope:
      .env.example doc, :?error required-mode, frontend env_file removal,
      docker-compose.prod.yml with Docker secrets, README security.
    - infra-volumes-quotas-and-backup — storage quota arq cron, /tmp
      cleanup, pg_dump cron (build on Delta's cron_jobs), orphan detection.

  PHASE 4 remaining (frontend stores/types, ~400 LOC surface):
    - frontend-store-isolation-and-types — S1 store reset race, S2
      project-id guard, S3 DeviceAcquisitionPage `as any` removal.

  PHASE 5 SERIAL (dedicated 2-session block — DO NOT parallelise):
    - backend-cache-module-extraction-and-ttl
    - backend-private-api-and-circular-imports (8+ inline
      `from app.services import X` workarounds; 70 cross-imports baseline)
    - backend-service-decomposition (8 services > 1000 LOC; target <800)

  PHASE 6 remaining:
    - feature-android-hardware-firmware-detection — LARGE (5-phase,
      ~6 sessions). Recommend spinning out to its own campaign file
      rather than treating as one stream.

  PHASE 7 maintenance sweep (trivial, batched):
    - quick-wins-bundle Q4 (DEFERRED — blocks on Phase 5 cache extraction)
    - Mark 5 stale security-* intakes as completed (work shipped Phase 1)
    - Harness.json quality-rule adoption (4 rules pending, hook-blocked):
      auto-intake-sweep-1-no-stat-docker-sock,
      auto-intake-sweep-1-no-docker-from-env,
      auto-fleet-worktree-requires-branch-checkout (NEW — session 435cb5c2),
      auto-frontend-tsc-requires-b-force (NEW — session 435cb5c2)
    - Frontend healthcheck migration /health → /ready (Delta follow-up)
    - Fix wairz-mcp --list-tools CLI (ModuleNotFoundError, pre-existing)

Wave 3 dispatch plan — OPTION B (RECOMMENDED, yield 5+ intakes/session):

  Stream α: Infra bundled (SERIAL within) — both touch docker-compose.yml
           • infra-secrets-and-auth-defaults finish-partial
           • infra-volumes-quotas-and-backup
           Expected 5-7 commits.
           Build on top of Delta's arq cron (add storage_quota + pg_dump
           cron jobs). Do NOT regress docker-socket-proxy from Phase 1.

  Stream β: Frontend stores disjoint (new files + existing store edits)
           • frontend-store-isolation-and-types
           Expected 3-4 commits. tsc -b --force (NOT --noEmit).

  Stream γ: Phase 7 maintenance sweep (batched trivialities)
           • apk-scan-deep-linking Rule-19 verify (if done: mark intake
             completed, no code change)
           • Stale security-* intake close-outs (5 items — header edits)
           • Harness.json 4 quality-rule adoption (bypass protect-files
             hook carefully; check with user before bypassing)
           • Frontend healthcheck /health → /ready in docker-compose.yml
           • Fix wairz-mcp --list-tools entry point
           Expected 3-6 commits.

  Deferred (dedicated future sessions):
    - Phase 5 refactor (serial, 2 sessions)
    - Phase 6 Android HW firmware (6-session campaign; consider
      spinning out `.planning/campaigns/android-hw-firmware.md`)

CRITICAL DISPATCH DISCIPLINE (from Wave-2 anti-pattern #1):

  EACH Wave 3 sub-agent must run FIRST, before any file writes:
    git checkout -b feat/stream-{alpha,beta,gamma}-2026-04-XX
  
  Orchestrator merges after all three complete (sequential FF merges).
  Rationale: `isolation: "worktree"` + `worktreePath: "ok"` does NOT
  isolate working trees. Observed 3 cross-stream file sweeps in 6 streams
  (50% hit rate) in session 435cb5c2. Per-branch isolation is the only
  reliable mitigation until Citadel fleet ships real worktree checkouts.

  If an agent reports `git checkout -b` failed (worktree already on a
  branch from a previous stream), use `git switch -c` with a unique
  suffix. NEVER let two agents share a branch.

VERIFICATION BATTERY PER STREAM (reuse Wave 1+2 shape):

  Stream-local:
    - intake's acceptance criteria
    - relevant verify command from campaign Phase-end-conditions table
  
  Global (in every stream, always last — rate-limit counter reasons):
    - /health 200
    - /health/deep all-ok (4 subsystems)
    - /ready 200
    - /metrics 200 with Prom HELP lines
    - auth matrix: no-key=401, good-key=200
    - DPCS10 canary = 260 blobs
    - alembic current = 123cc2c5463a (no new revs unless Stream α adds)
    - MCP tool count = 172 (no new tools in Wave 3)

  Frontend streams: `(cd frontend && npx tsc -b --force)` — NOT `--noEmit`
  + Rule 17 canary. Stream γ may touch backend too; run both checks.

Rule-19 enforcement (mandatory first step per stream):

  Before implementing, measure the intake's premise:
    - α: grep current docker-compose.yml for secrets/volumes/ports baseline
    - β: grep current stores for ProjectId comparisons + `as any` counts
    - γ: actually USE the APK deep-linking URL to see if it works end-to-end
  
  If the premise is false (like 4 cases in Wave 1+2), document as no-op
  and move to the next sub-task. Do NOT write dormant code.

Handoff discipline (same shape as session 435cb5c2):
  Each stream writes .planning/fleet/outputs/stream-{name}-2026-04-XX-research.md
  and stream-{name}-2026-04-XX-wave3.md.
  End of session: /learn extraction + handoff via
  .planning/knowledge/handoff-2026-04-XX-session-{id}-end.md.

Ask me ONE question:

  "Proceed with Wave 3 Option B (infra-bundled + store-isolation +
  Phase-7-maintenance-sweep) using per-stream branch isolation?"

Execute without interview once confirmed.
```

---

## Why Option B beats Option A and C

- **Option A** (infra + APK + stores): yields 3-4 intakes closed. Wastes Stream γ on a single intake.
- **Option B** (infra + stores + P7 sweep): yields 5+ intakes closed (infra×2 + stores + sweep items). Phase 7 trivialities accumulate cost if carried; batching them closes the noise in 30 min.
- **Option C** (Phase 5 refactor serial): valid but doesn't fit the "max throughput" user preference for 3-parallel waves. Reserve for a dedicated session when the refactor is the day's goal.

## Harness issue (for Dustin — out-of-band follow-up)

The Fleet worktree-isolation problem is 3-for-6 in this session. Candidate fixes (roughly in order of effort):

1. **Prompt discipline (current mitigation):** instruct each agent to `git checkout -b` first. Works but is a contract, not an invariant.
2. **Fleet harness patch:** make `isolation: "worktree"` actually create a `git worktree add ../wairz-<uuid>` and CD into it. Current behaviour treats `worktreePath: "ok"` as a sentinel string, not a filesystem path.
3. **Post-dispatch check:** orchestrator verifies `git worktree list` shows N distinct paths for N active agents. Fails fast if not.
4. **Commit-scope linter:** post-commit hook that rejects commits containing files outside a declared stream scope. Detects the anti-pattern when it happens rather than preventing it.

(1) is live in the prompt above. (2) is the durable fix — belongs in Citadel.

## Campaign-health snapshot (post-session 435cb5c2)

- Intakes closed: 9/17 (53%) in 2 sessions (69f004fe = 3; 435cb5c2 = 6).
- Feature commits: 33 (5 Phase-1 + 28 Wave-1+2).
- Coverage: Phase 1 done; Phase 2 done; Phase 3 partial (1/3); Phase 4 partial (2/3); Phase 5 untouched; Phase 6 partial (1/3); Phase 7 untouched.
- Estimated to campaign close:
  - Wave 3 (this prompt) → 5 intakes closed → 14/17 (82%)
  - Phase 5 dedicated sessions ×2 → 3 intakes closed → 17/17 (100%)
  - Phase 6 HW-firmware spin-out → separate campaign, not counted here
- Budget remaining at current burn: $40 - (~$4 Phase 1) - (~$8 session 435cb5c2) = ~$28 for 2-3 more sessions.
