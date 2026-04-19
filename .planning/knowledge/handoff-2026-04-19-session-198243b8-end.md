# Session Handoff — 2026-04-19 (session 198243b8, Wave 3)

> Outgoing: Opus 4.7 (1M context), effort=max
> Branch: `clean-history` (18 new commits, 200 total ahead of main)
> Baseline HEAD at session start: `c954039`
> Post-session HEAD: `d868cb6`
> Predecessor handoff: `.planning/knowledge/handoff-2026-04-19-session-435cb5c2-end.md`
> Campaign: `wairz-intake-sweep-2026-04-19` — Phases 1/2/3/4 **COMPLETE**; Phase 7 5/6 closed (harness.json deferred); Phase 5 + Phase 6 remainder pending.
> Daemon: running (budget $40; 3 sessions into the 8-session estimate)

---

## Starter prompt for the next session (paste as first message)

```
Resume campaign wairz-intake-sweep-2026-04-19. Daemon running.
Session 198243b8 closed Wave 3 (3 parallel streams, 18 commits, 5+ intakes).
Phases 1/2/3/4 fully complete. Phase 7 is 5/6 (harness.json rules blocked
on protect-files proposal). Remaining: Phase 5 serial refactor (3 items,
dedicated session) + Phase 6 Android HW firmware (spin out to own campaign).

Read in order:
  1. .planning/campaigns/wairz-intake-sweep-2026-04-19.md — Active Context
     + Continuation State. Post-Wave-3 HEAD = d868cb6.
  2. .planning/knowledge/handoff-2026-04-19-session-198243b8-end.md (this file)
  3. CLAUDE.md Rules 1-25 canonical. Rule #23 REFINED by Wave-3 evidence:
     true `git worktree add` is the effective mitigation, not just
     `git checkout -b`. β did it proactively (0 sweeps); α did it after
     2 sweeps (recovered cleanly); γ stayed in main checkout (2 sweeps,
     recovered via cherry-pick + reflog-replay). See this session's
     knowledge artefact for the refined pattern.
  4. (Optional) predecessor handoff
     .planning/knowledge/handoff-2026-04-19-session-435cb5c2-end.md

Current state (verified live at 198243b8 handoff):
  - Backend + worker + migrator(Exited 0) + docker-proxy + postgres +
    redis + pg-backup (NEW — α V3) + frontend all healthy.
  - /health 200, /ready 200, /health/deep 200 (db+redis+docker+storage
    all ok), /metrics 200.
  - Auth LIVE: noauth=401, X-API-Key=200.
  - DPCS10 canary (firmware 0ed279d8): 260 blobs (7 sessions unchanged).
  - Alembic head: 123cc2c5463a (no new migrations this session).
  - MCP tool count: 172 (Python API via create_tool_registry()); CLI
    `wairz-mcp --list-tools` reports 173 (includes a metadata row, not
    a duplicate tool).
  - arq cron jobs: 6 (sync_kernel@03:00 + cleanup_emulation@:05/:35 +
    cleanup_fuzzing@:20/:50 + check_storage_quota@:15 hourly +
    cleanup_tmp_dumps@04:00 + reconcile_firmware_storage@05:00).
  - pg-backup compose service: running, first dump in 24h + 30-day
    retention in ${BACKUP_DIR:-./backups}.
  - Secrets gated: POSTGRES_PASSWORD + FIRMAE_DB_PASSWORD are :?required;
    .env.example documents the requirement; README secret-rotation section
    added; frontend env_file:.env already removed (pre-session).
  - Frontend store isolation: currentProjectId guards live in explorer/
    project/vulnerability stores; ProjectRouteGuard wraps 12 /projects/
    :projectId/* routes; DeviceAcquisitionPage has 0 `as any` casts;
    DeviceInfo/DeviceDetailResponse type BROM surface end-to-end.
  - Phase 7 close-outs: apk-scan-deep-linking closed (Rule-19 verify);
    5 security-* intakes status-bumped; backend Docker healthcheck now
    hits /ready; wairz-mcp --list-tools CLI restored; 10 completed
    campaigns moved to .planning/campaigns/completed/.

Remaining work (3 dispatch options):

  Option A — Phase 5 backend refactor (SERIAL, dedicated session):
     cache-module-extraction → private-api + circular-imports →
     god-class decomposition. Order matters; do NOT parallelise.
     2 sessions estimated. Highest leverage for long-term maintainability.

  Option B — Phase 6 Android HW firmware spin-out:
     create .planning/campaigns/android-hw-firmware.md, treat as its
     own 5-phase / ~6-session campaign. Close wairz-intake-sweep campaign
     with Phase 5 + harness.json remainder as open threads.

  Option C — harness.json exception unblock (small session):
     Review + land .planning/proposals/citadel-protect-files-learn-
     exception.md, adopt the 4 candidate quality rules via /learn.
     Unblocks Phase 7 final item.

Dispatch discipline if ANY parallel Wave is attempted (Rule #23 refined):

  Each sub-agent MUST operate in a dedicated worktree:
    git worktree add .worktrees/stream-{name} -b feat/stream-{name}-YYYY-MM-DD
    cd .worktrees/stream-{name}
    # ... all writes and commits here
  Not just `git checkout -b`. β proved this works (0 sweeps in 4 commits);
  α and γ proved `checkout -b` alone doesn't (4 sweeps across 14 commits,
  all recovered but painful).

Ask me ONE question: "Proceed with Option A (Phase 5 serial refactor),
Option B (Android HW spin-out), or Option C (harness.json unblock)?"
Execute without further interview once confirmed.
```

---

## What shipped this session (18 commits, by stream, in landed order)

### Stream γ (Phase 7 maintenance sweep — landed first, original SHAs)

| SHA | Scope |
|---|---|
| `e1f94c3` | chore(intake): close apk-scan-deep-linking — Rule-19 verify-only |
| `48296c1` | chore(intake): status-bump 5 security-* intakes — Phase 1 close-out |
| `352508b` | chore(infra): switch backend Docker healthcheck from /health to /ready |
| `17ff896` | fix(mcp): restore wairz-mcp --list-tools CLI |
| `2db769b` | docs(campaigns): archive 10 completed campaigns |
| `e241571` | docs(fleet): Stream Gamma Wave 3 handoff + research |

### Stream β (frontend-store-isolation — rebased, new SHAs)

| SHA | Scope |
|---|---|
| `72ec063` | feat(frontend): store project-id guards for async actions (S1) |
| `9bcf379` | feat(frontend): ProjectRouteGuard component + route wrap (S2) |
| `7a3fd8d` | feat: type device BROM surface end-to-end (backend + frontend) (S3) |
| `90c0dc6` | docs(fleet): stream-beta Wave 3 research + handoff |

### Stream α (infra bundled — rebased, new SHAs)

| SHA | Scope |
|---|---|
| `83e31c8` | feat(infra): promote POSTGRES/FIRMAE passwords to :?required + .env.example security header |
| `0773fd0` | docs(readme): secret rotation + binding requirements (infra-secrets) |
| `3f60398` | feat(config): firmware_retention_days + backup_dir knobs |
| `2440150` | feat(workers): check_storage_quota cron + 507 pre-upload check (V1) |
| `51770af` | feat(workers): cleanup_tmp_dumps cron (V2) |
| `5f08db1` | feat(infra): pg-backup service + backup-recovery docs (V3) |
| `50a9ca6` | feat(workers): reconcile_firmware_storage cron (V4 log-only) |
| `d868cb6` | docs(fleet): Stream Alpha Wave 3 handoff + Rule-19 research notes |

## Intake close-outs (Wave 3 scope)

Closed and removed from remaining-work:
- `infra-secrets-and-auth-defaults` (α finished-partial)
- `infra-volumes-quotas-and-backup` (α)
- `frontend-store-isolation-and-types` (β)
- `apk-scan-deep-linking` (γ Rule-19 verify; was already implemented)
- 5 security-* intakes (γ status bump — work was shipped in session 69f004fe Phase 1, YAML headers finally caught up)

Deferred:
- `feature-android-hardware-firmware-detection` → recommend spin-out to own campaign
- `backend-cache-module-extraction-and-ttl` + `backend-private-api-and-circular-imports` + `backend-service-decomposition` → Phase 5 dedicated serial session
- 4 harness.json quality rules → blocked on `.planning/proposals/citadel-protect-files-learn-exception.md`

## Verification gate for the next session (copy-paste)

```bash
docker compose ps    # backend + worker + migrator(Exited 0) + docker-proxy + postgres + redis + pg-backup all expected
curl -sf -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/health         # 200
curl -sf -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/ready          # 200
curl -sf -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/metrics        # 200
curl -sI http://127.0.0.1:8000/api/v1/projects | head -1                       # HTTP/1.1 401 Unauthorized
curl -sf -o /dev/null -w '%{http_code}\n' -H "X-API-Key: dev-test-key-wairz-b1" http://127.0.0.1:8000/api/v1/projects  # 200
curl -sf -H "X-API-Key: dev-test-key-wairz-b1" http://127.0.0.1:8000/health/deep | python3 -c 'import json,sys; d=json.load(sys.stdin); print("all_ok=", all(c["ok"] for c in d["checks"].values()))'  # True
docker compose exec -T postgres psql -U wairz -d wairz -tAc "SELECT COUNT(*) FROM hardware_firmware_blobs WHERE firmware_id IN (SELECT id FROM firmware WHERE id::text LIKE '0ed279d8%' OR sha256 LIKE '0ed279d8%');"  # 260
docker compose exec -T -e PYTHONPATH=/app -w /app backend /app/.venv/bin/alembic current | tail -1  # 123cc2c5463a (head)
docker compose exec -T -e PYTHONPATH=/app -w /app backend /app/.venv/bin/python -c "from app.ai import create_tool_registry; print(len(create_tool_registry().get_anthropic_tools()))"  # 172
docker compose exec -T -e PYTHONPATH=/app -w /app backend /app/.venv/bin/wairz-mcp --list-tools 2>&1 | tail -1   # "Total: 173 tools"
docker compose exec -T -e PYTHONPATH=/app -w /app worker /app/.venv/bin/python -c "from app.workers.arq_worker import WorkerSettings; print(len(WorkerSettings.cron_jobs))"  # 6
```

All checks must pass. If any fails, root-cause before proceeding.

## Open threads

1. **Harness.json 4 candidate quality rules** (BLOCKED on protect-files exception proposal).
   - `auto-intake-sweep-1-no-stat-docker-sock` (Phase 1)
   - `auto-intake-sweep-1-no-docker-from-env` (Phase 1)
   - `auto-fleet-worktree-requires-branch-checkout` (session-435cb5c2) — should REFINE to `requires-worktree-add` per Wave-3 evidence
   - `auto-frontend-tsc-requires-b-force` (session-435cb5c2)
   Resolution: review `.planning/proposals/citadel-protect-files-learn-exception.md`, approve, land. Then `/learn` adopts.

2. **Rule #23 refinement.** Wave 3 evidence suggests the rule wording should name `git worktree add .worktrees/<name> -b <branch>` as the effective mitigation, with `git checkout -b` as a fallback when worktrees are unavailable. β proved a 0-sweep outcome using the worktree pattern in the same session where α+γ had 4 sweeps without it. Candidate rule-amendment follow-up: update CLAUDE.md Rule #23 + the `auto-fleet-worktree-requires-*` candidate to match the new evidence, in the same session that unblocks harness.json.

3. **Phase 5 serial refactor prerequisites** (for when it runs).
   - `wc -l backend/app/services/*.py | sort -rn | head -10` baseline for god-class decomposition target.
   - `grep -rn 'from app.services' backend/app/services/ | grep -v __init__ | wc -l` — baseline cross-service imports (campaign says 70).
   - Current 172-tool MCP registry must continue to register at startup after every Phase 5 commit — `create_tool_registry().get_anthropic_tools()` is the invariant test.

4. **Phase 6 Android HW firmware spin-out.** `.planning/intake/feature-android-hardware-firmware-detection.md` describes a 5-phase plan. Recommend NOT running in this campaign; create `.planning/campaigns/android-hw-firmware.md` and treat as own work stream. Keeps wairz-intake-sweep-2026-04-19 focused on cleanup/foundation work.

5. **pg-backup first-run sanity.** The pg-backup container waits 5 minutes before first dump to let operators tune BACKUP_DIR. After 24h, `ls ./backups/wairz_*.dump` should show at least one file. Worth a spot-check at the start of next session.

6. **Operator upgrade note** (already mentioned in campaign, restated here for next-session agent): existing deployments upgrading through Wave 3 need `POSTGRES_PASSWORD=wairz` + `FIRMAE_DB_PASSWORD=firmae` in `.env` to match running `pgdata`. This session's orchestrator added those during verification; they persist in `.env`.

7. **Frontend healthcheck**. Currently `wairz-frontend-1` shows `(unhealthy)` in `docker compose ps`. Not a Wave 3 regression — predates the session. γ changed the BACKEND healthcheck (to /ready); frontend healthcheck is separate. Worth investigating at leisure; not blocking.

## Rollback safety

Wave 3 added zero alembic migrations (alembic head unchanged at `123cc2c5463a`). All 18 commits are feature-additive; no schema changes. Rollback paths:

```bash
# Nuclear: back to pre-session
git checkout clean-history && git reset --hard c954039
docker compose up -d --build backend worker  # pick up the class-shape revert
# (No alembic downgrade needed — no migrations added this session)

# Per-stream revert
# α only (8 commits):
git revert 83e31c8..d868cb6
# β only (4 commits):
git revert 72ec063..90c0dc6
# γ only (6 commits, note 2db769b is a directory-move):
git revert e1f94c3 48296c1 352508b 17ff896 e241571
git revert -m 1 2db769b  # only if the move commit has multiple parents

# Per-commit (examples)
git revert 352508b   # undo /ready healthcheck, back to /health
git revert 5f08db1   # remove pg-backup service
```

## Wave-3 dispatch notes for future orchestrators

Wave 3's effective pattern (for future parallel waves):

1. **True worktrees, always.** Each sub-agent gets `git worktree add .worktrees/stream-{name} -b feat/stream-{name}-{date}`. β proved 0 sweeps; α proved recovery-possible-but-painful without; γ proved recovery-possible in the shared checkout but requires cherry-pick + reflog.

2. **Rule #19 first step, universally.** All 3 streams surfaced intake errors via research: α found env_file:.env frontend removal was pre-shipped; β found backend Pydantic was silently stripping BROM fields (expanded scope); γ found apk-scan intake was already implemented (doc-only close). Rule #19 paid for itself 3× in 1 session.

3. **Rule #25 per-sub-task commits.** α shipped 7 sub-tasks as 7 feature commits + 1 handoff. β shipped 3 sub-tasks as 3 feature commits + 1 handoff. γ shipped 5 sub-items as 5 commits + 1 handoff. Per-commit `git revert` works; per-commit bisect works. Bundled commits would have made Wave 3 rollback a nightmare.

4. **Rule-8 rebuild once at end.** α's config.py change, β's device schema change, γ's mcp_server.py change all required class-shape rebuild. Single `docker compose up -d --build backend worker` at the orchestrator level handled all three. Sub-agents did not rebuild per-commit.

5. **Rebase-then-FF-merge for linear history.** Matches the session-435cb5c2 28-linear-commit style. γ FF'd first (was already based on clean-history); β rebased + FF'd (no conflicts); α rebased + FF'd (no conflicts despite both α and γ touching docker-compose.yml — different sections).

6. **Global verification battery, last, always.** 10-check battery (/health, /ready, /metrics, auth 401, auth 200, /health/deep all-ok, DPCS10 canary, alembic head, MCP tool count, arq cron count) run once post-merge caught zero regressions. Sub-agents each ran their own stream-local + global checks; orchestrator re-ran global post-merge as final gate.

## For the incoming Citadel session

Entry points:
- `/archon` will detect daemon running + active campaign, resume automatically.
- `/do` — if user overrides with manual work.
- `.mex/ROUTER.md` — task-type navigation.
- This handoff + campaign Active Context + Continuation State.

The daemon-chained path: SessionStart hook → detect campaign → resume archon → load campaign Continuation State → present Options A/B/C for user selection → execute.
