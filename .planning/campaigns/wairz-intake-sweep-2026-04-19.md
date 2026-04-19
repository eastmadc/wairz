---
Status: active
Direction: Execute all remaining pending intake items from .planning/intake/ as a single multi-session campaign, phased by domain (security → data → infra → frontend → backend refactor → features → maintenance), using /fleet for parallel streams within a phase.
Created: 2026-04-19
Estimated Sessions: 8
Type: build
Baseline HEAD: 3d8aa10 (B.1 pure-ASGI auth middleware shipped)
Baseline tsc errors: unverified at campaign start (frontend container path mismatch — re-baseline at first build phase)
Daemon: activating (budget $40 @ $2/session, 2x safety margin)
---

# Campaign: Wairz Intake Sweep (2026-04-19)

## Direction

Clear the entire `.planning/intake/` backlog of 20 pending items by decomposing into 7 domain-phases. Within each phase, independent items run as Fleet streams in isolated worktrees; sequential items (e.g. backend decomposition depending on private-API audit) run single-stream. Daemon chains sessions after each phase end-condition gate.

**Three intakes already completed** (verified via `grep -m1 '^status:'` scan at campaign creation) and are excluded from scope:
- `data-analysis-cache-operation-varchar-fix` — alembic 1f6c72decc84 (session 59045370)
- `backend-cwe-checker-session-fix` — commit b9f625a (session 59045370)
- `frontend-firmware-hook-dedup` — commit 97c7c7a (session 59045370)

**Net scope: 17 intake items across 7 phases.**

## Phases

| # | Type | Description | Fleet | Est. Sessions | Status |
|---|------|-------------|-------|---------------|--------|
| 1 | build | **Security sweep** — auth-hardening (B.1.a/b/c), fuzzing-shell-injection (B.2), android-unpack-hardening (B.3), docker-socket-proxy | YES (4 streams) | 1 (done in 1 session) | complete |
| 2 | build | **Data / schema** — schema-drift (findings/firmware/CRA), CHECK/UNIQUE constraints + back_populates audit, pagination on unbounded list endpoints | YES (3 streams) | 1 | pending |
| 3 | build | **Infra** — infra-secrets-and-auth-defaults (finish partial), cleanup-migration-observability (arq reaper + migration-race + /metrics), volumes-quotas-backup | NO (shared config touches) | 1 | pending |
| 4 | build | **Frontend hardening** — api-client-hardening, code-splitting + list-virtualization, store-isolation + project-id guards + device types | YES (3 streams) | 1 | pending |
| 5 | refactor | **Backend refactor** — cache-module-extraction + TTL, private-APIs + break circular imports, god-class decomposition | NO (serial — later phases depend on earlier) | 2 | pending |
| 6 | build | **Feature growth** — Android HW firmware (Adreno+WCNSS / Shannon / Broadcom / MTK DSP), LATTE taint analysis, APK deep-linking | YES (3 streams) | 1–2 | pending |
| 7 | build | **Maintenance sweep** — frontend healthcheck 127.0.0.1, harness.json B.1 quality-rule append, compose-override transition note, orphan campaign archival | NO (single commit) | 0.5 | pending |

## Phase End Conditions

| # | Condition | Type |
|---|-----------|------|
| 1 | `grep -rn 'sh\", \"-c\",\\s*f\"' backend/app/services/ → 0 hits` | command_passes |
| 1 | `curl -sI -H "X-API-Key: dev-test-key-wairz-b1" http://127.0.0.1:8000/api/v1/projects → 200` | command_passes |
| 1 | `curl -sI http://127.0.0.1:8000/api/v1/projects → 401` | command_passes |
| 1 | slowapi rate limit returns 429 after burst | command_passes |
| 1 | streaming upload aborts at MAX_UPLOAD_SIZE_MB + small epsilon | command_passes |
| 1 | android unpack rejects zipslip + symlink-escape test fixtures | command_passes |
| 1 | docker-socket-proxy image in compose; backend reads through proxy, direct /var/run/docker.sock unmounted | file_exists + command_passes |
| 2 | `alembic upgrade head` clean | command_passes |
| 2 | CHECK constraints enforced (INSERT with bad values → IntegrityError) | command_passes |
| 2 | `/api/v1/projects/{id}/sbom/components?limit=50&offset=0` returns paged response with total/limit/offset metadata | command_passes |
| 3 | `docker compose exec backend arq app.workers.arq_worker.WorkerSettings --check-jobs` lists orphan_reaper | command_passes |
| 3 | nightly pg_dump cron defined in compose; `docker compose exec postgres_backup /backup.sh` produces a >1 KiB dump | command_passes |
| 3 | migration-race regression test passes (two workers, single head) | command_passes |
| 4 | `npx tsc --noEmit` clean | command_passes |
| 4 | `ls frontend/dist/assets/*.js \| wc -l` > 5 (code split) | metric_threshold |
| 4 | ExplorePage tree virtualised (scroll to depth 10K, frame-time < 20 ms) | visual_verify |
| 5 | `grep -rn "from app.services" backend/app/services/ \| grep -v __init__ \| wc -l → baseline-X%` | metric_threshold |
| 5 | `wc -l backend/app/services/*.py \| sort -rn \| head -1` < 800 | metric_threshold |
| 5 | all 65+ MCP tools still register at startup (`wairz-mcp --list-tools \| wc -l ≥ 65`) | command_passes |
| 6 | DPCS10 canary gains ≥10 Adreno/WCNSS blobs (from 260 baseline) | metric_threshold |
| 6 | `trace_binary_taint` + `explain_taint_path` MCP tools registered | command_passes |
| 6 | APK deep-link scanner returns scheme list for a test APK | command_passes |
| 7 | `docker compose ps frontend \| grep healthy` | command_passes |
| 7 | `grep -rn BaseHTTPMiddleware backend/app/middleware/ → 0 hits` | command_passes |
| 7 | harness.json custom rule count +1 (B.1 lesson) | command_passes |

## Feature Ledger

| Feature | Phase | Status | Files |
|---------|-------|--------|-------|
| safe_extract_zip (zipslip + bomb + symlink defences) | 1 | done (ab09e1c) | `backend/app/workers/safe_extract.py` (NEW), `unpack_android.py:503,525`, `unpack_common.py:249-267`, `firmware_service.py:224-254` |
| B.1.a startup auth guard + B.1.b slowapi rate limiting + B.1.c streaming upload-size verified | 1 | done (de3f6bd) | `backend/app/config.py` (`allow_no_auth` Field with AliasChoices), `backend/app/main.py` (lifespan assert, SlowAPIMiddleware, 429 handler), `backend/app/rate_limit.py` (NEW, shared Limiter), `backend/app/routers/firmware.py:76` (@limiter.limit 5/min), `backend/app/routers/events.py:35` (@limiter.limit 10/min), `backend/pyproject.toml` (slowapi>=0.1.9) |
| Fuzzing / emulation double-shell injection eliminated (4 sites) | 1 | done (e443def) | `backend/app/services/fuzzing_service.py` (AFL launch + GDB triage → put_archive + argv-list), `backend/app/services/emulation_service.py:462` (argv-list test/chmod loop) + `:1383` (shlex.quote on binary_path). Harness rule `auto-review-no-shell-interpolation` at 0 matches. |
| Docker socket narrowed via tecnativa/docker-socket-proxy sidecar | 1 | done (bac49ea) | `docker-compose.yml` (proxy service + DOCKER_HOST env on backend/worker, socket mount removed from both), `backend/app/config.py` (`docker_host` setting), `backend/app/utils/docker_client.py` (NEW factory), 10 call sites across 8 files migrated from `docker.from_env()` to `get_docker_client()`. Allowlist verified: VOLUMES=0 returns 403, CONTAINERS=1 returns count (19). |
| /health/deep regression fix — docker check now via proxy-compatible `containers.list(limit=1)` instead of socket `os.path.exists` | 1 | in-progress (pending commit) | `backend/app/main.py:186-194` |

## Decision Log

| Date | Decision | Reason |
|------|----------|--------|
| 2026-04-19 | Skip 3 already-completed intakes | `data-analysis-cache-operation-varchar-fix`, `backend-cwe-checker-session-fix`, `frontend-firmware-hook-dedup` all carry `status: completed` header; previous sessions (59045370, 698549d4) shipped them. Evidence-first rule 19 — don't write dormant code for work already done. |
| 2026-04-19 | Phase 1 = Fleet 4-stream parallel | B.1.a/b/c + B.2 + B.3 + docker-socket-proxy touch disjoint files (middleware, services/fuzzing, workers/unpack_*, docker-compose) — safe to run in isolated worktrees. Merge queue handles any config collision. |
| 2026-04-19 | Phase 5 backend refactor = sequential, not fleet | Order matters: private-API audit informs circular-import break (which imports become private after decomposition); cache-module extraction is a prereq for god-class split (the cache is the biggest shared-state blob). |
| 2026-04-19 | Daemon budget $40 @ $2/session | 110 historical sessions × $2 avg; 8-phase estimate × 2 for multi-session phases (5, 6) = 10 sessions × $2 = $20; 2x safety margin per Archon protocol = $40. |
| 2026-04-19 | Campaign scope excludes new intake discoveries | If a phase surfaces a new item (common for rule 19 evidence scans), it gets its own intake file + queues for the next campaign. This campaign closes the KNOWN-at-create-time backlog, not a moving target. |

## Active Context

**Current phase:** 2 COMPLETE · 3 **COMPLETE** (3/3) · 4 **COMPLETE** (3/3) · 6 (1/3) · 7 **COMPLETE (6/6)** — session a90838f6 closed the protect-files-exception thread (Citadel hooks_src/protect-files.js extended with append-only exception + 6 quality rules adopted in wairz harness.json + typecheck.command self-healed). Remaining: Phase 5 serial refactor (3 items, dedicated session) + Phase 6 Android-HW (own campaign spin-out).
**Current sub-step:** session a90838f6 end-of-session (Option C executed: protect-files exception landed in Citadel; wairz harness.json `qualityRules.custom` 15 → 21 + `typecheck.command` self-healed; CLAUDE.md Rule #23 refined; mex Verify Checklist mirrored).

**Session history:**
- 2026-04-19 (session 69f004fe): campaign created. Phase 1 shipped (5 commits). 8/8 verification items PASS.
- 2026-04-19 (session 435cb5c2): **Wave 1+2 cross-phase dispatch — 28 commits, 6 intakes closed.**
  - Wave 1 (3 parallel streams in isolated worktrees):
    - Stream Alpha (GROUP A bundled): 8 commits `9ef0924..4cc5354` — D1 findings.source backfill+NOT NULL, D2 FirmwareDetailResponse extraction_dir, D3 CRA JSONB retype, I1 CHECK constraints on 8 enum-likes, I2 UNIQUE firmware+sbom_components + dedup, I3 indexes, I4 Project back_populates + cascade, test_schemas ORM↔Pydantic alignment. Alembic head `123cc2c5463a`. 9/9 new schema tests pass. Rule 19 caught: D1 backfill was 0-row no-op; D2 was 1 field not 2 (device_metadata already present); 10 duplicate firmware rows deduped (test data); 2 intake allowlists widened to match live DB.
    - Stream Beta (GROUP B.1): 5 commits `8994dcb..3063283` — pagination schema + utility, paged sbom/attack_surface/security_audit/projects/findings endpoints, frontend api-client Page-envelope unwrap. Live probe confirmed OOM risk REAL: one firmware has 180,048 vuln rows. Acceptance grep 0 unbounded `scalars().all()` hits.
    - Stream Gamma (GROUP D.3): 2 direct commits `914d139..bf60b53` + 2 cross-attributed in `f614c43` — PageLoader + lazy App.tsx routes, react-window virtualization for SbomPage + FindingsList. Bundle: **1 chunk → 73 chunks, 455KB → 119KB gzip on /projects (74% reduction)**. Rule-17 canary caught `tsc --noEmit` silent-pass with tsconfig references; corrected to `tsc -b --force`.
  - Wave 2 (3 parallel streams):
    - Stream Delta (infra cleanup+migration+observability): 7 commits `a4e9eb8..daa7ecf` — structlog JSON logging + prometheus-fastapi-instrumentator + /ready alias + /metrics endpoint, arq cron jobs (sync_kernel@03:00, cleanup_emulation@:05/:35, cleanup_fuzzing@:20/:50), FuzzingService.cleanup_orphans reconciliation, one-shot migrator service + stripped alembic from backend/worker entrypoints (migration race fixed), uvicorn/arq logger reroute through JSON handler. 10/10 verification PASS. Migrator `Exited (0)`, alembic_version = 1 row.
    - Stream Epsilon (LATTE LLM taint): 4 commits `cbeb8fd..06b80b8` — YAML sink+source dictionaries, `scan_taint_analysis` + `deep_dive_taint_analysis` MCP tools (LATTE-style prompt composers), registered in `create_tool_registry`, 39/39 unit tests pass. **MCP tool count 170 → 172.** Rule 19: pyyaml already present; DVRF fixture declined for unit tests (integration target). Zero Anthropic SDK, zero API keys — follows existing MCP pattern (tools return prompt strings; Claude client reasons).
    - Stream Zeta (frontend api-client hardening): 2 direct commits `bfbfa91`, `a01236f` + 1 cross-attributed in `e8548fd` — axios request/response interceptors with auth+error toasts + dedupe, apiUrl() helper + API_BASE migration across 8 files, p-limit chunking for bulkResolve. Added sonner + p-limit deps. Rule 19: SecurityScanPage hard-code already patched; A2 VITE_API_KEY rotation already handled by existing getApiKey interceptor.
- 2026-04-19 (session a90838f6, Option C): **Phase 7 6/6 closed — Citadel `protect-files.js` append-only exception landed; 6 candidate harness rules adopted; typecheck.command self-healed.** Citadel `hooks_src/protect-files.js` extended 305 → 508 lines with `isAllowedHarnessJsonChange` + `isAllowedQualityRulesAppend` + `isAllowedTypecheckChange` validators (single-key-change discipline; schema invariants on appended rules; allowlist on typecheck commands). 7 new integration-test sequences in `Citadel/scripts/integration-test.js` (existing 19 still green; full suite now 26/26). Wairz `.claude/harness.json` qualityRules.custom 15 → 21: 2 Phase-1 candidates (no-stat-docker-sock, no-docker-from-env), 3 Wave-3 candidates (pydantic-extra-ignore-on-api-schemas, frontend-tsc-no-noemit, intake-yaml-status-lowercase), 1 refined session-435cb5c2 candidate (fleet-worktree-requires-worktree-add — was `requires-branch-checkout`). `typecheck.command` swapped `npx tsc --noEmit` → `npx tsc -b --force` via the secondary exception path (resolves CLAUDE.md Rule #24's stale-companion defect). CLAUDE.md Rule #23 refined inline to name `git worktree add` as primary mitigation per Wave-3 evidence (β 0 sweeps, α+γ 4 sweeps); `.mex/context/conventions.md` Verify Checklist mirrored per Rule #21. Proposal `citadel-protect-files-learn-exception.md` marked Resolved with full implementation notes. Net wairz commits: 0 application code changes; harness.json + CLAUDE.md + mex + 1 antipatterns doc + 1 proposal; +1 Citadel commit (cross-repo). Daemon budget consumed: ~$2.
- 2026-04-19 (session 198243b8): **Wave 3 three-stream dispatch — 18 commits, 5+ intakes closed across Phases 3/4/7.**
  - Stream α (infra bundled — 8 commits `83e31c8..d868cb6` after rebase onto clean-history): finished `infra-secrets-and-auth-defaults` (POSTGRES/FIRMAE passwords `:?required`; `.env.example` security header; README secret-rotation section; no frontend `env_file:` change — already shipped in b9f438f per Rule #19) + all of `infra-volumes-quotas-and-backup` V1/V2/V3/V4 (config.py `firmware_retention_days` + `backup_dir`; `check_storage_quota_job` + 507 pre-upload check; `cleanup_tmp_dumps_job`; new `pg-backup` compose service with nightly `pg_dump -Fc` + 30-day retention + `docs/operations/backup-recovery.md`; `reconcile_firmware_storage_job` log-only). arq cron_jobs 3 → 6.
  - Stream β (frontend-store-isolation — 4 commits `72ec063..90c0dc6` after rebase): S1 `currentProjectId` check-before-commit guard in explorerStore/projectStore/vulnerabilityStore; S2 `ProjectRouteGuard` wrapping 12 `/projects/:projectId/*` routes; S3 end-to-end BROM typing (backend `DeviceInfo.mode/available/error` + `DeviceDetailResponse.chipset` + service passthrough + frontend `DeviceMode` union + removal of all 5 `as any` casts). **β Rule-19 save**: intake S3 was half-wrong — backend Pydantic `extra="ignore"` was silently stripping 4 BROM fields, so `(dev as any).mode` was always undefined at runtime. Frontend-only typing fix would have left the feature broken; β expanded scope end-to-end. Rule-17 canary passed twice.
  - Stream γ (Phase 7 maintenance sweep — 6 commits `e1f94c3..e241571` landed directly, pre-rebase): apk-scan-deep-linking closed (Rule-19 verify); 5 stale security-* intakes status-bumped; backend Docker healthcheck `/health` → `/ready`; `wairz-mcp --list-tools` CLI restored (was `ModuleNotFoundError`); 10 completed campaigns archived via `git mv` to `.planning/campaigns/completed/`; 4 candidate harness.json rules DEFERRED (protect-files exception proposal still `status: proposed`).

**Wave-3 anti-pattern confirmed 4× more this session (Rule #23 damage catalog — cross-stream commit sweeps despite per-branch discipline):** all three sub-agents reported the shared-checkout symptom again. α swept gamma content twice before creating its own true `.worktrees/stream-alpha`; γ recovered via cherry-pick + reflog-replay twice during its run. β's agent identified the fix early and created a true `git worktree add .worktrees/stream-beta` proactively. The `isolation: "worktree"` sentinel is still a no-op at the working-tree level; the effective mitigation is `git worktree add <path> <branch>` + operate IN that path. CLAUDE.md Rule #23 wording should be tightened to name true `git worktree add` as the primary mitigation (not just `git checkout -b`). Updated knowledge artefact will be written this session.

**Post-session verification (HEAD = d868cb6):**
- /health 200 · /ready 200 · /health/deep all-4-ok (db+redis+docker+storage) · /metrics 200
- Auth matrix: noauth=401 · auth-GET=200 (`-H X-API-Key: dev-test-key-wairz-b1`)
- Alembic head `123cc2c5463a` (unchanged — Wave 3 added no migrations) · DPCS10 canary = 260 · MCP tools = 172 (Python API) / 173 (CLI `--list-tools` includes a metadata row)
- arq cron jobs = 6 (3 Delta + check_storage_quota_job + cleanup_tmp_dumps_job + reconcile_firmware_storage_job)
- pg-backup container running, first-run 5-min startup delay logged
- docker compose config renders clean with `:?required` POSTGRES_PASSWORD / FIRMAE_DB_PASSWORD gates
- Phase 1 invariant: docker-proxy `DOCKER_HOST=tcp://docker-proxy:2375` intact

## Continuation State

**Phases status after 198243b8 (Wave 3):**
- Phase 1: COMPLETE (69f004fe, 5 commits)
- Phase 2: COMPLETE (435cb5c2, 13 commits — schema-drift, constraints, pagination)
- Phase 3: **COMPLETE** (435cb5c2 Delta cleanup-migration-observability + 198243b8 α infra-secrets-finish + infra-volumes-quotas-and-backup)
- Phase 4: **COMPLETE** (435cb5c2 Gamma + Zeta code-split/virtualize/api-client + 198243b8 β store-isolation/device-types)
- Phase 5: 0/3 (serial refactor — dedicated session). Items: `backend-cache-module-extraction-and-ttl`, `backend-private-api-and-circular-imports`, `backend-service-decomposition`.
- Phase 6: 1/3 (435cb5c2 Epsilon LATTE taint + 198243b8 γ apk-scan Rule-19 close). Remaining: `feature-android-hardware-firmware-detection` — spin out to dedicated campaign per plan.
- Phase 7: **COMPLETE (6/6)** — session a90838f6 closed the harness.json blocker via Citadel protect-files append-only exception. 6 candidate rules adopted (15 → 21); typecheck.command self-healed.

**Net remaining after this campaign's current scope:**
- 3 Phase-5 serial refactors (dedicated session, ~2 sessions)
- 1 Phase-6 Android HW firmware spin-out campaign (~6 sessions in own campaign file)

**Next session pickup options:**
1. **Read** this campaign file + `.planning/knowledge/handoff-2026-04-19-session-198243b8-end.md` + CLAUDE.md Rules 1–25 canonical.
2. **Option A (Phase 5 serial refactor — RECOMMENDED for depth):** cache-module-extraction → private-api + circular-imports (8+ inline `from app.services import X` workarounds; 70 cross-imports baseline) → god-class decomposition (8 services > 1000 LOC; target <800). ORDER MATTERS; do NOT parallelise within Phase 5. 2 sessions estimated.
3. **Option B (Phase 6 Android HW firmware spin-out):** create `.planning/campaigns/android-hw-firmware.md`, close this campaign, begin a dedicated 5-phase / ~6-session campaign for `feature-android-hardware-firmware-detection`.
4. **Option C (harness.json unblock):** resolve `.planning/proposals/citadel-protect-files-learn-exception.md` (review, approve, land). Then adopt the 4 candidate rules. Small session.
5. **CRITICAL dispatch discipline if any future Wave is attempted (CLAUDE.md Rule #23 — refined by Wave-3 evidence):** `git checkout -b feat/…` BEFORE writes is NECESSARY but NOT SUFFICIENT. The durable fix is `git worktree add .worktrees/stream-{name} -b feat/stream-{name}-{date}` and operating IN that worktree path — β did this proactively and had zero cross-sweep; α did it mid-session after two sweeps and recovered cleanly; γ stayed in the main checkout and absorbed two sweeps. Fleet harness should adopt this as the default isolation mode.

**Active streams this session:** none at handoff (3 worktrees removed, 3 branches deleted post-merge).

**Continuation-state checkpoint refs:**
- checkpoint-wave3: `d868cb6` is the post-Wave-3 baseline (18 linear commits atop `c954039`). Rollback to `c954039` for full session revert. Sub-rollback per stream:
  - α only: `git revert 83e31c8..d868cb6` (8 commits)
  - β only: `git revert 72ec063..90c0dc6` (4 commits)
  - γ only: `git revert e1f94c3..e241571` (6 commits; note the directory-move commit `2db769b` may need `--mainline 1`)

**Blocking issues:** none.

**Reset instructions:** if next-session work fails, `git checkout clean-history && git reset --hard d868cb6` to the post-Wave-3 baseline (18 commits preserved). `git reset --hard c954039` drops all of Wave 3 (last resort).

**Operator action REQUIRED on any existing deployment upgrading through this campaign:** add `POSTGRES_PASSWORD=wairz` + `FIRMAE_DB_PASSWORD=firmae` to `.env` (matches running `pgdata`). Without these, `docker compose up` fails with the intended `:?required` message — this is the new safe default for fresh clones (they must pick real strong values) but is a one-time migration step for existing `.env` files.

<!-- session-end: 2026-04-19T session 435cb5c2 -->
<!-- session-end: 2026-04-19T session 198243b8 (Wave 3 — 18 commits, 5+ intakes, HEAD=d868cb6) -->

<!-- session-end: 2026-04-19T19:18:15.812Z -->
