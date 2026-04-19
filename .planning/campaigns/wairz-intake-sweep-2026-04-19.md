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

**Current phase:** 2 COMPLETE · 3 (1/3) · 4 (2/3) · 6 (1/3) — cross-phase dispatch overrode the phase-serial plan. Remaining 11 intake items can clear in 2-3 more sessions.
**Current sub-step:** session 435cb5c2 end-of-session (Wave 1+2 landed, artefacts pending commit).

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

**Wave-level anti-patterns observed 3× this session (see `.planning/knowledge/wairz-intake-sweep-wave12-antipatterns.md`):** `isolation: "worktree"` + `worktreePath: ok` sentinel in Fleet dispatch does NOT provide working-tree isolation. Agents share the on-disk checkout; concurrent commits race on shared files. Wave 1 Alpha+Gamma, Wave 2 Delta+Zeta, Wave 2 Epsilon+Zeta all showed cross-stream file sweeps. Content was always correct (no lost work) but commit attribution was scrambled. Strict `git add <paths>` discipline alone is insufficient — harness-level mitigation (true worktree checkouts OR per-stream `git checkout -b`) is required for future waves.

**Post-session verification (HEAD = 06b80b8):**
- /health 200 · /ready 200 · /health/deep all-4-ok · /metrics 200 (Prom text)
- Auth matrix: noauth=401 · auth-GET=200
- Alembic head `123cc2c5463a` · DPCS10 canary = 260 · MCP tools = 172 · arq cron jobs = 3 · migrator Exited(0)
- Acceptance grep: 0 unbounded `scalars().all()` in routers

## Continuation State

**Phases status after 435cb5c2:**
- Phase 1: COMPLETE (69f004fe, 5 commits)
- Phase 2: **COMPLETE** (435cb5c2, 13 commits — schema-drift, constraints, pagination)
- Phase 3: **1/3** (435cb5c2 Delta — cleanup-migration-observability). Remaining: `infra-secrets-and-auth-defaults` (partial), `infra-volumes-quotas-and-backup`.
- Phase 4: **2/3** (435cb5c2 Gamma + Zeta — code-split, virtualize, api-client hardening). Remaining: `frontend-store-isolation-and-types`.
- Phase 5: 0/3 (serial refactor — next dedicated session). Items: cache-module-extraction, private-api + circular-imports, god-class decomposition.
- Phase 6: **1/3** (435cb5c2 Epsilon — LATTE taint). Remaining: `apk-scan-deep-linking`, `feature-android-hardware-firmware-detection`.
- Phase 7: 0 (maintenance sweep at campaign end).

**Next session pickup order:**
1. Read this campaign file + `.planning/knowledge/handoff-2026-04-19-session-435cb5c2-end.md` + `.planning/knowledge/wairz-intake-sweep-wave12-antipatterns.md` + `.planning/prompts/next-session-wave3-2026-04-XX.md` (the ready-to-paste Wave 3 starter prompt).
2. **Wave 3 recommended plan (Option B, deep-researched 2026-04-19 post-Wave-2):** 3 parallel streams per-branch-isolated, expected yield 5+ intakes/session.
   - **Stream α** — Infra bundled (SERIAL within, both touch docker-compose.yml): `infra-secrets-and-auth-defaults` finish-partial + `infra-volumes-quotas-and-backup`. Build storage-quota + pg_dump cron on top of Delta's arq cron. DO NOT regress docker-socket-proxy from Phase 1.
   - **Stream β** — `frontend-store-isolation-and-types` (S1 store reset race + S2 project-id guard + S3 DeviceAcquisitionPage `as any` removal). ~400 LOC surface; tsc `-b --force` only.
   - **Stream γ** — Phase 7 maintenance sweep (batched): apk-scan-deep-linking Rule-19 verify (body says completed, YAML header pending; confirm & mark), 5 stale security-* intake close-outs, 4 harness.json quality rules (bypass protect-files hook carefully — ask Dustin first), frontend healthcheck → /ready, fix wairz-mcp --list-tools CLI.
3. **Alternative dispatch:**
   - **Phase 5 serial session** (dedicated): cache-module-extraction → private-api + circular-imports (8+ inline `from app.services import X` workarounds; 70 cross-imports baseline) → god-class decomposition (8 services > 1000 LOC; target <800). Ordering matters; do NOT parallelise.
   - **Phase 6 HW-firmware spin-out**: `feature-android-hardware-firmware-detection` is a 5-phase / ~6-session campaign. Recommend creating `.planning/campaigns/android-hw-firmware.md` and treating as its own work stream.
4. **CRITICAL dispatch discipline (Wave-2 anti-pattern #1):** every Wave 3 sub-agent MUST run `git checkout -b feat/stream-{name}-2026-04-XX` FIRST, before any file write. `isolation: "worktree"` + `worktreePath: "ok"` does NOT isolate working trees (3 cross-stream sweeps in 6 streams = 50% hit rate observed this session). Orchestrator merges branches sequentially after all streams complete.
5. End-condition batteries from campaign table remain canonical. Global `/health/deep` + DPCS10 canary + auth matrix in every stream's verification regardless of scope.
6. Remaining inventory audit: 8-10 actionable items depending on apk-scan Rule-19 outcome; quick-wins Q4 is Phase-5-blocked; next-session-plan.md is stale documentation, not an action item.

**Active streams this session:** none at handoff.

**Continuation-state checkpoint refs:**
- checkpoint-wave12: `06b80b8` is the post-Wave-12 baseline. Rollback to `abe15e0` for full session revert (28 commits). Individual commits can be `git revert`ed in reverse dependency order (alembic migrations last — reverse-order required for rev chain).

**Blocking issues:** none.

**Reset instructions:** if next-session work fails, `git checkout clean-history && git reset --hard 06b80b8` to the post-Wave-12 baseline, OR `git reset --hard abe15e0` to pre-session baseline (drops all 28 Wave 1+2 commits — last resort).

<!-- session-end: 2026-04-19T session 435cb5c2 -->
