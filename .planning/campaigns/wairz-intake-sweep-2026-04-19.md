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

**Current phase:** 1 → **COMPLETE** — advance to Phase 2 (Data / schema) in next daemon-chained session.
**Current sub-step:** Final commit pending (health-deep regression fix + campaign/daemon artefacts).

**Session history:**
- 2026-04-19 (session 69f004fe): campaign created. Wave 1 shipped `ab09e1c` (safe_extract) + `de3f6bd` (B.1.a/b/c auth-hardening). All 8 Wave-1 verification items PASS: no-key→401, good-key→200, /health→200, /health/deep→200, DPCS10 canary=260, slowapi 100/min default triggers 429 at 101st request (99×200 + 11×429 observed), rate-limit decorators at firmware.py:76 "5/min" + events.py:35 "10/min", streaming upload-size guard live at firmware_service.py:260-284. Backend + worker rebuilt with slowapi baked in. Wave 2 dispatched (Stream B fuzzing shell injection + Stream D docker-socket-proxy).

**Procedural note:** checkpoint stash was created AFTER the campaign file write — campaign file + daemon.json ended up inside stash@{0}. Recovered via `git stash pop` once Stream C notified. Future phases: stash BEFORE creating untracked campaign artefacts.

## Continuation State

**Phase 1:** COMPLETE as of 29dba35 (session 69f004fe). Full end-condition battery PASS. 5 commits shipped: ab09e1c (safe_extract), de3f6bd (auth B.1.a/b/c), e443def (fuzzing shell-inj), bac49ea (docker-socket-proxy), 29dba35 (health-fix + campaign artefacts).

**Next session (Phase 2 — Data / schema) pickup order:**
1. Read this campaign file + `.planning/knowledge/handoff-2026-04-19-session-698549d4-end.md`.
2. Phase 2 scope = 3 streams, fleet-parallel possible:
   - `.planning/intake/data-schema-drift-findings-firmware-cra.md` — column/enum drift between model and migrations.
   - `.planning/intake/data-constraints-and-backpop.md` — CHECK + UNIQUE constraints + SQLAlchemy `back_populates` audit.
   - `.planning/intake/data-pagination-list-endpoints.md` — wrap sbom/attack_surface/security_audit list endpoints with limit/offset/total metadata.
3. Per-stream dispatch prompt template: see Phase 1 streams A/B/C/D as the shape — full context injection (CLAUDE.md, predecessor handoff), intake file reference, verification battery with file:line targets, HANDOFF output to `.planning/fleet/outputs/stream-*-2026-04-19.md`.
4. Phase 2 end-condition table above already lists the 3 required checks. Rebuild backend+worker once after the 3 streams merge.
5. Mark Phase 2 complete, advance to Phase 3 (Infra).

**Active streams this session:** none at handoff.

**Continuation-state checkpoint refs:**
- checkpoint-phase-1: stash@{0} dropped after successful completion — no rollback artefact needed.
- checkpoint-phase-2: (next session should stash BEFORE writing any campaign updates; Phase 1 procedural note preserved in Session history above.)

**Blocking issues:** none.

**Reset instructions:** if a Phase 2 stream fails hard, `git checkout clean-history && git reset --hard 29dba35` rolls back to post-Phase-1. Individual Phase 2 commits can be reverted in reverse order if Phase 2 as a whole fails.
