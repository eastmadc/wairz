# Session Handoff — 2026-04-19 (session 93a4948d, Option A)

> Outgoing: Opus 4.7 (1M context), effort=max
> Branch: `clean-history` (13 new commits, post-session HEAD = `2a27175`)
> Baseline HEAD at session start: `3977a9c`
> Predecessor handoff: `.planning/knowledge/handoff-2026-04-19-session-a90838f6-end.md`
> Campaign: `wairz-intake-sweep-2026-04-19` — Phases 1–4 + 6–7 **COMPLETE**; Phase 5 **2/3**; one sub-item remaining (god-class decomposition).
> Daemon: ~$3 of $40 consumed this session (cumulative ~$5 since daemon start).
> Cross-repo: none (wairz-only work this session).

---

## Starter prompt for the next session (paste as first message)

```
Resume campaign wairz-intake-sweep-2026-04-19. Daemon running.

Session 93a4948d executed Option A and closed 2 of 3 Phase-5 sub-items:
  - backend-cache-module-extraction-and-ttl: FULL (10 call sites migrated —
    7 from intake + 3 scope-widened — plus cron + 15 tests)
  - backend-private-api-and-circular-imports: P1+P2 of 3 (kernel cycle
    broken; _scan_* promoted via run_scan_subset public API). P3 systemic
    function-local audit DEFERRED — non-blocking.
  - feature-android-hardware-firmware-detection: CLOSED via Rule-19 audit
    (already shipped across 20+ commits; intake status pending → completed
    with evidence matrix).

Post-session HEAD = 2a27175. Function-local from-app.services count
40 → 37. MCP tools still 172. arq cron_jobs 6 → 7. alembic head
unchanged at 123cc2c5463a.

Read in order:
  1. .planning/campaigns/wairz-intake-sweep-2026-04-19.md — Active Context +
     Continuation State.
  2. .planning/knowledge/handoff-2026-04-19-session-93a4948d-end.md (this file)
  3. CLAUDE.md Rules 1-25 canonical (unchanged this session).
  4. (Optional) predecessor handoffs a90838f6 + 198243b8 for context.

Current state (verified post-rebuild, 2a27175):
  - All containers healthy (backend + worker + migrator(Exited 0) +
    docker-proxy + postgres + redis + pg-backup; frontend still
    `unhealthy` — known pre-existing IPv6/IPv4 mismatch, not blocking).
  - /health 200, /ready 200, /metrics 200.
  - Auth: noauth=401, X-API-Key=200.
  - Alembic head: 123cc2c5463a.
  - MCP tool count: 172.
  - arq cron jobs: 7 (added cleanup_analysis_cache_job @06:00 UTC).
  - HW firmware blobs (DPCS10+all): 797.
  - .claude/harness.json qualityRules.custom: 21 rules; typecheck.command:
    `npx tsc -b --force` (Rule-17 canary verified bad-TS input flagged).

Remaining work:

  Option A.3 — Phase 5 god-class decomposition (RECOMMENDED; serial,
     dedicated session). Intake: backend-service-decomposition.md —
     ~2 sessions for 5 god-class services (manifest_checks 2589 →
     subpackage; security_audit 1220 → subpackage; sbom 2412; mobsfscan
     1555; emulation 1667). Start with manifest_checks (worst offender,
     easiest split: mixin → composition). Baselines to capture at start:
       wc -l backend/app/services/*.py | sort -rn | head -10
       grep -rn 'from app.services' backend/app/services/ | grep -v __init__ | wc -l
     Invariant test (must pass after every Phase 5 commit):
       docker compose exec -T -e PYTHONPATH=/app -w /app backend \
         /app/.venv/bin/python -c "from app.ai import create_tool_registry; \
         print(len(create_tool_registry().get_anthropic_tools()))"
       # must report 172
     Rule #25 commit discipline: one commit per topic-file extract.
     Rule #8 rebuild ONCE at end of each stream.

  Option E — P3 follow-up (systemic function-local import audit).
     37 function-local `from app.services.*` imports across 13 files.
     Generate dependency graph, identify cycles, propose shared-base
     extractions. Open-ended; intake explicitly notes "cap the scope to
     specific service pairs per PR." Small session.

  Option D (carried from session a90838f6) — Citadel follow-ups.
     - protect-files.js stderr mirror commit d0029b5 fix-gate pattern
     - /learn skill candidate rule-name normalisation (^[a-z0-9-]+$)
     30-min tasks each; only worth doing if you're already in Citadel.

Ask me ONE question: "Proceed with Option A.3 (god-class decomposition
Phase 1 = manifest_checks), Option E (P3 audit), or Option D (Citadel
follow-ups)?" Execute without further interview once confirmed.
```

---

## What shipped this session (13 commits in wairz)

| SHA | Scope |
|---|---|
| `d100595` | feat(services): add `_cache` module + `analysis_cache_retention_days` Setting |
| `5808555` | refactor(ghidra): migrate 3 cache call sites to `_cache` |
| `b5f2432` | refactor(cwe_checker): migrate cache (fixes missing-delete bug) |
| `1b84726` | refactor(jadx): migrate 3 cache call sites |
| `909101c` | refactor(mobsfscan): migrate 2 cache call sites |
| `b5212f0` | refactor(firmware_metadata): migrate firmware-wide cache (NULL key) |
| `b5f3a78` | refactor(apk_scan): migrate manifest+bytecode cache in router + tool |
| `404b9c8` | refactor(component_map): migrate filesystem tool + REST router (**scope-widened**) |
| `1744fad` | refactor(mcp_server): migrate save_code_cleanup (**scope-widened**) |
| `618ee09` | feat(workers): `cleanup_analysis_cache_job` cron (6 → 7) + 15 unit tests |
| `68ecb64` | refactor(services): break kernel_service↔emulation_service cycle |
| `835dd70` | refactor(mobsfscan): hoist `_cache` to module level |
| `2a27175` | refactor(security_audit): promote `_scan_*` via `run_scan_subset` |

### Files touched

```
 backend/app/ai/tools/android_bytecode.py           48 +/-
 backend/app/ai/tools/filesystem.py                 34 +/-
 backend/app/config.py                               7 +
 backend/app/mcp_server.py                          31 +/-
 backend/app/routers/apk_scan.py                    69 +/-
 backend/app/routers/component_map.py               38 +/-
 backend/app/services/_cache.py                    171 +   (NEW)
 backend/app/services/assessment_service.py         13 +/-
 backend/app/services/cwe_checker_service.py        33 +/-
 backend/app/services/emulation_service.py           5 +/-
 backend/app/services/firmware_metadata_service.py  28 +/-
 backend/app/services/ghidra_service.py             55 +/-
 backend/app/services/jadx_service.py               51 +/-
 backend/app/services/kernel_service.py              4 +/-
 backend/app/services/mobsfscan_service.py          43 +/-
 backend/app/services/security_audit_service.py     38 +
 backend/app/workers/arq_worker.py                  36 +/-
 backend/tests/test_cache_module.py                269 +   (NEW)
 18 files changed, 664 insertions(+), 309 deletions(-)
```

Plus (not counted in above): campaign + intake state updates
(`.planning/campaigns/wairz-intake-sweep-2026-04-19.md`,
`.planning/intake/backend-cache-module-extraction-and-ttl.md`,
`.planning/intake/backend-private-api-and-circular-imports.md`,
`.planning/intake/feature-android-hardware-firmware-detection.md`).

## Verification gate for the next session (copy-paste)

```bash
docker compose ps    # backend + worker + migrator(Exited 0) + docker-proxy + postgres + redis + pg-backup all expected
curl -sf -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/health         # 200
curl -sf -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/ready          # 200
curl -sf -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/metrics        # 200
curl -sI http://127.0.0.1:8000/api/v1/projects | head -1                       # HTTP/1.1 401 Unauthorized
curl -sf -o /dev/null -w '%{http_code}\n' -H "X-API-Key: dev-test-key-wairz-b1" http://127.0.0.1:8000/api/v1/projects  # 200
docker compose exec -T -e PYTHONPATH=/app -w /app backend /app/.venv/bin/alembic current | tail -1  # 123cc2c5463a (head)
docker compose exec -T -e PYTHONPATH=/app -w /app backend /app/.venv/bin/python -c "from app.ai import create_tool_registry; print(len(create_tool_registry().get_anthropic_tools()))"  # 172
docker compose exec -T -e PYTHONPATH=/app -w /app worker /app/.venv/bin/python -c "from app.workers.arq_worker import WorkerSettings; print(len(WorkerSettings.cron_jobs))"  # 7  (+1 from last session)
docker compose exec -T -e PYTHONPATH=/app -w /app backend /app/.venv/bin/python -c "from app.services._cache import get_cached, store_cached, exists_cached, invalidate_firmware, cleanup_older_than; print('cache OK')"  # cache OK
docker compose exec -T -e PYTHONPATH=/app -w /app backend /app/.venv/bin/python -c "from app.services.security_audit_service import SCANNERS, run_scan_subset; print(f'scanners={len(SCANNERS)}')"  # scanners=12
python3 -c "import json; d=json.load(open('.claude/harness.json')); assert len(d['qualityRules']['custom']) == 21, f'expect 21 got {len(d[\"qualityRules\"][\"custom\"])}'; assert d['typecheck']['command'] == 'npx tsc -b --force'; print('harness OK')"  # harness OK
echo 'const x: number = "nope"; export default x;' > frontend/src/__canary.ts && (cd frontend && npx tsc -b --force 2>&1 | tail -2); rc=$?; rm -f frontend/src/__canary.ts; echo "Rule-17 canary: expect TS2322 error above"
```

All curls + DB checks must pass. The Rule-17 canary must show `error TS2322: Type 'string' is not assignable to type 'number'.`

## Rollback safety

This session added zero alembic migrations (alembic head unchanged at `123cc2c5463a`). All 13 commits are additive or swap internal plumbing without changing external APIs. The `Settings` class gained one new field (`analysis_cache_retention_days: int = 30`) with a safe default — Rule #20's class-shape caveat applied; handled via the final backend+worker rebuild.

```bash
# Undo this entire session
git -C /home/dustin/code/wairz checkout clean-history && \
  git -C /home/dustin/code/wairz reset --hard 3977a9c

# Undo only the Phase-5 sub-item-2 work (private-api + cycle + mobsfscan hoist)
git -C /home/dustin/code/wairz revert 2a27175 68ecb64 835dd70

# Undo only the cache refactor (keep cycle + private-api fixes)
git -C /home/dustin/code/wairz revert 618ee09 1744fad 404b9c8 b5f3a78 b5212f0 909101c 1b84726 b5f2432 5808555 d100595
# Then rebuild backend+worker and restart.
```

## Open threads (carried + new)

1. **Phase 5 god-class decomposition** (NEW in "open") — the one remaining Phase-5 sub-item. Recommended as the next session's primary. Intake: `backend-service-decomposition.md`. ~2 sessions.

2. **Phase 5 P3 systemic function-local audit** (NEW) — 37 function-local `from app.services.*` imports across 13 files. `backend-private-api-and-circular-imports.md` status = `partial` reflects this deferral. Standalone campaign when prioritised.

3. **Frontend healthcheck `(unhealthy)`** (carried from 198243b8) — pre-existing IPv6/IPv4 mismatch in `wget -qO /dev/null http://localhost:3000/`. Trivial Dockerfile fix (use `127.0.0.1`); not blocking.

4. **`.mex/ROUTER.md` Current Project State drift** (carried from a90838f6) — says "22 learned rules" (now 25); "Not yet built" section lists shipped items. Phase-7 hygiene task.

5. **Citadel UX follow-ups** (carried Option D) — stderr mirror + `/learn` rule-name normalisation. 30-min Citadel tasks.

6. **Citadel f65251c not pushed** (carried from a90838f6). Local-only. No urgency.

7. **pg-backup first-run sanity** (carried) — `ls ./backups/wairz_*.dump` should show ≥1 file 24h after pg-backup start.

## For the incoming Citadel session

Entry points:
- `/archon` — detects daemon running + active campaign, resumes automatically.
- `/do` — manual override.
- `.mex/ROUTER.md` — task-type navigation (NB: Current Project State is stale, see thread #4).
- This handoff + campaign Active Context + Continuation State.

The daemon-chained path: SessionStart hook → detect campaign → resume archon → load campaign Continuation State → present Options A.3 / E / D for user selection → execute.

## Learnings worth extracting via /learn (post-session)

Three patterns discovered this session deserve knowledge-base capture:

1. **Rule-22 scope widening via grep** — intake listed 7 cache call sites; blind-grep found 10 (3 extras: component_map tool + router, mcp_server save_code_cleanup). The extras were genuinely in-scope (same query-and-upsert pattern) but absent from the intake's file manifest. Lesson for next sub-item: always run the full `grep -rn 'TargetSymbol'` before starting, not just the intake's `Files` section.

2. **`exists_cached` as a cache helper** — 2 of 10 migrated sites only needed a presence probe (ghidra's `_is_analysis_complete`, jadx's `_is_decompilation_complete`). Selecting `id` instead of the full JSONB `result` column avoids pulling multi-MB blobs for a boolean. Worth generalising to any "cache exists?" pattern.

3. **Firmware-wide cache entries use `binary_sha256 IS NULL`** — not all cached analyses key off a specific binary. `firmware_metadata`, `component_map` cache whole-firmware state. PostgreSQL treats NULL as distinct in unique indexes, so these coexist with per-binary rows. The helper signature `binary_sha256: str | None = None` cleanly expresses both cases and generates `IS NULL` in the query.

Candidate /learn quality rules:
- `auto-cache-uses-services-cache-module` — flag `from app.models.analysis_cache import AnalysisCache` appearing outside `backend/app/services/_cache.py`, `backend/app/services/export_service.py`, `backend/app/services/import_service.py`, `backend/tests/`
- `auto-no-private-scan-cross-module` — flag `from app.services.security_audit_service import _scan_` appearing outside `security_audit_service.py` and its tests
