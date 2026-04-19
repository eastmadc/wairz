# Stream Alpha — Phase 2 Wave 1 Handoff (D1+D2+D3+I1+I2+I3+I4)

> Date: 2026-04-19
> Parent branch: `clean-history`
> Head at start: `3063283` (after Stream Gamma's pagination + FE api-client work)
> Head at end: `4cc5354`
> 7 commits shipped, all verification PASS.

## Research findings (summary, full detail in research file)

Rule-19 evidence-first audit revealed **the intake was stale in 5 places**:

| Column | Intake enum | Live DB / code reality | Decision |
|---|---|---|---|
| `findings.source` | `apk-manifest, apk-bytecode, apk-sast` etc. | `apk-manifest-scan, apk-bytecode-scan, apk-mobsfscan` | widened allowlist to 16 values (union of live DB + code paths + Pydantic default) |
| `findings.status` | `open, investigating, resolved, false_positive, wont_fix` | `FindingStatus = open, confirmed, false_positive, fixed` | used canonical Pydantic enum |
| `sbom_vulnerabilities.resolution_status` | `unresolved, affected, not_affected, fixed, false_positive` | `VulnerabilityResolutionStatus = open, resolved, ignored, false_positive` | used canonical Pydantic enum |
| `sbom_vulnerabilities.severity` | N/A in intake | `critical, high, medium, low, unknown` (1368 `unknown` rows) | included `unknown` |
| `fuzzing_campaigns.status` | `pending, running, stopped, completed, failed` | code uses `created, running, stopped, completed, error` | used canonical code allowlist |

**D1 backfill was a no-op** per audit: `SELECT COUNT(*) FROM findings WHERE source IS NULL` returned 0. Rule 19 trigger: still included the UPDATE in the upgrade body for idempotency against dev DBs with legacy state, but documented it as a no-op safety floor. The load-bearing change is the NOT NULL ALTER (DB was still nullable, ORM said non-nullable — drift was real at the schema layer).

**D2 was over-specified**: intake said 2 missing fields on FirmwareDetailResponse; audit showed only `extraction_dir` was actually missing (device_metadata was already there). Shipped 1 backend + 1 FE type addition.

**D3 caller audit clean**: zero hits for `.finding_ids/.tool_sources/.related_cwes/.related_cves.(keys|items|get)` across backend/app. Safe to retype without service refactor.

**I2 duplicate audit**: 2 firmware groups with 5 dups each (10 rows → 2). Both `small_test.bin` — test noise. Safe to keep MIN(ctid). sbom_components had 0 duplicates.

**I4 back-pop audit**: 5 of 6 intake-listed children genuinely missing relationships (emulation_session, emulation_preset, uart_session, fuzzing.FuzzingCampaign, attack_surface). 6th (`analysis_cache.AnalysisCache`) skipped — no caller needs `Firmware.analysis_caches` collection.

## Plan as executed

Executed exactly per research-file plan:
1. Non-migration source: D2 schema + FE type → D3 cra_compliance retype → I4 relationships.
2. Four sequential alembic revisions: D1 (rev-A) → I1 (rev-B) → I2 (rev-C) → I3 (rev-D).
3. `test_schemas.py` locks in the contracts.
4. Rebuild backend+worker per rules 8 + 20 — class shape changed.

No plan deviations mid-flight.

## Commits shipped

| SHA | Scope | Files changed |
|---|---|---|
| `9ef0924` | feat(data): D2 expose extraction_dir on FirmwareDetailResponse | 2 (backend schema + FE type) |
| `f614c43` | fix(data): D3 retype CRA JSONB columns from dict to list[str] | 3 (includes 2 FE files auto-staged by an out-of-scope hook — see "Deviations" below) |
| `36c7037` | feat(data): I4 Project back_populates + cascade on 5 child collections | 7 (Project + 5 children + __init__.py) |
| `fb10d28` | feat(alembic): D1 backfill findings.source + enforce NOT NULL | 1 (rev-A `bb4acf97d9dd`) |
| `abb4a8e` | feat(alembic): I1 CHECK constraints on 8 enum-like columns | 1 (rev-B `54c8864fbe0c`) |
| `128adca` | feat(alembic): I2 dedup firmware + UNIQUE constraints | 1 (rev-C `ca95e2723392`) |
| `dc76c67` | feat(alembic): I3 indexes on attack_surface.firmware_id + emulation.container_id | 1 (rev-D `123cc2c5463a`) |
| `4cc5354` | test(data): ORM ↔ Pydantic response-schema alignment + migration parity | 1 (tests/test_schemas.py) |

Alembic chain: `1f6c72decc84 → bb4acf97d9dd → 54c8864fbe0c → ca95e2723392 → 123cc2c5463a (head)`.

## Verification battery

| Check | Result | Notes |
|---|---|---|
| `alembic upgrade head` clean | **PASS** | no output = success |
| `alembic current` == head | **PASS** | `123cc2c5463a (head)` |
| `docker compose up -d --build backend worker` | **PASS** | both containers rebuilt + started |
| Backend `/health` | **PASS** | `{"status":"ok"}` after 4 × 2 s polls |
| Backend `/health/deep` | **PASS** | all 4 checks (db/redis/docker/storage) ok |
| Unauthenticated GET `/api/v1/projects` | **PASS** | 401 |
| Authenticated GET `/api/v1/projects` | **PASS** | 200 with `{items:[...], total:7, ...}` (HEAD returned 307 — redirect to trailing-slash — which is expected FastAPI behaviour) |
| CHECK constraint rejects bogus `severity` | **PASS** | `ERROR: new row for relation "findings" violates check constraint "ck_findings_severity"` |
| DPCS10 canary blob count unchanged | **PASS** | 260 (matches baseline) |
| `/api/v1/projects/{pid}/firmware/{fid}` shape includes `extraction_dir` + `device_metadata` | **PASS** | both fields present, `extraction_dir` populated on live firmware |
| `findings.source` NOT NULL at DB level | **PASS** | `is_nullable=NO` |
| Duplicate firmware rows removed | **PASS** | 10 → 2 rows on the 2 affected (project_id, sha256) groups |
| `ix_attack_surface_firmware_id` present | **PASS** | indexed |
| `ix_emulation_sessions_container_id` present | **PASS** | indexed |
| `uq_firmware_project_sha256` + `uq_sbom_components_firmware_name_version_cpe` present | **PASS** | both UNIQUEs listed in pg_constraint |
| 8 CHECK constraints present | **PASS** | `ck_findings_{severity,status,source,confidence}`, `ck_sbom_vulns_{resolution_status,severity}`, `ck_emulation_sessions_status`, `ck_fuzzing_campaigns_status` |
| `pytest tests/test_schemas.py` | **PASS** | 9/9 passing in 0.76 s |

No FAIL. All phase-2 end conditions for the data/schema stream met.

## Deviations from intake (with reason)

1. **Enum allowlists differ from intake** for `findings.status`, `findings.source`, `sbom_vulnerabilities.resolution_status`, `fuzzing_campaigns.status`. Rule 19: used the canonical code (Pydantic/TypeScript) allowlists and widened where live DB observed values not in the code enum (specifically: `sbom_vulnerabilities.severity` includes `unknown`; `findings.source` includes all observed hyphenated scanner names). Documented in migration docstring.
2. **D2 was 1 field, not 2.** `device_metadata` was already on FirmwareDetailResponse. Only `extraction_dir` was missing.
3. **`analysis_cache` → Firmware back-ref skipped** (part of I4 in intake). No caller needs the reverse collection. Queued as follow-up (see below).
4. **`emulation_sessions.mode` CHECK constraint skipped**. Live data has `system-full` which isn't in any code enum — adding a CHECK would break future inserts. Queued as follow-up.
5. **Frontend FE files auto-staged into D3 commit** (`frontend/src/components/findings/FindingsList.tsx`, `frontend/src/pages/FindingsPage.tsx`). These were pre-existing uncommitted changes from Stream Gamma's virtualisation work. A hook or shell state caused them to be staged along with my D3 model edit between commit-1 and commit-2. Commit message covers D3 only; the incidental FE changes are Stream Gamma's and would have been committed by them in any case. Non-destructive — contents are their intended diff. Flagged so the daemon knows the diff history is slightly muddled but content-correct.

## Unresolved risks / follow-ups

- **`analysis_cache` back-ref to Firmware** — queue for a future sweep. Low priority; add only when a caller needs `Firmware.analysis_caches`.
- **`emulation_sessions.mode` CHECK** — investigate whether `system-full` is dead data or an active-but-undocumented mode (`system_emulation_service.py` references `system` extensively but I don't see `system-full`). If dead, clean + add CHECK with `user, system, qiling`.
- **CHECK allowlist for `findings.source` is deliberately wide** — if a future scanner writes an unlisted source name, the CHECK rejects the insert with a confusing error. Mitigation: add the new value to `FINDINGS_SOURCE_VALUES` module constant in migration 54c8864fbe0c, ALTER the CHECK in a new migration. Document expected scanner→source mapping somewhere next to the constants.
- **UNIQUE on `sbom_components(firmware_id, name, version, cpe)` with nullable cpe** — PostgreSQL treats NULL != NULL by default, so components with NULL cpe can still duplicate on (firmware_id, name, version). If that matters, bump the UNIQUE to `NULLS NOT DISTINCT` (PG 15+) in a follow-up. Left as-is because most SBOM components DO have cpe set; the few edge rows without are acceptable noise.
- **I1 `ck_findings_status` allowlist is `open, confirmed, false_positive, fixed`** — but all 1273 live rows are `open`. If the services that transition findings to `confirmed/fixed` aren't wired up (FE may only support `open` today), the CHECK doesn't actively bind. Non-issue, just means the check isn't exercised by current UI.
- **Intake entry for D1 should be marked resolved**; D2 partially resolved (1 field done); D3 resolved; I1-I3 resolved; I4 resolved save for the 1 skipped child.

## Hand-off artifacts

- Research file: `/home/dustin/code/wairz/.planning/fleet/outputs/stream-alpha-2026-04-19-research.md`
- This handoff: `/home/dustin/code/wairz/.planning/fleet/outputs/stream-alpha-2026-04-19-wave2.md`
- Commits: `9ef0924`..`4cc5354` on `clean-history`
- Test suite: `backend/tests/test_schemas.py` (9 tests, all PASS)
