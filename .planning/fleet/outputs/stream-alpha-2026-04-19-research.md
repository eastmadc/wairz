# Stream Alpha — Phase 2 Wave 1 Research & Plan

> Scope: D1 + D2 + D3 (schema drift) + I1 + I2 + I3 + I4 (constraints & back-pop).
> Stream Alpha owns: `backend/app/models/`, `backend/app/schemas/firmware.py`, alembic revisions, `backend/tests/test_schemas.py`, and a tiny `frontend/src/types/index.ts` addition.

## Evidence (Rule 19 — measure before migrate)

### D1: `findings.source` NULL audit
- `SELECT COUNT(*) FROM findings WHERE source IS NULL` → **0** rows. Backfill is a no-op UPDATE; still include it in the revision as a safety floor for future NULL insertions before the NOT NULL constraint is applied.
- DB still reports `is_nullable=YES` for `findings.source` despite ORM declaring non-nullable. Drift is real at the schema layer; ALTER to NOT NULL remains required.
- `column_default` already `'manual'::character varying` — no server_default change required.

### D1: Finding-source live enum audit (8 distinct values in DB)
| source | count |
|---|---|
| `yara_scan` | 470 |
| `apk-mobsfscan` | 301 |
| `apk-manifest-scan` | 297 |
| `security_audit` | 101 |
| `hardware_firmware_graph` | 56 |
| `attack_surface` | 33 |
| `sbom_scan` | 9 |
| `apk-bytecode-scan` | 6 |

Intake allowlist (line 70) included: `manual, security_audit, yara_scan, vulhunt_scan, attack_surface, apk-manifest, apk-bytecode, apk-sast, clamav, virustotal, abusech, cwe_checker` — **none of the hyphenated `apk-*-scan` names match** the intake's dashed names. The intake is stale.

Code-path audit (`grep source=\"...\"` across backend/app): additional source values that the code CAN write but DB has not yet observed:
- `manual` — `FindingCreate` default
- `cwe_checker` — `ai/tools/cwe_checker.py:237`
- `uefi_scan` — mentioned in `routers/security_audit.py` docstring
- `clamav_scan`, `vt_scan`, `abusech_scan` — mentioned in `routers/security_audit.py` docstrings
- `fuzzing` — mentioned in `ai/system_prompt.py:142` and `ai/tools/fuzzing.py:902`

**Decision (Rule 19 / widen allowlist to match reality):** the CHECK constraint allowlist for `findings.source` will be the union of observed DB values + code-path values + default. Any doubt → include, because the failure mode of an over-tight allowlist is worse (500s on a scanner that writes a valid-looking source) than a too-loose one.

Final `findings.source` allowlist: `manual, security_audit, yara_scan, attack_surface, sbom_scan, hardware_firmware_graph, apk-manifest-scan, apk-bytecode-scan, apk-mobsfscan, cwe_checker, uefi_scan, clamav_scan, vt_scan, abusech_scan, fuzzing, fuzzing_scan`.

### D1: Finding other enums (all clean)
- `severity`: `medium(387), info(19), critical(47), high(691), low(129)` — matches intake.
- `status`: only `open(1273)`. But Python schema (`backend/app/schemas/finding.py:22`) defines `FindingStatus = open|confirmed|false_positive|fixed`. Intake proposed `open|investigating|resolved|false_positive|wont_fix` — DIFFERENT from schema. **Decision: use the schema's allowlist (canonical code), not the intake's.**
- `confidence`: `NULL(970), high(181), medium(121), low(1)` — matches intake (nullable + 3 values).

### D1: Other live enum audits
- `sbom_vulnerabilities.resolution_status`: only `open(364857)`. Pydantic `VulnerabilityResolutionStatus = open|resolved|ignored|false_positive` (`backend/app/schemas/sbom.py:8`). Intake proposed `unresolved|affected|not_affected|fixed|false_positive` — DIFFERENT from schema. **Decision: use the schema allowlist (canonical code), not the intake.**
- `sbom_vulnerabilities.severity`: `medium(261516), high(96356), low(5041), critical(576), unknown(1368)`. `unknown` is not in Finding.severity enum but is used for unscored CVEs. Allowlist must include `unknown`.
- `emulation_sessions.mode`: `system-full(1), system(1)` (only ones present). Frontend `EmulationMode = user|system|qiling`. System-full is undocumented. **Decision: don't CHECK mode yet** — too many unmapped values and no hard requirement in intake. Omit this constraint, note as follow-up.
- `emulation_sessions.status`: `error(1), stopped(1)`. ORM default `created`. Full code set: `created, starting, running, stopping, stopped, error` (matches frontend type). Intake proposed `starting|running|stopped|error` — missing `created` and `stopping`. **Decision: use code allowlist.**
- `fuzzing_campaigns.status`: 0 rows. Code default `created`. Frontend type: `created|running|stopped|completed|error`. Intake said `pending|running|stopped|completed|failed` — different. **Decision: use frontend/code allowlist.**

### D2: FirmwareDetailResponse consumers
- Backend consumers (9 hits): `routers/firmware.py:14, 89, 97, 109, 139, 307, 340, 461, 475` — all use `response_model=FirmwareDetailResponse` or list variant.
- Frontend consumers: 10 files use `FirmwareDetail` type (`types/index.ts:67`).
- `FirmwareDetailResponse` already has `device_metadata: dict | None` at line 55, and `extracted_path: str | None` at line 48. It is MISSING `extraction_dir` only.
- `FirmwareDetail` in `frontend/src/types/index.ts:67-82` already has `extracted_path` and `device_metadata`. MISSING `extraction_dir`.
- **Net work for D2: one backend field (`extraction_dir`), one frontend field.** Intake mistakenly listed 2 missing — was actually 1.

### D3: CRA JSONB `dict→list[str]` caller audit
- `grep -rnE "(finding_ids|tool_sources|related_cwes|related_cves)\.(keys|items|get)\(" backend/app` — **0 hits.**
- Safe to retype without service changes.

### I2: Duplicate row audit
- `firmware (project_id, sha256)`: 2 groups with 5 duplicate rows each (both `small_test.bin` uploads, project `00815038-cb0f-4642-b2bf-2f176fd807f7`). Clearly test noise — safe to dedup (keep oldest per (project_id, sha256)).
- `sbom_components (firmware_id, name, version, cpe)`: 0 duplicates. Clean.

### I3: Missing indexes verified
- `attack_surface_entries`: only has composite `(project_id, firmware_id, score DESC)`; no standalone `firmware_id` index. Confirmed.
- `emulation_sessions.container_id`: no index. Confirmed.
- `firmware.sha256`: has `ix_firmware_sha256` (non-unique index), no unique constraint. Confirmed.

### I4: Relationship gap audit (6 child models → Project)
Direct `grep` of each child model for `project: Mapped["Project"]`:
- `emulation_session.py` — missing (no relationship declared in model)
- `emulation_preset.py` — missing
- `uart_session.py` — missing
- `fuzzing.py` (FuzzingCampaign) — missing
- `attack_surface.py` (AttackSurfaceEntry) — missing
- `analysis_cache.py` — no project FK (only firmware FK); intake's "back-ref to Firmware" item applies but is low value (Firmware has no `analysis_caches` collection need). Mark as follow-up, skip this one.

Project-side (`backend/app/models/project.py`): has `firmware, conversations, findings, documents, reviews` relationships. Missing: `emulation_sessions, emulation_presets, uart_sessions, fuzzing_campaigns, attack_surface_entries`.

### Alembic chain state
- Current head: `1f6c72decc84` (widen_analysis_cache_operation_to_512).
- DB current rev: `1f6c72decc84`.
- New revisions will chain from this head.

## Plan

Rule references: **4** (Pydantic↔ORM), **8** (rebuild backend+worker together), **17** (silent-CLI canary for alembic), **19** (evidence first — applied above), **20** (class-shape change requires restart), **22** (multi-file edits: grep first, typecheck every 1–2 edits).

### Non-migration source changes (commit once, before migrations)

1. **D2** — add `extraction_dir: str | None = None` to `FirmwareDetailResponse` in `backend/app/schemas/firmware.py`. Add `extraction_dir?: string | null` to `FirmwareDetail` in `frontend/src/types/index.ts`.
2. **D3** — retype 4 JSONB columns `dict → list[str]` in `backend/app/models/cra_compliance.py`. No migration needed (server_default already `[]`).
3. **I4** — add 5 `relationship()` back-pop pairs:
   - On `Project`: 5 new `Mapped[list[...]] = relationship(back_populates=..., cascade="all, delete-orphan")`.
   - On each child model: `project: Mapped["Project"] = relationship(back_populates=...)`.

### Alembic revisions (4 new, each a single PR commit)

Ordering: **D1 first** (backfill + NOT NULL on `source`); then **I1 CHECKs** (need D1's NOT NULL to exist); then **I2 UNIQUEs** (independent; needs pre-dedup); then **I3 indexes** (independent). Fresh revision per commit so a revert drops a single concern.

1. **rev-A: `backfill_and_enforce_findings_source_not_null`**
   - `UPDATE findings SET source='manual' WHERE source IS NULL` (no-op per audit but safety floor).
   - `ALTER TABLE findings ALTER COLUMN source SET NOT NULL`.
   - Downgrade: `ALTER ... DROP NOT NULL` (keep server_default).
2. **rev-B: `add_enum_check_constraints`**
   - 7 CHECKs using the allowlists determined above:
     - `ck_findings_severity`
     - `ck_findings_status`
     - `ck_findings_source` (with the 16-value union allowlist)
     - `ck_findings_confidence` (nullable + 3 values)
     - `ck_sbom_vulns_resolution_status` (4 values)
     - `ck_sbom_vulns_severity` (5 values including `unknown`)
     - `ck_emulation_sessions_status` (6 values)
     - `ck_fuzzing_campaigns_status` (5 values)
   - Downgrade: DROP each constraint.
3. **rev-C: `dedup_firmware_and_add_unique_constraints`**
   - Pre-dedup SQL: keep min(ctid) per (project_id, sha256) for `firmware` table (10 dup rows → 2 unique).
   - `uq_firmware_project_sha256` on firmware(project_id, sha256).
   - `uq_sbom_components_firmware_name_version_cpe` on sbom_components(firmware_id, name, version, cpe).
   - Downgrade: drop both constraints (do NOT restore dups).
4. **rev-D: `add_missing_indexes_attack_surface_emulation`**
   - `ix_attack_surface_firmware_id` on attack_surface_entries(firmware_id).
   - `ix_emulation_sessions_container_id` on emulation_sessions(container_id).
   - Downgrade: drop each index.

### Test (new)

`backend/tests/test_schemas.py` — ORM↔Pydantic alignment: iterate each `(model_cls, schema_cls)` pair and assert `schema.fields <= orm.columns ∪ {computed fields}`, printing dropped-from-response fields as notes (not failures).

### Rebuild + verify

Per rule 8 + 20: at end of implement, `docker compose up -d --build backend worker`. Class shape changes in models + schemas mean restart-only is insufficient.

## Execution Order (sequential, single worktree)

1. Research file written (this document).
2. Commit chunk 1: D2 schema + FE type addition.
3. Commit chunk 2: D3 retype of cra_compliance.py.
4. Commit chunk 3: I4 back-populates + cascade on 5 child models + Project.
5. Commit chunk 4: rev-A alembic (D1 NOT NULL).
6. Commit chunk 5: rev-B alembic (I1 CHECKs).
7. Commit chunk 6: rev-C alembic (I2 UNIQUEs + dedup).
8. Commit chunk 7: rev-D alembic (I3 indexes).
9. Commit chunk 8: `test_schemas.py` new file.
10. Rebuild backend+worker, run verification battery, write wave2 handoff.

## Deviations from intake (acknowledged)

- Intake's `status` allowlists (findings, resolution_status, fuzzing_campaigns, emulation_sessions) disagree with current Pydantic/TypeScript enums. Using code enums as canonical per Rule 19. Any future change to these enums must be done in code first, then the CHECK constraint updated, to maintain alignment.
- Intake's `findings.source` allowlist uses `apk-manifest/apk-bytecode/apk-sast` while code uses `apk-manifest-scan/apk-bytecode-scan/apk-mobsfscan`. Using code values.
- Intake's D2 claimed 2 missing fields; only `extraction_dir` is actually missing (device_metadata already present).
- Intake's I4 includes `analysis_cache` → `Firmware` back-ref. Skipping — no caller needs `Firmware.analysis_caches` collection; add only when a real need materialises. Noted in handoff as follow-up.
- Intake's CHECK on `emulation_sessions.mode` skipped — `system-full` observed in data is not covered by any code-path enum; too many unknowns for a safe allowlist. Noted as follow-up.
