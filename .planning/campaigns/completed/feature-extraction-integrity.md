---
slug: feature-extraction-integrity
title: "Extraction Integrity — Systemic Data-Loss Fix Across Unpack + Detection Pipeline"
status: completed
completed: 2026-04-17
created: 2026-04-17
priority: critical
estimated_sessions: 5
intake: .planning/intake/feature-extraction-integrity.md
research_bundle: .planning/research/fleet-wairz-data-loss-audit/
depends_on: feature-hw-firmware-phase2-enrichment
scope:
  - backend/app/workers/
  - backend/app/services/hardware_firmware/
  - backend/app/services/sbom_service.py
  - backend/app/services/yara_service.py
  - backend/app/services/security_audit_service.py
  - backend/app/services/file_service.py
  - backend/app/services/firmware_paths.py
  - backend/app/ai/tools/
  - backend/app/models/firmware.py
  - backend/scripts/
  - CLAUDE.md
  - .claude/harness.json
---

## Direction

**A 4-scout research-fleet (2026-04-17) confirmed systemic data-loss in the Wairz extraction pipeline.** The DPCS10 `md1dsp.img` case is one symptom of:

- **12 silent-drop sites** in the extraction code.
- **13+ downstream consumers** blind to sibling partition dirs.
- **~1,218 undetected blobs** across the existing 10-firmware DB sample (2.5× the current 490-blob corpus).
- **3 firmware rows with zero detected blobs** (pre-detector uploads).
- Every MediaTek parser landed in Phase 2/3 (mtk_preloader, mtk_lk, mediatek_modem, mediatek_wifi, awinic_acf) has **never fired on real data**.

Campaign drives "deeply fix, deeply test, deeply iterate until resolved fully" per user mandate. 5 phases: stop-the-bleeding upstream, `get_detection_roots()` helper + JSONB cache, consumer migration, backfill, observability + regression guard.

## Baseline (recorded 2026-04-17)

- **Backend tests (hw-firmware suite):** 192/192 pass
- **Frontend typecheck:** 0 errors (last verified end of hw-firmware-phase2)
- **HardwareFirmwareBlob row count (DB):** 490 (per scout 3)
- **Live Redis kernel_vulns_index:** populated (10,725 CVEs across 1,603 subsystems)
- **Last merge:** a0dd65e (phase2 enrichment archive)

## Research Bundle

- `.planning/research/fleet-wairz-data-loss-audit/REPORT.md` — synthesis
- `upstream-extraction-gaps.md` — Scout 1 (12 silent-drop sites)
- `downstream-consumer-audit.md` — Scout 2 (13+ affected consumers)
- `live-db-audit.md` — Scout 3 (per-firmware orphan counts)
- `architectural-fix-design.md` — Scout 4 (Option A chosen: helper + JSONB cache)

## Phases

### Phase 1 — Stop the Bleeding (build, medium effort, ~300 LOC)

Upstream extraction fixes; no new helper yet. Pure "don't silently drop data".

Targets:
- `unpack_android.py:429-430, 323-324` — remove 1 MB minimum-size filter.
- `unpack_android.py:457, 476, 483` — stop `os.remove()` after mount failure.
- Add simg2img output verification (size + magic non-zero).
- `unpack.py` / `cleanup_unblob_artifacts` — stop deleting `.unknown` chunks.
- `unpack_android.py:416-418` — preserve scatter-zip version subdir (relocate into rootfs OR leave for Phase 2 helper).
- `unpack_common.py` — recursive nested-archive extraction (`.tar.md5`, nested `.zip`, `.lz4`).

### Phase 2 — `get_detection_roots()` Helper + JSONB Cache (build, high effort, ~250 LOC)

- `backend/app/services/firmware_paths.py` (new) — `get_detection_roots(firmware) -> list[str]`, cached in `firmware.device_metadata["detection_roots"]`.
- `backend/tests/test_firmware_paths.py` (new) — coverage per firmware type.
- `invalidate_detection_roots(firmware)` helper for backfill.

### Phase 3a — Migrate Core Consumers (build, high effort, ~400 LOC diff)

- `hardware_firmware/detector.py` — multi-root walk, dedup by SHA-256.
- `sbom_service.py` — multi-root.
- `yara_service.py` — multi-root.
- `security_audit_service.py` — multi-root + fix `_scan_android_apps` hardcoded paths.
- `file_service.py` — multi-root + fix `_ROOT_DIR_PATTERN`.

### Phase 3b — Migrate MCP + Scanner Consumers (build, high effort, ~400 LOC diff)

- `ai/tools/{filesystem,binary,strings}.py`
- `assessment_service.py` (7 phases)
- `update_mechanism_service.py`, `component_map.py`
- `clamav_service.py`, `virustotal_service.py`, `abusech_service.py`

### Phase 4 — Backfill + Verification (build, medium effort, ~150 LOC)

- `backend/scripts/backfill_detection.py` — re-resolve roots + re-run detector + CVE matcher for every firmware.
- Live run on 10 existing rows.
- Feature ledger recovery report.

### Phase 5 — Observability + Regression Guard (build, low effort, ~200 LOC)

- Per-firmware extraction audit (`device_metadata["detection_audit"]` or new table).
- `/audit` endpoint.
- CLAUDE.md Learned Rule #16.
- Harness quality rule `auto-extraction-roots-no-direct-extracted-path`.
- `grep` check: zero `firmware.extracted_path` outside the helper.

## Phase End Conditions

| Phase | Condition | Check |
|-------|-----------|-------|
| 1 | command_passes | Baseline regression: `pytest tests/test_hardware_firmware_*.py tests/test_firmware_classification.py` still 192+ pass |
| 1 | command_passes | New test: fixture DPCS10-shape scatter → all 21 partition stubs survive extraction (no 1 MB drop, no mount-fail remove) |
| 1 | manual | Live re-upload small DPCS10 fixture, confirm partition images present on disk |
| 2 | file_exists | `backend/app/services/firmware_paths.py` |
| 2 | command_passes | `pytest tests/test_firmware_paths.py` passes |
| 2 | metric_threshold | Helper returns ≥2 roots for Android OTA fixture |
| 3a | command_passes | Integration test: detector re-run on DPCS10 → mtk_preloader parser populates metadata |
| 3a | command_passes | Full hw-firmware regression still 192+ pass |
| 3b | command_passes | MCP tool tests pass (list_directory sees partition dir) |
| 3b | command_passes | Frontend typecheck 0 errors |
| 4 | command_passes | `python scripts/backfill_detection.py --dry-run` produces ≥800 expected new blobs across 10 firmware |
| 4 | metric_threshold | After live backfill: HardwareFirmwareBlob count grew by ≥800 |
| 5 | file_exists | CLAUDE.md contains "Learned rule #16" about detection_roots |
| 5 | command_passes | `grep -rn "firmware\.extracted_path" backend/app/services/ \| grep -v firmware_paths.py` returns 0 |
| 5 | command_passes | Harness quality rule registered in `.claude/harness.json` |

## Active Context

**Phase: 5 — Observability + Regression Guard** (completed)
All five phases landed; campaign archived.

## Feature Ledger

**Phase 1 (72a2049)** — Stop-the-bleeding. Removed 1 MB drop filter, mount-fail cleanup, simg2img verify, preserved scatter-zip version subdir, recursive nested-archive extraction. ~300 LOC.

**Phase 2 (ceade9a)** — `get_detection_roots()` helper + JSONB cache. ~250 LOC. `backend/app/services/firmware_paths.py` + `backend/tests/test_firmware_paths.py`.

**Phase 3a (0d11d07)** — Core consumer migration. Detector, SBOM, YARA, security-audit, file-service multi-root. ~400 LOC diff.

**Phase 3b (bbf92b1)** — MCP + scanner consumer migration. AI tools (filesystem/binary/strings), assessment, update-mechanism, component-map, ClamAV, VirusTotal, abuse.ch. ~400 LOC diff.

**Phase 4 (5f70134)** — Backfill + verification. `backend/scripts/backfill_detection.py` + recovery run across 10 firmware rows. Feature ledger recovery report. ~150 LOC.

**Phase 4 follow-up (84d94ce)** — Multi-archive ZIP fix (RespArray / Avalon live-fire). `get_detection_roots` now rescues shallow-container firmware where unblob picks an inner archive as the unpack target; surfaces sibling `.bin` MCU firmware + `.tar.xz` bundles at the parent level. Recovered RespArray from 0 blobs → 11+.

**Phase 5 (this commit)** — Observability + regression guard. CLAUDE.md Learned Rule #16. Harness quality rule `auto-extraction-roots-no-direct-extracted-path`. Live-detection audit stamp on `device_metadata["detection_audit"]` (roots_count / blobs_detected / files_on_disk / orphan_ratio / last_detection_at / walk_source). `GET /api/v1/projects/{project_id}/firmware/{firmware_id}/audit` endpoint with optional `?recompute=true` orphan preview (max 10 filenames). Pytest `test_no_new_direct_extracted_path_reads` regression guard (scans `services/` + `ai/tools/` for direct reads outside the allowlisted per-binary flows). ~210 LOC.

## Decision Log

**2026-04-17** — **Campaign framing.** User discovered the DPCS10 `md1dsp.img` gap during post-phase-2 live validation. Research-fleet (4 scouts) confirmed systemic scope. Intake file spec'd directly from scout findings + Scout 4's Option A recommendation. Priority raised to critical because it blocks every post-detection feature.

**2026-04-17** — **Option A chosen over B/C/D.** Helper module with JSONB cache, builds on existing `_pick_detection_root` at `unpack.py:52-68`. Avoids Alembic migration complexity (Option B), avoids extraction-layout regression risk (Option C), defers normalized FirmwarePath table (Option D) until concrete need.

**2026-04-17** — **No daemon activation.** Trust level 115+ sessions (Trusted tier). User explicitly wants "deeply iterate until resolved" — executing continuously this session rather than scheduling out.

## Continuation State

checkpoint-phase-1: _(to be written before delegation)_
checkpoint-phase-2: _(pending)_
checkpoint-phase-3a: _(pending)_
checkpoint-phase-3b: _(pending)_
checkpoint-phase-4: _(pending)_
checkpoint-phase-5: _(pending)_

**If context runs low mid-campaign:**
- Campaign state persisted in this file + Continuation State below.
- All scout briefs at `.planning/research/fleet-wairz-data-loss-audit/`.
- Next session: read this file's Active Context, pick up at the noted sub-step.

## Reversibility

**Amber** — multi-phase, ~5 commits expected. Each phase is independently revertable via `git revert`. Recovery baseline: HEAD = a0dd65e.

## Quality Gates

- Direction alignment check after Phase 2 and Phase 4.
- Quality spot-check every phase (largest new/modified file read end-to-end).
- Regression guard every build phase (pytest full hw-firmware suite + typecheck).
- Anti-pattern scan every build phase (no shell interpolation, no transition-all, no confirm/alert, proper async session discipline).
- CLAUDE.md rule added at campaign close (Phase 5 deliverable).
