---
version: 1
id: "41e39acc-764f-4220-8048-0f68280574fc"
status: active
started: "2026-04-17T01:32:19Z"
completed_at: null
direction: "Android hardware firmware detection — modem/TEE/Wi-Fi/GPU/DSP/drivers: detection, parsers, driver graph, CVE matcher, UI + MCP tools"
phase_count: 5
current_phase: 2
branch: null
worktree_status: null
---

# Campaign: Android Hardware Firmware Detection

Status: active
Started: 2026-04-17T01:32:19Z
Direction: Android device images contain 20-40 hardware firmware blobs (modem, TEE, Wi-Fi/BT, GPU, DSPs, touch, NFC, boot chain) currently opaque to Wairz. Add detection, per-format parsers, driver↔firmware graph, three-tier CVE matcher, and dedicated UI + 6 MCP tools. Architected as plugin system so iBoot/IMG4, automotive, IoT, Cisco IOS, Junos slot in later.

## Claimed Scope
- backend/app/services/hardware_firmware/
- backend/app/models/hardware_firmware.py
- backend/app/schemas/hardware_firmware.py
- backend/app/routers/hardware_firmware.py
- backend/app/ai/tools/hardware_firmware.py
- backend/app/ai/__init__.py (tool registration only)
- backend/app/workers/unpack.py (post-extraction hook only)
- backend/app/workers/unpack_android.py (post-extraction hook only)
- backend/app/main.py (router registration only)
- backend/alembic/versions/ (new migrations)
- backend/tests/fixtures/hardware_firmware/
- backend/tests/services/test_hardware_firmware_*.py
- frontend/src/pages/HardwareFirmwarePage.tsx
- frontend/src/api/hardwareFirmware.ts
- frontend/src/components/hardware-firmware/
- frontend/src/App.tsx (route registration only)
- frontend/src/components/AppSidebar.tsx (sidebar entry only)

## Phases

| # | Status | Type | Phase | Done When |
|---|--------|------|-------|-----------|
| 1 | complete | build | Detect & Classify | Model + migration + detector/classifier + `list_hardware_firmware` MCP tool shipped. Detection runs non-blocking after successful extraction for any firmware via `_run_hardware_firmware_detection_safe` (fire-and-forget with own session). |
| 2 | pending | build | Per-format Parsers | Six parser plugins (qualcomm_mbn, dtb, kmod, elf_tee, broadcom_wl, raw_bin) via PARSER_REGISTRY + `analyze_hardware_firmware` MCP tool + fixture-based unit tests per parser. |
| 3 | pending | build | Driver↔Firmware Graph | `graph.py` + `list_firmware_drivers` MCP tool + `loads_firmware` edges in component_map + "missing firmware" findings. |
| 4 | pending | build | CVE Heuristic Matcher | Three-tier matcher + `known_firmware.yaml` with ≥10 seed entries + `blob_id` FK migration on `sbom_vulnerabilities` + `check_firmware_cves` MCP tool. |
| 5 | pending | build | UI + Remaining MCP Tools | `HardwareFirmwarePage` + API client + sidebar entry + `find_unsigned_firmware` + `extract_dtb` MCP tools. ComponentMap overlay toggle. |

## Phase End Conditions
<!-- Machine-verifiable; Archon checks before marking phase complete -->

**Phase 1:**
- `file_exists` | backend/app/models/hardware_firmware.py
- `file_exists` | backend/app/services/hardware_firmware/__init__.py
- `file_exists` | backend/app/services/hardware_firmware/detector.py
- `file_exists` | backend/app/services/hardware_firmware/classifier.py
- `file_exists` | backend/app/ai/tools/hardware_firmware.py
- `file_exists` | new Alembic revision under backend/alembic/versions/ creating `hardware_firmware_blobs`
- `command_passes` | `docker compose exec backend python -c "from app.services.hardware_firmware import detect_hardware_firmware"` (exit 0)
- `command_passes` | `docker compose exec backend python -c "from app.models.hardware_firmware import HardwareFirmwareBlob"` (exit 0)
- `command_passes` | `grep -q "list_hardware_firmware" backend/app/ai/tools/hardware_firmware.py`
- `command_passes` | `grep -q "register_hardware_firmware_tools" backend/app/ai/__init__.py`
- `command_passes` | `docker compose exec backend alembic upgrade head` (migration applies cleanly)

**Phase 2:**
- `file_exists` | backend/app/services/hardware_firmware/parsers/base.py (Parser protocol + ParsedBlob)
- `file_exists` | backend/app/services/hardware_firmware/parsers/qualcomm_mbn.py
- `file_exists` | backend/app/services/hardware_firmware/parsers/dtb.py
- `file_exists` | backend/app/services/hardware_firmware/parsers/kmod.py
- `file_exists` | backend/app/services/hardware_firmware/parsers/elf_tee.py
- `file_exists` | backend/app/services/hardware_firmware/parsers/broadcom_wl.py
- `file_exists` | backend/app/services/hardware_firmware/parsers/raw_bin.py
- `command_passes` | `docker compose exec backend python -c "import fdt"` (Phase 2 added `fdt` dep)
- `command_passes` | `docker compose exec backend pytest backend/tests/services/test_hardware_firmware_parsers.py -q` (all pass)
- `command_passes` | `grep -q "analyze_hardware_firmware" backend/app/ai/tools/hardware_firmware.py`

**Phase 3:**
- `file_exists` | backend/app/services/hardware_firmware/graph.py
- `command_passes` | `grep -q "list_firmware_drivers" backend/app/ai/tools/hardware_firmware.py`
- `command_passes` | `grep -q "loads_firmware" backend/app/services/component_map_service.py` (edge type wired)
- `command_passes` | `docker compose exec backend pytest backend/tests/services/test_hardware_firmware_graph.py -q`

**Phase 4:**
- `file_exists` | backend/app/services/hardware_firmware/cve_matcher.py
- `file_exists` | backend/app/services/hardware_firmware/known_firmware.yaml
- `metric_threshold` | `wc -l < backend/app/services/hardware_firmware/known_firmware.yaml` returns value ≥ 50 (proxy for ≥10 seed entries)
- `file_exists` | backend/alembic/versions/ contains a migration that adds `blob_id` column to `sbom_vulnerabilities`
- `command_passes` | `docker compose exec backend alembic upgrade head`
- `command_passes` | `grep -q "check_firmware_cves" backend/app/ai/tools/hardware_firmware.py`

**Phase 5:**
- `file_exists` | frontend/src/pages/HardwareFirmwarePage.tsx
- `file_exists` | frontend/src/api/hardwareFirmware.ts
- `command_passes` | `cd frontend && npx tsc --noEmit` (zero new errors vs baseline)
- `command_passes` | `grep -q "hardware-firmware" frontend/src/App.tsx` (route registered)
- `command_passes` | `grep -qE "find_unsigned_firmware.*extract_dtb|extract_dtb.*find_unsigned_firmware" backend/app/ai/tools/hardware_firmware.py || (grep -q find_unsigned_firmware backend/app/ai/tools/hardware_firmware.py && grep -q extract_dtb backend/app/ai/tools/hardware_firmware.py)`
- `visual_verify` | `/projects/:id/hardware-firmware` renders blob tree + detail panel without console errors (via /live-preview)

## Feature Ledger

| Feature | Status | Phase | Notes |
|---------|--------|-------|-------|
| Campaign created | complete | — | Intake + 4-file research bundle already committed at bc91258 |
| `HardwareFirmwareBlob` model + migration `c8a1f4e2d5b6` | complete | 1 | 18 columns, 2 FKs, unique (firmware_id, blob_sha256), 5 indexes incl. ORM auto-indexes. |
| `classifier.py` — magic-byte + filename/path heuristics | complete | 1 | 17 categories × 14 vendors × 16 formats. ~10 magic rules, ~14 filename patterns. Pure-Python deterministic. |
| `detector.py` — post-extraction FS walker | complete | 1 | Sync walk in `run_in_executor`; O_NOFOLLOW; 64-byte magic read; 128 MB file cap; 10K candidate cap; bulk INSERT ... ON CONFLICT DO NOTHING. |
| `hardware_firmware` MCP tool: `list_hardware_firmware` | complete | 1 | Filters by category/vendor/signed; groups by category in output. |
| `unpack.py` post-extraction hook (fire-and-forget) | complete | 1 | Wrapped existing `_unpack_firmware_inner` in new `unpack_firmware` that fires `asyncio.create_task` on any success path. |
| Caller wiring: arq_worker / routers/firmware / device_service | complete | 1 | All three callers now pass `firmware_id=` so detection actually triggers. |
| Pydantic schemas: `HardwareFirmwareBlobResponse` et al. | complete | 1 | Prepared for Phase 5 router + frontend. |

## Decision Log

- 2026-04-17T01:32Z: HardwareFirmwareBlob gets its own model (not a `type="hardware_firmware"` flag on `SbomComponent`). Reason: per research-architecture.md — hardware firmware has chipset targets, signature metadata, driver refs, per-format headers that don't map to CPE. Sibling model + one-way FK into sbom_components keeps both clean.
- 2026-04-17T01:32Z: Detection runs as post-extraction async step in `unpack.py` (after `_analyze_filesystem()` succeeds), wrapped in `run_in_executor` per rule #5. Reason: 5 GB images take seconds to walk; cannot block uvicorn event loop.
- 2026-04-17T01:32Z: Magic-byte read capped at 64 bytes; file-size filter skips <512 bytes and >128 MB; hard cap 10K candidate files. Reason: research-architecture.md performance budget, 30-second target for 5 GB image.
- 2026-04-17T01:32Z: Phase 2 parsers bundled into one phase instead of 2a/2b. Reason: intake says "2 sessions" but parser interdependence is minimal; can split at run-time if needed.
- 2026-04-17T01:32Z: qtestsign vendoring deferred to Phase 2 decision. Options on the table: (a) vendor GPL-2.0 (AGPL-3.0 is GPL-compatible upstream), (b) subprocess, (c) reimplement ~200 LOC header parser. Preferred: reimplement — smallest surface, no license question.
- 2026-04-17T01:45Z: Extended unpack.py signature with `firmware_id: uuid.UUID | None = None` kwarg; trampoline pattern (new `unpack_firmware` wraps `_unpack_firmware_inner`) so detection fires once per success rather than at each of ~10 early-return branches. Wired three callers (arq_worker, routers/firmware, device_service) to pass the firmware_id. Reason: alternative (hook at every success branch) is fragile — any new branch would miss the hook.
- 2026-04-17T01:45Z: Detection uses `INSERT … ON CONFLICT (firmware_id, blob_sha256) DO NOTHING` for idempotency. Unique constraint `uq_hwfw_firmware_sha256` added to model + migration. Reason: re-running detection on the same firmware (e.g., worker restart) must not create duplicate rows; dedup by content hash per firmware is the natural key.
- 2026-04-17T01:45Z: `signed` and `detection_confidence` columns have `server_default` in the migration (not just Python `default=`). Reason: bulk-insert via `sqlalchemy.dialects.postgresql.insert` bypasses ORM defaults; DB-side default is required for NOT NULL columns when the detector omits these fields.

## Review Queue

- [ ] Architecture: Phase 2 — confirm qtestsign license path (vendor vs subprocess vs reimplement).
- [ ] Architecture: Phase 4 — `known_firmware.yaml` CVE families need review before seeding (14 families listed in research-threats.md §Seed CVE Families).
- [ ] UX: Phase 5 — HardwareFirmwarePage layout matches existing ComponentMap left-panel + Monaco pattern.
- [ ] Security: Phase 1 — magic-byte sniff must use `os.open(O_NOFOLLOW)` or realpath check to prevent symlink escape.

## Circuit Breakers

- 3+ consecutive failures on the same parser (Phase 2): park, re-scope parser list
- Typecheck introduces 5+ new errors in a single phase
- Direction drift: if Phase 2 grows beyond 6 parsers or Phase 4 seed YAML >30 entries without justification, park
- Detection blocks unpack >60 seconds on benchmark image: park Phase 1, revisit async boundary

## Active Context

Campaign created this session. Phase 1 starts immediately. Research bundle (4 files in `.planning/knowledge/hw-firmware-research-*.md`) is authoritative reference — every sub-agent reads the relevant file for its phase.

Integration point for Phase 1 is `backend/app/workers/unpack.py:484` (Android fast path `_analyze_filesystem()` call) and `:519`, `:551`, `:591` (other branches). We add `await _run_hardware_firmware_detection(result, firmware_id, db)` as a fire-and-forget `asyncio.create_task(...)` after `_analyze_filesystem()` succeeds and before the success return.

## Continuation State

Phase: 1 (complete, uncommitted) → Phase 2 (pending)
Sub-step: awaiting user decision — commit Phase 1 and proceed to Phase 2, or review first
Files created (7):
  backend/app/models/hardware_firmware.py
  backend/app/schemas/hardware_firmware.py
  backend/app/services/hardware_firmware/__init__.py
  backend/app/services/hardware_firmware/classifier.py
  backend/app/services/hardware_firmware/detector.py
  backend/app/ai/tools/hardware_firmware.py
  backend/alembic/versions/c8a1f4e2d5b6_add_hardware_firmware_blobs.py
Files modified (4):
  backend/app/ai/__init__.py (register hardware firmware tools)
  backend/app/workers/unpack.py (post-extraction fire-and-forget hook)
  backend/app/workers/arq_worker.py (pass firmware_id to unpack)
  backend/app/routers/firmware.py (pass firmware_id to unpack)
  backend/app/services/device_service.py (pass firmware_id to unpack)
Verification:
  - py_compile clean on all 12 touched Python files
  - grep checks for list_hardware_firmware, register_hardware_firmware_tools pass
  - Docker-runtime checks (alembic upgrade head; live MCP call) deferred — require `docker compose up -d --build backend worker` per CLAUDE.md rule 8
Blocking: none — Phase 1 logically complete, awaiting Docker verification + user review
checkpoint-phase-1: none (clean starting state; rollback via git revert or git reset on committed phase)
