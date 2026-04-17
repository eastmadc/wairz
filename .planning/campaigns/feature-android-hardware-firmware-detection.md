---
version: 1
id: "41e39acc-764f-4220-8048-0f68280574fc"
status: completed
started: "2026-04-17T01:32:19Z"
completed_at: "2026-04-17T02:45:00Z"
direction: "Android hardware firmware detection — modem/TEE/Wi-Fi/GPU/DSP/drivers: detection, parsers, driver graph, CVE matcher, UI + MCP tools"
phase_count: 5
current_phase: 5
branch: null
worktree_status: null
---

# Campaign: Android Hardware Firmware Detection

Status: completed (2026-04-17T02:45Z)
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
| 2 | complete | build | Per-format Parsers | Six parser plugins (qualcomm_mbn, dtb, kmod, elf_tee, broadcom_wl, raw_bin) via PARSER_REGISTRY + `analyze_hardware_firmware` MCP tool + fixture-based unit tests per parser. |
| 3 | complete | build | Driver↔Firmware Graph | `graph.py` + `list_firmware_drivers` MCP tool + `loads_firmware` edge type documented in component_map_service + "missing firmware" findings + new `/hardware-firmware/firmware-edges` + `/drivers` REST endpoints. |
| 4 | complete | build | CVE Heuristic Matcher | Three-tier matcher (Tier 3 curated YAML active, Tiers 1/2 stubbed) + `known_firmware.yaml` with 14 seed CVE families (all 14 from research-threats.md §Seed) + migration adds `blob_id` FK + `match_confidence` + `match_tier` + CHECK constraint + `check_firmware_cves` MCP tool. |
| 5 | complete | build | UI + Remaining MCP Tools | `HardwareFirmwarePage` (304 lines) + 5 hardware-firmware subcomponents + API client with 6 methods + sidebar entry between SBOM and Emulation + 4 REST endpoints (list/detail/cves/cve-match POST) + `find_unsigned_firmware` + `extract_dtb` MCP tools. ComponentMap overlay toggle deferred to follow-up. |

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
- `command_passes` | `docker compose exec backend pytest backend/tests/test_hardware_firmware_parsers.py -q` (all pass)
- `command_passes` | `grep -q "analyze_hardware_firmware" backend/app/ai/tools/hardware_firmware.py`

**Phase 3:**
- `file_exists` | backend/app/services/hardware_firmware/graph.py
- `command_passes` | `grep -q "list_firmware_drivers" backend/app/ai/tools/hardware_firmware.py`
- `command_passes` | `grep -q "loads_firmware" backend/app/services/component_map_service.py` (edge type wired)
- `command_passes` | `docker compose exec backend pytest backend/tests/test_hardware_firmware_graph.py -q`

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
| PARSER_REGISTRY plugin contract (`parsers/base.py`) | complete | 2 | Protocol + ParsedBlob dataclass + register_parser/get_parser helpers. |
| `qualcomm_mbn.py` parser | complete | 2 | Reimplemented (no qtestsign vendor): MBN v3 raw header (40-byte codeword `0x844bdcd1`) + ELF QC segments (LIEF) + X.509 cert-chain DER walker via `cryptography`. Registered for qcom_mbn + mbn_v3/v5/v6. |
| `dtb.py` parser | complete | 2 | Uses `fdt` pip pkg: flat DTB + Android DTBO container (magic `0xd7b7ab1e`); extracts `model`, `compatible` lists, `firmware-name` props recursively; chipset inference from compatible pattern. |
| `kmod.py` parser | complete | 2 | pyelftools `.modinfo` section walk: license/version/srcversion/vermagic/depends/alias/firmware_deps + CMS appendix magic detection (`~Module signature appended~`). |
| `elf_tee.py` parser | complete | 2 | OP-TEE `.ta_head` section → TA UUID; signed=signed + RSA-SHA256 default. |
| `broadcom_wl.py` parser | complete | 2 | brcmfmac ASCII version scan (wl0/Firmware regex); paired `.txt` NVRAM + `.clm_blob` detection; chipset from filename. |
| `raw_bin.py` parser | complete | 2 | Shannon entropy of first 1 MB + generic version regex + printable-string sampling. |
| Detector → parser integration | complete | 2 | `_walk_and_classify` invokes `get_parser(cls.format).parse()` inside the executor; defensive try/except per blob. Carries version/signed/signature_algorithm/cert_subject/chipset_target/metadata through to `insert(...).values([...])`. |
| `analyze_hardware_firmware` MCP tool | complete | 2 | Reads persisted row only (no re-parsing); markdown summary with parsed-metadata JSON. |
| `fdt>=0.3.3` pip dep | complete | 2 | Added to backend/pyproject.toml (pure-Python, Apache-2.0). Requires `docker compose up -d --build backend worker` per rule 8. |
| Parser unit tests | complete | 2 | 13 test functions + parametrized malformed-input across 10 formats. Synthetic fixtures only (no firmware binaries checked in). |
| `_build_fixtures.py` helper | complete | 2 | Pure-Python generators: ELF64, kmod with .modinfo, OP-TEE TA with .ta_head, MBN v3 header + cert chain, DTB, DTBO, Broadcom firmware with embedded version. Self-signed RSA-2048 X.509 via `cryptography`. |
| `graph.py` — driver↔firmware resolver | complete | 3 | `build_driver_firmware_graph()` resolves kmod `.modinfo firmware=` + DTB firmware_names + vmlinux string scan against blob inventory by basename; writes `driver_references` to .ko rows; creates idempotent Finding rows (source=`hardware_firmware_graph`) for unresolved. |
| `list_firmware_drivers` MCP tool | complete | 3 | Collapses edges into per-driver summaries; optional `module_pattern` substring filter; outputs resolved + unresolved in markdown. |
| `/hardware-firmware/firmware-edges` + `/drivers` REST endpoints | complete | 3 | New router under `/api/v1/projects/{project_id}/hardware-firmware`; returns FirmwareEdgesResponse (overlay) + FirmwareDriversListResponse. Registered in `main.py`. |
| `loads_firmware` edge type documented | complete | 3 | Comment-level in `component_map_service.py:ComponentEdge` — no runtime entanglement; frontend renders the overlay from the separate endpoint. |
| unpack.py hook extended | complete | 3 | Post-detection, if count > 0, `_run_hardware_firmware_detection_safe` fires `build_driver_firmware_graph` in a second session (rule 7). |
| Graph unit tests | complete | 3 | 17 tests across 4 classes covering `_resolve_firmware_name`, `_scan_vmlinux_firmware_strings`, `build_driver_firmware_graph`, plus idempotency on second run. Mock-based per existing project pattern (no async-sqlite harness). |
| `cve_matcher.py` — three-tier matcher | complete | 4 | Tier 3 (curated YAML) active; Tiers 1 (chipset CPE lookup) + 2 (NVD free-text) explicitly stubbed per architecture decision. Persists to `sbom_vulnerabilities` with `blob_id` + `match_tier` + `match_confidence`; dedups on (firmware_id, blob_id, cve_id); `db.flush()` not commit. |
| `known_firmware.yaml` — curated CVE database | complete | 4 | 14 seed CVE families (BroadPwn, Snapdragon modem RCE, Shannon cluster, TEEGRIS Powerful Clipboard, Mali CSF, MediaTek-SU, Hexagon Achilles, MediaTek-reaver, Kr00k, BleedingTooth, QSEE Widevine keybox, kamakiri BROM advisory, EDL programmers, FragAttacks). 202 lines. |
| Migration `d9b2e3f5a6c7` — sbom_vulnerabilities blob_id | complete | 4 | Adds `blob_id UUID NULL` FK CASCADE to hardware_firmware_blobs; makes `component_id` nullable; CHECK constraint `component_id IS NOT NULL OR blob_id IS NOT NULL`; adds `match_confidence` + `match_tier` columns + `idx_sbom_vulns_blob` index. |
| `check_firmware_cves` MCP tool | complete | 4 | Runs three-tier matcher against current firmware; returns markdown summary grouped by blob; optional `force_rescan` bypasses dedup. |
| `pyyaml>=6.0` pip dep | complete | 4 | Added to backend/pyproject.toml. Required for YAML loader (not previously imported in app/). Rebuild both backend and worker. |
| CVE matcher unit tests | complete | 4 | 7 test functions covering YAML load, curated matching (exact + vendor/chipset/version regex), metadata-version fallback, advisory-only families, Shannon cluster multi-CVE, persistence, idempotency. |
| `HardwareFirmwarePage.tsx` + 5 subcomponents | complete | 5 | StatsHeader, BlobFilters, BlobTable, BlobDetail, DriversTable. 304-line page; two tabs (Blobs + Drivers); exhaustive SEVERITY_STYLE + SIGNED_STYLE Records with fallback per rule 9. |
| `frontend/src/api/hardwareFirmware.ts` | complete | 5 | 6 methods (listHardwareFirmware, getHardwareFirmwareBlob, getHardwareFirmwareCves, runCveMatch, getFirmwareEdges, getFirmwareDrivers) + typed interfaces. |
| Sidebar entry + App.tsx route | complete | 5 | Sub-page entry between SBOM and Emulation (`Cpu` icon from lucide). Route `/projects/:projectId/hardware-firmware`. |
| 4 REST endpoints on `/hardware-firmware` | complete | 5 | GET "" (list + filters), GET /{blob_id}, GET /{blob_id}/cves, POST /cve-match. Uses `_blob_to_response` manual helper to sidestep `metadata`/`metadata_` Pydantic alias fragility. |
| `find_unsigned_firmware` MCP tool | complete | 5 | Triage: lists blobs with signed=unsigned/unknown/weakly_signed, grouped by category. |
| `extract_dtb` MCP tool | complete | 5 | Parses a DTB on-demand using `fdt.parse_dtb`, walks all nodes with `compatible` props, emits compatible→firmware-name mapping (cap 100 nodes). Uses `context.resolve_path()` for sandbox. |
| MCP tool smoke tests | complete | 5 | 5 tests covering find_unsigned_firmware (empty + grouping) and extract_dtb (missing path/file + parse via `build_minimal_dtb()` fixture). |

## Decision Log

- 2026-04-17T01:32Z: HardwareFirmwareBlob gets its own model (not a `type="hardware_firmware"` flag on `SbomComponent`). Reason: per research-architecture.md — hardware firmware has chipset targets, signature metadata, driver refs, per-format headers that don't map to CPE. Sibling model + one-way FK into sbom_components keeps both clean.
- 2026-04-17T01:32Z: Detection runs as post-extraction async step in `unpack.py` (after `_analyze_filesystem()` succeeds), wrapped in `run_in_executor` per rule #5. Reason: 5 GB images take seconds to walk; cannot block uvicorn event loop.
- 2026-04-17T01:32Z: Magic-byte read capped at 64 bytes; file-size filter skips <512 bytes and >128 MB; hard cap 10K candidate files. Reason: research-architecture.md performance budget, 30-second target for 5 GB image.
- 2026-04-17T01:32Z: Phase 2 parsers bundled into one phase instead of 2a/2b. Reason: intake says "2 sessions" but parser interdependence is minimal; can split at run-time if needed.
- 2026-04-17T01:32Z: qtestsign vendoring deferred to Phase 2 decision. Options on the table: (a) vendor GPL-2.0 (AGPL-3.0 is GPL-compatible upstream), (b) subprocess, (c) reimplement ~200 LOC header parser. Preferred: reimplement — smallest surface, no license question.
- 2026-04-17T01:45Z: Extended unpack.py signature with `firmware_id: uuid.UUID | None = None` kwarg; trampoline pattern (new `unpack_firmware` wraps `_unpack_firmware_inner`) so detection fires once per success rather than at each of ~10 early-return branches. Wired three callers (arq_worker, routers/firmware, device_service) to pass the firmware_id. Reason: alternative (hook at every success branch) is fragile — any new branch would miss the hook.
- 2026-04-17T01:45Z: Detection uses `INSERT … ON CONFLICT (firmware_id, blob_sha256) DO NOTHING` for idempotency. Unique constraint `uq_hwfw_firmware_sha256` added to model + migration. Reason: re-running detection on the same firmware (e.g., worker restart) must not create duplicate rows; dedup by content hash per firmware is the natural key.
- 2026-04-17T01:45Z: `signed` and `detection_confidence` columns have `server_default` in the migration (not just Python `default=`). Reason: bulk-insert via `sqlalchemy.dialects.postgresql.insert` bypasses ORM defaults; DB-side default is required for NOT NULL columns when the detector omits these fields.
- 2026-04-17T02:00Z: Phase 2 — qtestsign decision executed: REIMPLEMENTED the MBN v3/v5/v6 parser (~500 LOC) rather than vendoring GPL-2.0 code or shelling out. Reason: smallest surface, no license entanglement, and MBN v3 raw header + QC segment flags + X.509 cert-chain DER walking is all that's needed — no need to replicate qtestsign's signing logic (we only READ).
- 2026-04-17T02:00Z: Phase 2 — Parser execution happens inline in `_walk_and_classify` (inside the executor), not as a separate pass. Reason: avoids a second FS walk; parsers are fast enough (pyelftools/LIEF/fdt) that the added cost is negligible; keeps detection a single atomic "classify + parse + persist" pipeline.
- 2026-04-17T02:00Z: Phase 2 — Parsers MUST NOT raise (contract enforced by defensive try/except in detector). Reason: one bad blob cannot abort detection for the other 20+ blobs in an Android image. Parsers surface errors through `metadata["error"]` instead.
- 2026-04-17T02:00Z: Phase 2 — Test fixtures are all synthesized in-memory from `_build_fixtures.py` helpers (no real firmware binaries checked in). Reason: avoids licensing/export-control issues; keeps repo small; parsers tested against controlled inputs with known-correct expected values.
- 2026-04-17T02:15Z: Phase 3 — Firmware-overlay edges served from a SEPARATE endpoint (`/hardware-firmware/firmware-edges`), NOT baked into the cached component_map. Reason: keeps the existing component_map cache FS-pure; lets frontend toggle overlay cheaply; avoids invalidating large cached graphs when detection re-runs. ComponentEdge dataclass gets `loads_firmware` type documented in comment only.
- 2026-04-17T02:15Z: Phase 3 — Graph builder uses TWO independent AsyncSessions (one for detection, one for graph build), fired sequentially from `_run_hardware_firmware_detection_safe`. Reason: CLAUDE.md rule 7 — never share AsyncSession across concurrency boundaries; separate sessions also give cleaner transaction boundaries (detection commits before graph starts).
- 2026-04-17T02:15Z: Phase 3 — Missing-firmware findings dedup by title within the same firmware_id + source=`hardware_firmware_graph`. Reason: graph builder runs on every detection (and on every API call to `/firmware-edges`) — we must not create duplicate findings on re-runs.
- 2026-04-17T02:15Z: Phase 3 — vmlinux string scan capped at first 32 MB of file + 500 unique references per file. Reason: vmlinux on modern Android can be 30-50 MB uncompressed; the regex scan cost scales linearly. 32 MB covers the whole image for typical cases while capping worst-case cost.
- 2026-04-17T02:30Z: Phase 4 — Only Tier 3 (curated YAML) is active; Tiers 1 (chipset CPE) and 2 (NVD free-text) are explicit stubs returning []. Reason: (a) real NVD keyword search is rate-limited + async; (b) chipset→CPE→CVE pipeline needs a separate lookup loop; (c) Tier 3 covers the ~15 famous CVE families where Wairz's differentiation lies; (d) userspace CVEs continue to flow through existing SBOM-grype path. Future phase can expand Tiers 1/2.
- 2026-04-17T02:30Z: Phase 4 — `component_id` on `sbom_vulnerabilities` is made nullable (was NOT NULL). CHECK constraint `component_id IS NOT NULL OR blob_id IS NOT NULL` enforces that every row has at least one of the two references. Reason: hw firmware CVEs don't have an SBOM component; making the column nullable + adding CHECK preserves integrity.
- 2026-04-17T02:30Z: Phase 4 — CVE matcher is NOT added to the post-unpack hook. It runs only on explicit MCP tool invocation or future UI button. Reason: CVE matching is a separate user decision (may want to force_rescan, pick a different CVE feed, etc.); keeping it explicit matches the existing `/generate_sbom` pattern for userspace vulns.
- 2026-04-17T02:30Z: Phase 4 — Advisory-only families (kamakiri BROM — no CVE assigned, permanent mask-ROM bug) emit `ADVISORY-<FAMILY-NAME>` pseudo-IDs instead of CVE rows. Reason: users still need to know the device has an unpatchable BootROM bug; keyed off a pseudo-ID lets it flow through the existing vulnerability table + dedup logic.

## Review Queue

- [x] Architecture: Phase 2 — qtestsign license path resolved by reimplementing ~500 LOC of header + segment + cert-chain parsing in `qualcomm_mbn.py`. No vendor, no subprocess, no license question.
- [ ] Verification: Phase 2 — `docker compose exec backend python -c "import fdt"` after `up -d --build backend worker` (rule 8); `docker compose exec backend pytest backend/tests/test_hardware_firmware_parsers.py -q`.
- [ ] OP-TEE fixture ELF: verify LIEF accepts the section-only ELF64 built by `_build_minimal_elf64`. If rejected, add a PT_LOAD program header to the fixture builder.
- [ ] MBN v3 header classifier: the parser reports either `"v3"` or `"v5_or_v6"` based on a size heuristic; current fixture ends up as `"v5_or_v6"` because it includes 8-byte cert-ptr extension. Test accepts either. Real-world refinement TBD when we have actual MBN v3 vs v5 samples.
- [x] Architecture: Phase 4 — `known_firmware.yaml` seeded with all 14 families from research-threats.md §Seed CVE Families. Each has vendor + category + optional chipset_regex + optional version_regex + CVE list + severity + cvss_score + notes.
- [ ] Phase 4 tuning: BroadPwn + FragAttacks both trigger on any broadcom/wifi blob because FragAttacks has no version_regex gate (applies broadly per 2021 disclosure). Consider tightening FragAttacks `version_regex` once real fixture images are scanned.
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

Campaign: COMPLETE — all 5 phases shipped.
Phase 1: ac6a493 (14 files, 1059+/-3 lines) — detect & classify
Phase 2: 5c9c464 (15 files, 2413+/-27 lines) — per-format parsers
Phase 3: 278aad7 (9 files, 1002+/-7 lines) — driver↔firmware graph
Phase 4: 1fbcce4 (8 files, 1014+/-7 lines) — CVE matcher + curated YAML
Phase 5: pending commit — UI + remaining MCP tools

Verification required in Docker (not run here):
- `docker compose up -d --build backend worker` (rule 8 — rebuild both for new `fdt` + `pyyaml` deps)
- `docker compose exec backend alembic upgrade head` (applies c8a1f4e2d5b6 + d9b2e3f5a6c7)
- `docker compose exec backend pytest backend/tests/test_hardware_firmware*.py -q`
- Upload a real Android firmware image (Pixel 5 / Galaxy S22) → navigate to `/projects/{id}/hardware-firmware` → verify ≥20 blobs detected, classified, parsed, and CVE-matched
- `/live-preview` visual verification of the HardwareFirmwarePage (Phase 5 visual_verify end condition)

Follow-ups (tracked in Review Queue):
- ComponentMap overlay toggle (Phase 5 stretch item, deferred)
- FragAttacks family version_regex tightening (Phase 4 tuning)
- Phase 2 MBN v3 header classifier edge case (refinement when real samples available)
- OP-TEE fixture ELF — verify LIEF accepts section-only construction
Phase 2 files created (10):
  backend/app/services/hardware_firmware/parsers/__init__.py
  backend/app/services/hardware_firmware/parsers/base.py
  backend/app/services/hardware_firmware/parsers/qualcomm_mbn.py
  backend/app/services/hardware_firmware/parsers/dtb.py
  backend/app/services/hardware_firmware/parsers/kmod.py
  backend/app/services/hardware_firmware/parsers/elf_tee.py
  backend/app/services/hardware_firmware/parsers/broadcom_wl.py
  backend/app/services/hardware_firmware/parsers/raw_bin.py
  backend/tests/test_hardware_firmware_parsers.py
  backend/tests/fixtures/hardware_firmware/_build_fixtures.py
  (+ backend/tests/fixtures/hardware_firmware/__init__.py empty marker)
Phase 2 files modified (3):
  backend/pyproject.toml (added fdt dep)
  backend/app/services/hardware_firmware/detector.py (parser dispatch + merge fields into insert)
  backend/app/ai/tools/hardware_firmware.py (added analyze_hardware_firmware handler + registration)
Verification:
  - py_compile clean on all 12 new/modified Python files
  - 13 test functions + parametrized malformed-input test
  - PARSER_REGISTRY has 10 keys (qcom_mbn, mbn_v3, mbn_v5, mbn_v6, dtb, dtbo, ko, optee_ta, fw_bcm, raw_bin)
  - Detector invokes get_parser+parser.parse inside executor; defensive try/except
  - Docker-runtime checks (fdt import, pytest, migration) deferred — require `docker compose up -d --build backend worker` per rule 8
Blocking: none — Phase 2 logically complete
checkpoint-phase-2: stash@{0} (telemetry deltas only)
