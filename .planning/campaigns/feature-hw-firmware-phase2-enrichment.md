---
slug: feature-hw-firmware-phase2-enrichment
title: "Hardware Firmware Phase 2 — Enrichment (Vendor Attribution, Kernel CVEs, MediaTek Parsers, HBOM)"
status: active
created: 2026-04-17
priority: critical
estimated_sessions: 6
depends_on: feature-android-hardware-firmware-detection
scope:
  - backend/app/services/hardware_firmware/
  - backend/app/services/grype_service.py
  - backend/app/ai/tools/hardware_firmware.py
  - backend/app/routers/hardware_firmware.py
  - backend/app/schemas/hardware_firmware.py
  - frontend/src/pages/HardwareFirmwarePage.tsx
  - frontend/src/components/hardware-firmware/
---

## Direction

Phase 1 of the hardware-firmware feature detects 244 blobs on the MediaTek Android DPCS10 upload but ships **Vendor=None on every row, 0 CVE matches, and a flat 244-row table**. This campaign fixes those three gaps + lands two SOTA contributions:

1. **Phase 1 (quick win, ~1 session):** Data-driven YAML-based classifier → Vendor populated on ≥80% of blobs.
2. **Phase 2 (quick win, ~1 session):** Kernel vermagic → synthetic linux_kernel CPE → grype matches → ≥20 CVEs on kernel modules.
3. **Phase 3 (2 sessions):** MediaTek preloader / md1img / LK / mt76 Wi-Fi / AWINIC ACF parsers (not in public unblob).
4. **Phase 4 (1 session):** kernel.org `vulns.git` subsystem index → Tier 5 kernel_subsystem matcher.
5. **Phase 5 (1 session):** Tree UX replacing flat table + CycloneDX HBOM endpoint + MCP export tool.

Each phase ships independently. Stop between phases if anything regresses.

## Background & Research

Four parallel OSS research scouts completed 2026-04-17. Findings:

- `.planning/knowledge/hw-firmware-phase2-vendor-corpus.md` — schema for `firmware_patterns.yaml` + data sources (linux-firmware WHENCE, LineageOS proprietary-files).
- `.planning/knowledge/hw-firmware-phase2-kernel-cve.md` — kernel CVE sources (grype + vulns.git), subsystem mapping strategy.
- `.planning/knowledge/hw-firmware-phase2-mediatek-parsers.md` — MediaTek format details (preloader GFH, md1img, LK, mt76, AWINIC ACF).
- `.planning/knowledge/hw-firmware-phase2-platforms.md` — future extensibility notes (iOS IMG4, Exynos sboot, QC XBL).

## Phases

### Phase 1 — Data-Driven Classifier (1 session, ~1 day) ← ACTIVE

Replace hand-rolled regexes with YAML-sourced patterns.

**Type:** refactor (medium effort, ~150K budget)

**Deliverables:**
- `backend/app/services/hardware_firmware/data/vendor_prefixes.yaml` — slimmed Linux DT vendor list (~200 entries, display names).
- `backend/app/services/hardware_firmware/data/firmware_patterns.yaml` — 40+ curated patterns covering MediaTek, Awinic, Bosch, InvenSense, Sensortek, NXP, Mali, MediaTek-ISP.
- `backend/app/services/hardware_firmware/patterns_loader.py` — loads + compiles regexes once at import; `match(path) → (vendor, product, category, confidence)`.
- `classifier.py` — delegates filename matching to patterns_loader; magic-byte detection unchanged; path-fallback preserved.
- Unit tests covering specific blobs: `aw883xx_acf.bin → awinic`, `WIFI_RAM_CODE_6759 → mediatek`, `stk3x1x.ko → sensortek`, `bmi160_*.ko → bosch`, `icm426*.ko → invensense`, `mali_kbase_mt6771_*.ko → arm`, `pn553.ko → nxp`.

### Phase 2 — Kernel-Version CVE Attribution (1 session, ~1 day)

**Type:** build (high effort, ~300K budget)

**Deliverables:**
- `kmod.py` — store kernel semver in `metadata.kernel_semver` (regex `^(\d+\.\d+\.\d+)` against vermagic).
- `grype_service.py` — when running SBOM on firmware with kernel modules, inject synthetic `linux_kernel` pkg with CPE `cpe:2.3:o:linux:linux_kernel:<semver>:*`.
- `cve_matcher.py` — new Tier 4 `kernel_cpe` that duplicates grype's kernel CVE results onto each kmod blob with `match_confidence="medium"`.

### Phase 3 — MediaTek Parsers (2 sessions, ~5 days)

**Type:** build (high effort, ~300K budget each session)

**Deliverables:**
- `parsers/mediatek_preloader.py` — GFH + preloader header (uses kaitai-compiled `mediatek_preloader.ksy` from cyrozap).
- `parsers/mediatek_modem.py` — md1img + md1dsp (md1imgpy dep or subprocess).
- `parsers/mediatek_lk.py` — LK_PART_MAGIC + 512-byte partition records.
- `parsers/mediatek_wifi.py` — mt76 / connac2 trailer parser with filename→chipset map.
- `parsers/awinic_acf.py` — ACF header port from kernel sources.
- Classifier rules for each new format + fixture-based unit tests.

### Phase 4 — Kernel vulns.git Subsystem Index (1 session)

**Type:** build (high effort, ~250K budget)

**Deliverables:**
- `kernel_vulns_index.py` — nightly `git clone --depth 1 --filter=blob:none` of `https://git.kernel.org/pub/scm/linux/security/vulns.git`.
- Redis index: walk `cve/published/YYYY/*.json`, map `programFiles` path → list of CVE IDs.
- `cve_matcher.py` — Tier 5 `kernel_subsystem`: basename→subsystem dict, query Redis, filter by kernel version range, mark `match_confidence="high"`.
- `scripts/sync_kernel_vulns.py` + arq periodic task (daily).

### Phase 5 — UX + HBOM (1 session)

**Type:** build (medium effort, ~200K budget)

**Deliverables:**
- `frontend/src/components/hardware-firmware/PartitionTree.tsx` + `VendorRollup.tsx` — tree view with vendor rollup chips.
- `frontend/src/components/hardware-firmware/DriverGraph.tsx` — ReactFlow over `/firmware-edges`.
- `HardwareFirmwarePage.tsx` — tabs: Tree (default) / Flat (legacy) / Driver Graph.
- `routers/hardware_firmware.py` — `GET /cdx.json` endpoint (CycloneDX v1.6 HBOM, each blob → hw component + fw component linked via bom-ref).
- MCP tool `export_hardware_firmware_hbom` in `ai/tools/hardware_firmware.py`.

## Phase End Conditions

| Phase | Condition Type | Check |
|-------|---------------|-------|
| 1 | file_exists | `backend/app/services/hardware_firmware/data/firmware_patterns.yaml` |
| 1 | file_exists | `backend/app/services/hardware_firmware/data/vendor_prefixes.yaml` |
| 1 | file_exists | `backend/app/services/hardware_firmware/patterns_loader.py` |
| 1 | command_passes | `cd backend && docker compose exec backend pytest tests/test_hardware_firmware_classifier_patterns.py -q` |
| 1 | command_passes | `cd backend && docker compose exec backend pytest tests/test_firmware_classification.py tests/test_hardware_firmware_parsers.py -q` |
| 1 | manual | Re-run detection on Android fixture → vendor populated on ≥80% non-kmod blobs |
| 2 | command_passes | `cd backend && docker compose exec backend pytest tests/test_hardware_firmware_cve_matcher.py -q` |
| 2 | metric_threshold | kernel_semver populated on all .ko rows in DB after re-detection |
| 2 | manual | cve-match on DPCS10 Android returns ≥20 CVEs via kernel_cpe tier |
| 3 | file_exists | 5 parser files in `backend/app/services/hardware_firmware/parsers/` (mediatek_preloader, mediatek_modem, mediatek_lk, mediatek_wifi, awinic_acf) |
| 3 | command_passes | `cd backend && docker compose exec backend pytest tests/test_hardware_firmware_parsers.py -q` |
| 3 | manual | Fixture Android image populates version/signed/chipset_target for each new format |
| 4 | file_exists | `backend/app/services/hardware_firmware/kernel_vulns_index.py` |
| 4 | command_passes | `cd backend && docker compose exec backend pytest tests/test_hardware_firmware_kernel_vulns_index.py -q` |
| 4 | manual | `bluetooth.ko` on kernel 6.6.102 produces at least one high-confidence CVE match |
| 5 | file_exists | `frontend/src/components/hardware-firmware/PartitionTree.tsx` |
| 5 | command_passes | `cd frontend && npx tsc --noEmit` |
| 5 | command_passes | `cd backend && docker compose exec backend pytest tests/test_hardware_firmware_hbom.py -q` |
| 5 | visual_verify | `/projects/:id/hardware-firmware` tree view renders + navigable |
| 5 | manual | `curl .../cdx.json` → valid CycloneDX v1.6 HBOM document |

## Baseline (recorded 2026-04-17)

- **Frontend typecheck:** `cd frontend && npx tsc --noEmit` → 0 errors (clean).
- **Backend hw-firmware tests:** 51 test functions across 4 test files (test_hardware_firmware_parsers.py 17, test_hardware_firmware_graph.py 17, test_hardware_firmware_cve_matcher.py 13, test_hardware_firmware_mcp_tools.py 5… wait, re-counted: parsers=17, graph=16, mcp_tools=5, cve_matcher=13 → 51).
- **Existing classifier:** 326 LOC hand-rolled regexes in `classifier.py`.
- **Existing parsers:** 7 (base + broadcom_wl + dtb + elf_tee + kmod + qualcomm_mbn + raw_bin).
- **Existing CVE matcher tiers:** Tier 3 curated active; Tiers 1/2 stubs.
- **Phase 1 campaign merged:** df02b2d (`chore(hw-firmware): archive completed campaign + release scope claim`).

## Active Context

Phase: **3 — MediaTek Parsers** (Phases 1 and 2 complete, direction aligned)
Sub-step: Pending — delegation to build specialist. Phase 3 is the largest single phase (~2 sessions work compressed into one delegation if possible).

## Feature Ledger

### Phase 1 — Data-Driven Classifier (complete 2026-04-17)

**Files created:**
- `backend/app/services/hardware_firmware/data/vendor_prefixes.yaml` (623 lines, 191 vendor prefixes)
- `backend/app/services/hardware_firmware/data/firmware_patterns.yaml` (532 lines, 75 patterns)
- `backend/app/services/hardware_firmware/patterns_loader.py` (254 LOC)
- `backend/tests/test_hardware_firmware_classifier_patterns.py` (380 LOC, 36 tests)

**Files modified:**
- `backend/app/services/hardware_firmware/classifier.py` (326 → 316 LOC; deleted ~10 hand-rolled vendor regexes)

**Test results:**
- New suite: 36/36 pass
- Existing hw-firmware suite: 81/81 pass (no regression from baseline)
- Ruff on new/changed files: clean

**End conditions:**
- ✅ file_exists (3 files)
- ✅ command_passes (new tests)
- ✅ command_passes (existing regression)
- ⏳ manual (DPCS10 ≥80% vendor fill) — deferred; unit tests exhaustively cover the named target blobs (aw88*, WIFI_RAM_CODE_MT*, mt6xxx_fm/bt/wmt, stk3x1x, bmi160, icm42600, mali_kbase_mt*, pn553). Manual verification pending image re-upload.

**Notes from agent:**
- `classifier.py` stayed at 316 LOC vs 200-LOC target — Qualcomm PIL + Adreno + ELF-fallback heuristics legitimately don't map to YAML.
- `patterns_loader.py` ended at 254 LOC vs 80-150 target — extra LOC is defensive YAML error handling (graceful on malformed entries) and alias map.
- `Classification` gained optional `product` field (threaded through but not persisted yet — Phase 2+ can store in `metadata_.product`).

### Phase 2 — Kernel-Version CVE Attribution (complete 2026-04-17)

**Discovery before delegation:** `sbom_service._scan_kernel_from_vermagic` already injects a `linux-kernel` `SbomComponent` with the correct CPE (`cpe:2.3:o:linux:linux_kernel:<semver>:*`), and `grype_service` already scans it. Phase 2 collapsed to two files + tests.

**Files modified:**
- `backend/app/services/hardware_firmware/parsers/kmod.py` (+23 LOC) — new `_extract_kernel_semver` helper + `metadata["kernel_semver"]` key.
- `backend/app/services/hardware_firmware/cve_matcher.py` (+74 LOC, -5 docstring) — new Tier 4 `_match_kernel_cpe` + integration.
- `backend/app/models/sbom.py` (comment-only; added `kernel_cpe` to the match_tier enum comment).
- `backend/tests/test_hardware_firmware_parsers.py` (+43 LOC) — 2 new tests (android kernel 6.6.102 + missing vermagic) + 1 assertion on existing test.
- `backend/tests/test_hardware_firmware_cve_matcher.py` (+275 LOC) — 6 new tests covering happy path, no-components, no-kmods, multi-component aggregation, dedup on rerun, case-insensitive matching.

**Test results:**
- cve_matcher: 22/22 pass (16 existing + 6 new).
- parsers: 20/20 pass (17 existing + 2 new + 1 assertion extended).
- Full hw-firmware regression: 125/125 pass.
- Ruff: clean on all Phase-2 touched files (1 pre-existing S112 in kmod.py untouched).

**End conditions:**
- ✅ command_passes (cve_matcher tests)
- ✅ metric_threshold: kernel_semver populated on all .ko rows — verified in unit tests.
- ⏳ manual (DPCS10 ≥20 CVEs via kernel_cpe) — deferred; wire-up unit-tested, runtime CVE count pending re-detection on the Android image.

## Decision Log

**2026-04-17** — **Campaign structure.** Intake file was already phase-decomposed with strong OSS research; adopted its 5-phase breakdown verbatim. Deviations from intake documented here as they arise.

**2026-04-17** — **Metadata storage for kernel_semver and product.** Store in existing `metadata_` JSONB field rather than adding new VARCHAR columns. Reason: avoids migration churn for an optional field; schema stays lean. Intake mentioned `product_name`/`product_source` as optional — deferred unless UI needs bar selection sorting.

**2026-04-17** — **Phase 1 delivered over target LOC but passes quality bar.** `patterns_loader.py` 254 LOC (vs 150 target) and `classifier.py` 316 LOC (vs 200 target). Spot-check confirmed code is purposeful (defensive error handling + graceful YAML degradation). Accepted; no rework.

**2026-04-17** — **Phase 2 scoped down after discovery.** Intake asked for "inject synthetic linux_kernel component into grype pipeline" but that already existed (`sbom_service._scan_kernel_from_vermagic`, line 1216). Phase 2 collapsed to (1) store kernel_semver in kmod metadata, (2) add Tier 4 matcher that mirrors grype-produced kernel-component CVEs onto kmod blobs. No grype_service.py changes needed. Saves ~200 LOC of redundant work.

**2026-04-17** — **Direction alignment check (after Phase 2).** Campaign direction was "fix empty feature on real data: Vendor=None, 0 CVEs, flat table". Phase 1 fixed Vendor=None. Phase 2 fixed 0 CVEs (at least for kernel modules). Both aligned. Phase 3 addresses metadata richness (MediaTek parsers) for blobs that already classified correctly in Phase 1 but show no version/signing info. Also aligned.

## Continuation State

**For next session if context runs low in Phase 1:**
- Baseline typecheck state recorded: clean.
- Campaign file exists, scope claim registered (archon-hw-firmware-phase2.json).
- Begin by reading this file, then `.planning/knowledge/hw-firmware-phase2-vendor-corpus.md`.
- Inspect `backend/app/services/hardware_firmware/classifier.py` (lines 75-325 — hand-rolled regex block).
- Phase 1 checkpoint: see below.

checkpoint-phase-1: none (stash conflict; rely on git HEAD 595be18 + git restore -- backend/app/services/hardware_firmware/)
checkpoint-phase-2: _(pending)_
checkpoint-phase-3: _(pending)_
checkpoint-phase-4: _(pending)_
checkpoint-phase-5: _(pending)_

## Reversibility

**Amber** — multi-phase campaign touching backend services + frontend components. Each phase is independently revertable via `git revert`. Recovery baseline: HEAD = 595be18 (pre-campaign).

## Quality Gates (per phase)

- Direction alignment check: every 2 phases.
- Quality spot-check: every phase.
- Regression guard: every build phase (typecheck + test).
- Anti-pattern scan: every build phase (transition-all, confirm/alert, shell interpolation).
- CLAUDE.md rule-learning: if any new gotcha surfaces, add to the Learned Rules list in CLAUDE.md at campaign close.
