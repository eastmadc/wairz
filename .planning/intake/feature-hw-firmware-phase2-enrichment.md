---
title: "Feature: Hardware Firmware Enrichment — Vendor Attribution, Kernel CVEs, MediaTek Parsers, HBOM Output"
status: pending
priority: critical
target: backend/app/services/hardware_firmware/, backend/app/services/grype_service.py, frontend/src/pages/HardwareFirmwarePage.tsx
---

## Overview

The original `feature-android-hardware-firmware-detection` campaign (5 phases, merged 2026-04-17) landed detection + classification + parsers + driver graph + CVE matcher + UI. On the first real MediaTek Android upload (MT6771 / Helio P60) it produced:

- **244 blobs detected** ✓
- **Vendor=None on every row** ✗ (classifier only knows ~14 hand-rolled patterns)
- **0 CVE matches** ✗ (three-tier matcher's Tier 3 YAML has no MediaTek entries; kernel modules never tried)
- **Flat 244-row table** ✗ (wall-of-text UX)

This campaign addresses those gaps using findings from 4 parallel OSS research scouts (2026-04-17). Full research lives in:

- `.planning/knowledge/hw-firmware-phase2-mediatek-parsers.md`
- `.planning/knowledge/hw-firmware-phase2-kernel-cve.md`
- `.planning/knowledge/hw-firmware-phase2-vendor-corpus.md`
- `.planning/knowledge/hw-firmware-phase2-platforms.md`

## Why This Is Priority-Zero

- **Phase-1 feature demonstrably ships "empty"** on real data. Every new user's first impression will be "detected 244 things, told me nothing about any of them."
- **Quick wins compound:** two ~1-day changes (data-driven classifier YAML + grype kernel-version injection) would take Vendor from 0 → ~80% and CVE matches from 0 → real numbers.
- **Novel SOTA contribution:** public unblob does NOT ship MediaTek preloader/modem handlers (OneKey keeps them closed). Shipping them here advances open-source firmware analysis.
- **Unblocks future work:** HBOM output lets Wairz feed Dependency-Track; tree UX lets users actually consume the data.

## Approach — 5 Phase Rollout

Estimated ~6 sessions end-to-end. Phases 1 and 2 are quick wins; 3-5 are deeper investments. Each phase ships independently.

### Phase 1 — Data-Driven Classifier (1 session, ~1 day)

Replace hand-rolled regexes with YAML-sourced filename patterns.

**Deliverables:**
- `backend/app/services/hardware_firmware/data/vendor_prefixes.yaml` — slimmed mirror of Linux kernel DT `vendor-prefixes.yaml` (~200 entries covering our VENDORS set, with display names).
- `backend/app/services/hardware_firmware/data/firmware_patterns.yaml` — 40-60 initial entries (hand-curated; audio/sensor/NFC/touch/USB-PD/camera/GPU/modem/Wi-Fi/BT). Schema per research-vendor-corpus.md §Concrete Recommendation.
- `backend/app/services/hardware_firmware/patterns_loader.py` — parses YAML, compiles regex tree once at import, `match(path) → (vendor, product, category, confidence)`.
- `classifier.py` updated: delete hand-rolled patterns, delegate to `patterns_loader`. Backwards-compatible: if YAML miss → path-fallback still works.
- Bootstrap script `scripts/gen_firmware_patterns.py` (optional this phase) — scrapes linux-firmware WHENCE + 50 LineageOS `proprietary-files-vendor.txt` files → generated patterns block.

**End condition:**
Re-running detection on DPCS10 Android image now populates `vendor` on ≥80% of non-kernel-module blobs (e.g., `aw883xx_acf.bin` → awinic, `WIFI_RAM_CODE_6759` → mediatek, `mt6631_fm_*` → mediatek, `stk3x1x.ko` → sensortek, `bmi160_*.ko` → bosch, `icm426*.ko` → invensense, `mali_kbase_mt6771_*.ko` → arm, `pn553.ko` → nxp).

### Phase 2 — Kernel-Version CVE Attribution (1 session, ~1 day)

Wire existing `vermagic` extraction into the grype pipeline.

**Deliverables:**
- `kmod.py` parser: extract kernel semver from vermagic (regex `^(\d+\.\d+\.\d+)` against the base vermagic string). Store in `metadata.kernel_semver`.
- `grype_service.py`: when an SBOM generation is run on firmware with detected kernel modules, inject a synthetic `linux_kernel` component with CPE `cpe:2.3:o:linux:linux_kernel:<semver>:*` so grype's stock CPE matcher picks it up.
- `cve_matcher.py`: new Tier 4 "kernel-cve" that reads the synthetic kernel component's grype results and duplicates them onto each kernel_module blob with `match_tier="kernel_cpe"` and `match_confidence="medium"`.
- Update `known_firmware.yaml` seed — add a "linux kernel CVE families" section OR skip since grype handles it.

**End condition:**
`POST /api/v1/projects/{id}/hardware-firmware/cve-match` on DPCS10 Android returns ≥20 CVEs across the 236 kernel modules (covering actively-exploited families like Bluetooth/nftables/io_uring).

### Phase 3 — MediaTek Parsers (2 sessions, ~5 days work)

Add MediaTek-specific parsers for the formats the scouts flagged.

**Deliverables:**
1. **Preloader + GFH parser** (`parsers/mediatek_preloader.py`) — vendor cyrozap `mediatek_preloader.ksy` + `mediatek_download_agent.ksy`, compile via `kaitai-struct-compiler`. Registers for `format="mtk_preloader"` and a new `format="mtk_gfh"`.
2. **md1img/md1dsp parser** (`parsers/mediatek_modem.py`) — add `md1imgpy` to `pyproject.toml`, wrap in ~50 LOC handler. Emits section list (md1rom, md1drdi, md1dsp, certs), build strings.
3. **LK image parser** (`parsers/mediatek_lk.py`) — 100 LOC native, LK_PART_MAGIC + 512-byte partition records.
4. **mt76 Wi-Fi firmware parser** (`parsers/mediatek_wifi.py`) — 150 LOC native. Three sub-parsers (pre-MT7915 ROM patch, MT7915 trailer, connac2 trailer). Filename→chipset map for non-`_hdr` files (MT6759 → MT6771 connsys, etc.).
5. **AWINIC ACF parser** (`parsers/awinic_acf.py`) — 80 LOC port of kernel `sound/soc/codecs/aw88*/aw_dev_load_cfg_by_hdr()`.

Register each parser's `FORMAT` string with `PARSER_REGISTRY` (existing Phase 2 plugin pattern). Add matching classifier rules for `preloader.bin`, `lk.bin`, `md1img.img`, `md1dsp.img`, `WIFI_RAM_CODE_MT*_hdr.bin`, `aw*_acf.bin`.

**End condition:**
- Fixture Android image (or DPCS10) populates parsed `version`, `signed`, `chipset_target`, and parser metadata for each of preloader, md1img, LK, Wi-Fi hdr, AWINIC blobs it contains.
- All 5 parsers have fixture-based unit tests.

### Phase 4 — Kernel.org vulns.git Subsystem Index (1 session)

Add the high-confidence Tier 5 matcher.

**Deliverables:**
- New service `backend/app/services/hardware_firmware/kernel_vulns_index.py`:
  - Nightly `git clone --depth 1` (or update) of `https://git.kernel.org/pub/scm/linux/security/vulns.git` to a persistent volume.
  - Walk `cve/published/YYYY/*.json`, index `programFiles` → subsystem path.
  - Load into Redis with 24h TTL (reuse existing redis infra).
- `cve_matcher.py`: new Tier 5 "kernel-subsystem". For each kernel_module blob, map basename → subsystem (static 50-entry dict), query Redis index, filter CVEs by kernel version range. Mark hits `match_tier="kernel_subsystem"`, `match_confidence="high"`.
- Scheduled task via arq (once daily) to `git pull` the vulns repo.

**End condition:**
`bluetooth.ko` returns the most-recent Bluetooth-subsystem CVEs applicable to 6.6.102; `mali_kbase_mt6771_r49.ko` returns Mali CSF CVEs; findings exist in DB with high confidence.

### Phase 5 — UX + HBOM Output (1 session)

Replace flat table with tree view; emit CycloneDX HBOM.

**Deliverables:**
- Frontend: `HardwareFirmwarePage.tsx` gets a new default "Tree" view:
  - Top: partition tree (vendor / system / odm / partition_N_erofs) with blob counts and vendor rollup (MediaTek: 47 · ARM: 3 · AWINIC: 1 · Unknown: 12).
  - Expanding a partition reveals vendor groups; expanding a vendor reveals individual blobs.
  - "Flat table" remains as a secondary view (backwards compat).
- Frontend: "Driver Graph" tab — renders `GET /firmware-edges` (Phase 3 endpoint, unchanged) as a ReactFlow graph showing `.ko` nodes linked to firmware blobs they load.
- Backend: `GET /api/v1/projects/{id}/hardware-firmware/cdx.json` — emits CycloneDX v1.6 HBOM. Each blob → two components (hardware + firmware) linked via `bom-ref`. Reuses existing CycloneDX emission library (already installed).
- MCP tool `export_hardware_firmware_hbom` — returns CycloneDX JSON on demand.

**End condition:**
- Visiting `/projects/:id/hardware-firmware` shows a tree view that collapses 244 blobs into a ~3-level navigable structure.
- `curl .../cdx.json` returns a valid CycloneDX HBOM v1.6 document that validates against the spec schema.

## Data Model

No new tables needed. Optional additions:

1. `HardwareFirmwareBlob.product_name: str | None` (VARCHAR 128) — add in Phase 1 migration. Populated from `firmware_patterns.yaml` `product` field. Lets UI display "AW88xxx Smart PA audio amplifier" instead of just `raw_bin`.
2. `HardwareFirmwareBlob.product_source: str | None` (VARCHAR 64) — records which YAML entry/source matched, for audit and tuning.

If the above addition is rejected, store these under existing `metadata_` JSONB field.

## File Layout

```
backend/app/services/hardware_firmware/
├── data/
│   ├── vendor_prefixes.yaml          (new Phase 1)
│   └── firmware_patterns.yaml        (new Phase 1)
├── patterns_loader.py                (new Phase 1)
├── kernel_vulns_index.py             (new Phase 4)
├── parsers/
│   ├── mediatek_preloader.py         (new Phase 3)
│   ├── mediatek_modem.py             (new Phase 3)
│   ├── mediatek_lk.py                (new Phase 3)
│   ├── mediatek_wifi.py              (new Phase 3)
│   └── awinic_acf.py                 (new Phase 3)
├── classifier.py                     (refactored Phase 1)
├── cve_matcher.py                    (Tiers 4 + 5 added)
└── known_firmware.yaml               (existing)

backend/app/services/grype_service.py (Phase 2 kernel injection)

scripts/
├── gen_firmware_patterns.py          (optional bootstrap scraper)
└── sync_kernel_vulns.py              (Phase 4 — invoked by arq scheduler)

frontend/src/components/hardware-firmware/
├── PartitionTree.tsx                 (new Phase 5)
├── VendorRollup.tsx                  (new Phase 5)
└── DriverGraph.tsx                   (new Phase 5 — ReactFlow)
```

## New Dependencies

**Pip (Phase 3):**
- `md1imgpy` — via `git+https://github.com/R0rt1z2/md1imgpy` (GPL-3, AGPL-compat). Optional — can be a runtime subprocess if distribution concerns.
- `kaitaistruct` — MIT, for Kaitai-compiled parsers (cyrozap preloader/GFH structs).

**Vendored source trees:**
- `cyrozap/mediatek-lte-baseband-re/SoC/mediatek_preloader.ksy` (GPL-3/CC-BY-SA-4.0) → compiled via kaitai-struct-compiler.
- `cyrozap/mediatek-lte-baseband-re/SoC/mediatek_download_agent.ksy` (same).

**Subprocess tool (optional Phase 3):**
- `kaitai-struct-compiler` (apt) — build-time only if we pre-commit compiled parsers; else runtime dep.

**Data files (Phase 1):**
- `vendor_prefixes.yaml` mirrored from Linux kernel (GPL-2 OR BSD-2).
- `firmware_patterns.yaml` — our own curation + WHENCE excerpt.

## Acceptance Criteria

### Phase 1
- [ ] `firmware_patterns.yaml` exists with ≥40 entries covering MediaTek/Awinic/Bosch/InvenSense/Sensortek/NXP/Mali/MediaTek-ISP.
- [ ] `vendor_prefixes.yaml` exists with ≥200 entries.
- [ ] Re-running detection on DPCS10 Android populates `vendor` on ≥80% of non-kernel-module blobs.
- [ ] `classifier.py` LOC reduced (net — more declarative, less imperative).

### Phase 2
- [ ] `kernel_semver` column/metadata populated on all `.ko` rows.
- [ ] Running `/cve-match` on DPCS10 returns ≥20 CVEs via grype's kernel CPE.
- [ ] `SbomVulnerability` rows for kernel modules have `match_tier="kernel_cpe"`.

### Phase 3
- [ ] Five parser files exist and self-register with PARSER_REGISTRY.
- [ ] Fixture unit tests pass for each parser.
- [ ] A test MediaTek image populates `version`, `chipset_target`, `metadata` for preloader / md1img / LK / Wi-Fi hdr / AWINIC blobs.

### Phase 4
- [ ] `kernel_vulns_index.py` exists; first nightly pull populates Redis.
- [ ] `cve_matcher.py` Tier 5 produces subsystem-scoped matches.
- [ ] `bluetooth.ko` on 6.6.102 produces at least one high-confidence CVE match.

### Phase 5
- [ ] `HardwareFirmwarePage` defaults to tree view; flat table is a secondary tab.
- [ ] `/cdx.json` endpoint returns a CycloneDX v1.6 HBOM that passes schema validation.
- [ ] Driver Graph tab renders firmware edges overlay for DPCS10.

### Cross-phase
- [ ] No regression in Phase-1 campaign tests (60 tests still pass).
- [ ] Typecheck clean: `npx tsc --noEmit` and `ruff check`.
- [ ] README updated with hardware firmware enrichment section.
- [ ] CLAUDE.md rule added if any new learned gotchas surface.

## Risks

1. **`md1imgpy` GPL-3 licensing vs AGPL-3 runtime linking** — AGPL-3 is GPL-compatible upstream so vendoring is OK, but downstream redistribution may need review. Fallback: subprocess the CLI.
2. **Kaitai-compiled Python parsers size** — compiled .py from .ksy can be 1-2K LOC per format; vendor in `parsers/_generated/` to separate hand-written from generated.
3. **`kernel.org vulns.git` at 100 MB** — persistent volume + once-daily pull is fine; if pull fails (offline), Tier 5 falls back to empty list gracefully.
4. **YAML pattern ordering matters** — first-match-wins. Maintain tests that assert specific blobs classify to expected (vendor, product, category).
5. **CycloneDX HBOM v1.6 vs 1.7** — v1.6 is current; v1.7 in draft. Stick with 1.6; revisit when tools stabilize.
6. **Frontend tree view perf** — ReactFlow for 244 blobs is fine, but if we scale to 1000+ blobs a virtualized tree is needed. Out of scope for Phase 5.

## Extensibility

Same plugin + YAML architecture handles:
- **iOS iBoot/IMG4** → `parsers/apple_img4.py` + `firmware_patterns.yaml` entries for `iBoot`, `iBEC`, `SEPFirmware`, `Bluetooth.aoa`, `AppleFirmware`.
- **Samsung Exynos** → existing `shannon_toc` + new entries for `sboot.bin`, `cp_*.bin` paths.
- **Qualcomm beyond MediaTek** → existing MBN parser + new `xbl`-specific metadata extraction.
- **Cisco IOS / Junos** → add per-vendor YARA + patterns.

## References

Full research in `.planning/knowledge/hw-firmware-phase2-{mediatek-parsers,kernel-cve,vendor-corpus,platforms}.md`. Archon reading the phase context should load the matching knowledge file.

## Campaign Tracking

Recommend:
- Dedicated campaign file: `.planning/campaigns/feature-hw-firmware-phase2-enrichment.md`
- 5 phases, estimated 6 sessions
- `/archon feature-hw-firmware-phase2-enrichment` to launch
- Depends on: `feature-android-hardware-firmware-detection` (completed at df02b2d)
