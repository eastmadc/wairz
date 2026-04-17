---
title: "Feature: Extraction Integrity — Fix systemic data-loss across unpack pipeline + downstream consumers"
status: pending
priority: critical
target: backend/app/workers/, backend/app/services/hardware_firmware/, backend/app/services/sbom_service.py, backend/app/services/yara_service.py, backend/app/ai/tools/, backend/app/models/firmware.py
estimated_sessions: 5
source: Citadel research-fleet-wairz-data-loss-audit (2026-04-17, 4 scouts)
research_bundle: .planning/research/fleet-wairz-data-loss-audit/
---

## Overview

Post-Phase-2 live validation discovered that `md1dsp.img` + 20 other partition images from DPCS10 Android uploads are invisible to the hardware-firmware detector. A 4-scout research-fleet confirmed this is **systemic**, not a one-off:

- **12 silent-drop sites** in the extraction pipeline (`unpack_android.py`, `unpack_common.py`, `arq_worker.py`).
- **13+ downstream consumers** blind to sibling partition dirs — including every MCP filesystem tool, yara, SBOM, security audit, and multiple scanners.
- **~1,218 undetected blobs** across the existing 10-firmware sample = **2.5× the current 490-blob corpus**.
- Three firmware rows have **zero detected blobs** — pre-detector uploads that were never re-scanned.
- Every MediaTek parser landed in Phase 3 (preloader, lk, modem, awinic, wifi_hdr) has **never fired on real data**.

## Why This Is Priority Zero

- Every post-detection feature (CVE matcher Tier 1-5, HBOM, vendor rollup) runs on incomplete data.
- Phase 3 parser work is *dormant code* that only executes after this fix.
- Every new firmware class we add (iOS IPSW, Qualcomm TEE, etc.) will inherit this bug unless we fix the root architecture first.
- User-reported: "holy shit this was a huge gap, where else are we not getting the data."

## Research Bundle

All findings live at `.planning/research/fleet-wairz-data-loss-audit/`:
- `REPORT.md` — synthesis + recommendation (this campaign intake lifts from it).
- `upstream-extraction-gaps.md` — Scout 1, 12 silent-drop sites with file:line.
- `downstream-consumer-audit.md` — Scout 2, 13+ affected consumers.
- `live-db-audit.md` — Scout 3, concrete per-firmware orphan counts.
- `architectural-fix-design.md` — Scout 4, Option A/B/C/D analysis → Option A chosen.

## Architectural Fix (Option A from Scout 4)

Generalize the existing `_pick_detection_root()` helper at `backend/app/workers/unpack.py:52-68` from returning a single string to returning a list:

```python
# backend/app/services/firmware_paths.py (new)
def get_detection_roots(firmware: Firmware) -> list[str]:
    """Return every directory under the firmware storage dir that contains
    extracted content the detector / SBOM / YARA / MCP tools should walk.

    For Android OTA: [rootfs_path, sibling_partition_image_dir, any other raw-image siblings]
    For Linux nested: [outermost extract dir, any intermediate levels with bootloader markers]
    For single-image: [extracted_path]
    For APK: [extracted_path]

    Results are cached in Firmware.device_metadata['detection_roots'] JSONB.
    """
```

Every consumer that currently walks `firmware.extracted_path` migrates to iterate over `get_detection_roots(firmware)` instead.

## Phase Structure

### Phase 1 — Stop the Bleeding (1 session, ~300 LOC)

Upstream fixes that prevent data from landing in unreachable / deleted locations in the first place.

**Deliverables:**

1. **Remove 1 MB minimum-size filter** (`unpack_android.py:429-430`, `unpack_android.py:323-324`). Real partition stubs can be <1 KB.
2. **Stop `os.remove()` after mount failure** (`unpack_android.py:457, 476, 483`). Keep the raw image so parsers can still extract metadata without mounting.
3. **simg2img output verification** — after converting sparse→raw, check file size is non-zero AND matches the sparse header's declared total size AND magic bytes are not all-zero.
4. **Stop `.unknown` chunk deletion** in `cleanup_unblob_artifacts` (`unpack.py`). These are exactly where hw-firmware parsers should look.
5. **Preserve scatter-zip version subdir** (`unpack_android.py:416-418`) — exact code path for DPCS10. Either relocate files into rootfs/ OR leave them where they are and let Phase 2's helper include the dir.
6. **Recursive nested-archive extraction** — `unpack_common.py` should detect `.tar.md5`, nested `.zip`, `.lz4` within extracted content and recurse.

**End conditions:**
- Unit test: `_pick_extraction_outputs` returns all files from a DPCS10-shaped scatter fixture, including 528-byte and 2-KB stubs.
- Integration test: re-upload a DPCS10 fixture; all 21 partition images land in the extracted tree.
- No existing regression: 192/192 hw-firmware tests + all Android unpack tests still pass.
- Ruff clean on touched files.

### Phase 2 — `get_detection_roots()` Helper + JSONB Cache (1 session, ~250 LOC)

**Deliverables:**

1. **`backend/app/services/firmware_paths.py`** (new, ~150 LOC):
   - `get_detection_roots(firmware: Firmware) -> list[str]` — main entry.
   - Per-firmware-type dispatch (android_ota, android_sparse, linux_rootfs_tar, apk, etc.) with content-derived fallback.
   - Cache results in `firmware.device_metadata["detection_roots"]` JSONB.
   - Includes `get_primary_root(firmware)` helper returning the first root for callers that need scalar path.
2. **Unit tests** (`backend/tests/test_firmware_paths.py`, new, ~200 LOC):
   - DPCS10-shaped fixture → returns `[rootfs, DPCS10-dir]`.
   - ACM-shaped nested fixture → returns walked-up-to-bootloader-marker dir.
   - Single-image fixture → returns `[extracted_path]`.
   - No-extracted-path firmware → returns `[]` gracefully.
3. **Backfill-ready helper** `invalidate_detection_roots(firmware)` — clears the JSONB cache so a re-run recomputes from disk state.

**End conditions:**
- `pytest tests/test_firmware_paths.py` — all pass.
- Helper covers all firmware types in `Firmware.firmware_type` enum.
- Ruff clean. Type checker clean (mypy/basedpyright if configured).

### Phase 3a — Migrate Core Consumers (1 session, ~400 LOC diff)

**Deliverables:**

1. **`services/hardware_firmware/detector.py`** — signature change from `extracted_path: str` to `walk_roots: list[str]` (or detector calls the helper internally given a firmware_id). Walks each root sequentially, merges results.
2. **`services/sbom_service.py`** — replace `self.extracted_root` usage with multi-root iteration via helper.
3. **`services/yara_service.py`** — multi-root YARA scan; dedupe by SHA-256.
4. **`services/security_audit_service.py`** — multi-root audit. **Also fix `_scan_android_apps`** to walk `system/app`, `system/priv-app`, `product/app`, `vendor/app`, `system_ext/app`, `vendor/priv-app`.
5. **`services/file_service.py`** — virtual root exposes ALL detection roots as top-level dirs (not just `*-root`-matching). Fix `_ROOT_DIR_PATTERN` accordingly.
6. **Integration test** — run detection on a restored DPCS10 firmware fixture, assert `mtk_preloader` / `mtk_lk` / `mediatek_modem` parsers populate version/signed/metadata on their target blobs.

**End conditions:**
- Full hw-firmware regression + new integration test pass.
- Typecheck clean.

### Phase 3b — Migrate MCP + Scanner Consumers (1 session, ~400 LOC diff)

**Deliverables:**

1. **`ai/tools/filesystem.py`** — `list_directory`, `read_file`, `search_files`, `find_files_by_type` respect multi-root. MCP path resolution uses `get_detection_roots` + sandbox.
2. **`ai/tools/binary.py`** — binary analysis MCP tools walk all roots.
3. **`ai/tools/strings.py`** — string extraction covers all roots.
4. **`services/assessment_service.py`** — all 7 phases walk multi-root.
5. **`services/update_mechanism_service.py`** — multi-root.
6. **`services/component_map.py`** — multi-root.
7. **`services/clamav_service.py`, `virustotal_service.py`, `abusech_service.py`** — multi-root. (Note VT/abusech 50-200 file caps may need bumping — flag if observed.)

**End conditions:**
- All MCP tool tests pass.
- Scanner tests pass.
- Adjacent integration: a yara scan + MCP `find_files_by_type` on DPCS10 sees the partition images.

### Phase 4 — Backfill + Verification (0.5 sessions)

**Deliverables:**

1. **Script `backend/scripts/backfill_detection.py`**:
   - For each Firmware row: invalidate cached `detection_roots`, re-compute, re-run `detect_hardware_firmware` on full root list, re-run CVE matcher.
   - Idempotent: existing blobs dedup via `(firmware_id, blob_sha256)` unique constraint.
   - Dry-run mode: report expected deltas without writing.
2. **Run it in-session** against the 10 existing firmware rows.
3. **Verification**:
   - DB scalar: `HardwareFirmwareBlob.count` grows by ≥ 800 (conservative vs scout 3's 1,218 estimate).
   - DPCS10 ROWS show MediaTek vendor + parsed metadata on preloader/lk/modem blobs.
   - CVE matcher tier `kernel_cpe` now produces matches on kernel modules where `linux-kernel` SbomComponent exists.
4. **Feature ledger entry** — "Recovery report: +N blobs, +M CVE matches from backfill on N firmware rows."

**End conditions:**
- Backfill script exits 0 on all 10 firmware rows.
- Per-row delta reported.
- No ORM integrity violations (no cascade failures from stale extracted_path).

### Phase 5 — Observability + Regression Guard (0.5 sessions)

**Deliverables:**

1. **Per-firmware extraction audit**:
   - New `Firmware.device_metadata["detection_audit"]` field or new `firmware_detection_audit` table. Stores `{total_files_on_disk, files_under_detection_roots, orphan_count, orphan_sha256_list}` at detection time.
   - `/api/v1/.../firmware/{id}/audit` endpoint returns the audit.
2. **Alert on orphan ratio > 5%** — log + expose via `/admin` or similar (non-blocking).
3. **CLAUDE.md Learned Rule #16** — "When walking a Firmware extraction, always use `get_detection_roots(firmware)`, never `firmware.extracted_path` alone."
4. **Harness quality rule** `auto-extraction-roots-no-direct-extracted-path`:
   ```json
   {
     "pattern": "firmware\\.extracted_path",
     "filePattern": "backend/app/services/**/*.py",
     "message": "Use get_detection_roots(firmware) instead of firmware.extracted_path — single-path walks miss sibling partition images (DPCS10 class of bug, 2026-04-17)."
   }
   ```
   Allowlist: `firmware_paths.py`, `unpack*.py` (they're the producers).
5. **README / CLAUDE.md update** — document the helper + where to use it.

**End conditions:**
- Harness quality rule registered.
- Audit endpoint live.
- CLAUDE.md updated.
- `grep -rn "firmware\.extracted_path" backend/app/services/ | grep -v firmware_paths.py` returns 0 results.

## Data Model

- No new tables. Uses existing `Firmware.device_metadata` JSONB column for `detection_roots` cache + optional `detection_audit` audit log.
- Optional Phase 5 deliverable: new `firmware_detection_audit` table if preferring relational over JSONB — flag in Decision Log.

## Acceptance Criteria (campaign-wide)

- [ ] DPCS10 detection: ≥90% of partition images (preloader, lk, md1dsp, tee, scp, sspm, spmfw, dtbo, cam_vpu*) are classified as hardware firmware AND parsed by their respective format parser.
- [ ] Backfill produces ≥800 new blob rows across the 10-firmware sample.
- [ ] CVE matcher `kernel_cpe` tier produces ≥1 match on kmods that belong to a firmware with a linux-kernel SbomComponent.
- [ ] `get_detection_roots(firmware)` is called by every filesystem-walking consumer; direct `firmware.extracted_path` use is gated by the harness rule to only unpackers + the helper itself.
- [ ] Full hw-firmware regression suite passes at ≥192 (baseline from Phase 2 campaign).
- [ ] Frontend typecheck clean.
- [ ] Ruff clean on all touched backend files.
- [ ] CLAUDE.md Learned Rule #16 added.

## Risks

1. **Performance:** Walking multiple roots multiplies I/O. Mitigation: cache `detection_roots` result; dedup by SHA-256 inside detector (already done).
2. **Migration double-walk:** Consumers that composed `extracted_path` with sub-paths (`os.path.join(fw.extracted_path, "system/bin")`) need careful migration. Audit in Phase 3a.
3. **Breaking changes for external callers:** If any external script uses the Firmware REST API expecting `extracted_path` to be authoritative, they'll need updating. Acceptable — no external users today.
4. **Sparse-image verification false positives:** `simg2img` Phase 1 fix must not reject legitimate all-zero holes in sparse images. Test against real OpenWrt sparse fixture.
5. **Backfill long-running:** 10 firmware × detection + CVE matcher could take 10-30 minutes. Run as a background script, not inline.

## Extensibility

Every future firmware class added to Wairz (iOS IPSW, Qualcomm firehose, OpenWrt sysupgrade, RISC-V OpenTitan) automatically inherits multi-root detection once its unpacker writes the roots into the JSONB cache. No per-class consumer updates needed.

## References

- Full research: `.planning/research/fleet-wairz-data-loss-audit/REPORT.md` + 4 scout briefs.
- Dormant Phase 3 parsers: `backend/app/services/hardware_firmware/parsers/{mediatek_preloader, mediatek_lk, mediatek_modem, awinic_acf, mediatek_wifi}.py` — finally get to run after this campaign.
- CLAUDE.md conventions this campaign reinforces: rules 4 (schema/model sync), 7 (async-session safety), 9 (frontend Record exhaustiveness), 11 (integration test after refactor).

## Campaign Tracking

- Campaign file: `.planning/campaigns/feature-extraction-integrity.md` (Archon will create).
- 5 phases, estimated 5 sessions (may compress if P3a+P3b fit in one session).
- Launch via `/archon feature-extraction-integrity`.
- Takes priority over queued LATTE, Tier-1-security, VEX campaigns — they all benefit from correct extraction.
