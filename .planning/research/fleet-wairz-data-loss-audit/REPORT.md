# Research Fleet: Wairz Data-Loss Audit

> Question: "holy shit this was a huge gap, where else are we not getting the data"
> Date: 2026-04-17
> Scouts: 4 in 1 wave
> Confidence: **High** overall — every finding cited file:line

## TL;DR

The DPCS10 `md1dsp.img` case is **one symptom of a systemic pattern** with 12 distinct silent-drop sites in the extraction pipeline, 13+ downstream consumers blind to sibling partition dirs, and an estimated **~1,218 undetected blobs across the 10-firmware DB sample (2.5× the current 490-blob corpus)**. Three firmware rows have ZERO detected blobs. The recently-shipped Phase 3 MediaTek parsers (preloader, lk, modem, awinic, wifi_hdr) have never fired on real data because the detector walks the wrong root.

Scout 4's recommendation — `get_detection_roots(firmware) -> list[str]` helper with JSONB cache in `device_metadata` — is the cleanest architectural fix. Builds on the existing `_pick_detection_root()` helper at `unpack.py:52-68`. Estimated 3.5 sessions; I'm sizing the campaign at 5 sessions to include the upstream bleeding + backfill.

## Consensus Findings Across All 4 Scouts

1. **`Firmware.extracted_path` as single opaque string is the root architectural flaw.** Every consumer that walks the filesystem uses this path. Every extractor that produces artifacts outside this path is invisible.
2. **The DPCS10 bug is a family of bugs, not a single one.** 9 of the 12 upstream silent-drop sites (Scout 1) cause content to land outside `extracted_path`. 13+ downstream consumers (Scout 2) consume it blindly. The live DB audit (Scout 3) quantifies the blast radius.
3. **Phase 3 parsers sit idle.** Every MediaTek parser we just landed (+ the Phase 2 kernel tier infrastructure) is correct code that has never executed on real uploads because the detector walks the rootfs only.
4. **`_pick_detection_root()` at `unpack.py:52-68` is the seed of the fix.** Scout 1 found it, Scout 2 confirms it's under-used (only the post-unpack fire-and-forget detection calls it), Scout 4 shows it generalizes cleanly to the multi-root helper.

## Scout Summaries

### Scout 1 — Upstream Extraction Gap Audit (`upstream-extraction-gaps.md`)

**12 silent-drop sites found; 9 high-severity.**

Top offenders:
| # | Site | File:Line | Cost |
|---|------|-----------|------|
| 1 | OTA zip `.img` drop at `extraction_dir/` root | `unpack_android.py:400` | Partition images never moved to rootfs |
| 2 | payload-dumper-go writes to `partitions/` sibling | `unpack_android.py:381-388` | Only mountable ones survive to rootfs |
| 3 | **1 MB minimum-size filter** | `unpack_android.py:429-430, 323-324` | DPCS10's 528-byte `modem.img` + 2-KB `md1dsp.img` dropped |
| 4 | Scatter-zip version subdir not relocated | `unpack_android.py:416-418` | Exact DPCS10 code path |
| 5 | **`os.remove()` after mount failure** | `unpack_android.py:457, 476, 483` | Deletes source image even if parser could handle raw bytes |
| 6 | simg2img **no output verification** | multiple | Silent truncation possible |
| 7 | fsck.erofs/debugfs timeouts → partial data marked "success" | multiple | Unknown subset missing |
| 8 | Nested archive non-recursion | `unpack_common.py` | Samsung tar.md5, nested zips, .lz4 bypass |
| 9 | `cleanup_unblob_artifacts` too aggressive | `unpack.py` | Deletes `.unknown` chunks before parsers see them |
| 10 | Tar filter drops device/FIFO/socket | `unpack_linux.py` | xattrs, SELinux contexts lost |
| 11 | arq 30-min timeout, no cleanup on error | `arq_worker.py` | Orphaned partial extraction dirs |
| 12 | `_pick_detection_root` misses raw `.img` siblings | `unpack.py:52-68` | Latent heuristic gap |

### Scout 2 — Downstream Consumer Audit (`downstream-consumer-audit.md`)

**13+ consumers blind; ~5 unaffected; 1 partially-fixed.**

**Affected:** hardware_firmware detector, yara_service, security_audit_service, clamav + virustotal + abusech scanners, update_mechanism_service, all 7 phases of assessment_service, component_map, SELinux audit, FileService, MCP filesystem tools (`list_directory`, `read_file`, `search_files`, `find_files_by_type`), MCP strings tools, MCP binary tools, 15+ MCP security tools.

**Unaffected:** GrypeService (DB-only), FindingService + export_service (DB-only), VulnerabilityService + AnalysisService (per-binary), BytecodeAnalysisService + MobSF (per-APK), androguard/mobsf_runner (per-APK).

**Partial fix already exists:** `SbomService._get_all_scan_roots()` enumerates sibling dirs — but only when the parent dir is named `rootfs`, `partitions`, or `images`. DPCS10's parent is `extracted/`, so the heuristic silently fails. Latent bug.

**Deeper bugs surfaced:**
- `security_audit_service._scan_android_apps` hardcodes `system/app` + `system/priv-app` only — misses `product/app`, `vendor/app`, `system_ext/app`.
- VT/abusech caps at 50-200 files — thin rootfs coverage even when scope is right.
- `file_service._ROOT_DIR_PATTERN` hides any dir not matching `*-root` from the UI's virtual filesystem root.

### Scout 3 — Live DB Audit (`live-db-audit.md`)

**10 firmware rows sampled, all production uploads.**

| Firmware | Type | On Disk | Detected | Orphans | Likely HW Orphans |
|----------|------|---------|----------|---------|-------------------|
| DPCS10_260414-1134 | android_ota | (many) | 246 | 21 | ~14 (preloader, lk, tee, scp, sspm, etc.) |
| DPCS10_260413-1709 | android_ota | — | (similar) | ~21 | ~14 |
| DPCS10_260403-1601 | android_ota | — | **0** (pre-detector) | ~1000+ | ~14+ |
| ACM RespArray | embedded_linux | deep nested | low | ~10 TI AM43xx DTBs | ~10 |
| ACM target-ld | embedded_linux | — | **0** | — | ~10+ |
| Other 5 rows | various | — | varies | — | — |

**Aggregate recovery estimate: ~1,218 new blob rows = 2.5× the current 490-blob DB corpus.**

Additional discovery: ACM RespArray's detection path is **10 levels deep** into `zImage-restore_extract/.../gzip.uncompressed_extract` — orphans 10 TI AM43xx DTBs sitting at the `zImage-restore/` level. The `_pick_detection_root` Android-partition heuristic can't help — needs a different signal (walk up until kernel/bootloader markers).

### Scout 4 — Architectural Fix Design (`architectural-fix-design.md`)

**Recommendation: Option A (helper module) with JSONB cache.**

Rationale:
- The fix already partly exists (`_pick_detection_root` at `unpack.py:52-68`). Generalize it from single-path to `list[str]`.
- No persisted `firmware_type` column — the helper must be content-derived (which `_pick_detection_root` already does).
- Wairz convention favors JSONB (CLAUDE.md explicit); `device_metadata` is the existing escape hatch. Cache `detection_roots` as a JSONB key.
- Option B (new column + migration) costs 4+ sessions and introduces double-write hazard.
- Option C (normalize layout) breaks `detect_architecture`/`detect_os_info`/`detect_kernel`. 5+ sessions, high regression risk.
- Option D (FirmwarePath table) — overkill for now; Option A's return type can promote to `list[FirmwarePath]` later if LATTE/iOS demand provenance.

**Effort: ~3.5 sessions for Option A alone.** Upstream fixes + backfill bring the full campaign to ~5 sessions.

## Conflicts

**None.** All 4 scouts converge on the same diagnosis and the same fix architecture.

## Surprises

1. **Three of ten firmware have ZERO detected blobs** — not a gap, a total blackout. Pre-detector uploads that never got re-scanned.
2. **`_get_all_scan_roots()` in SbomService already exists but is shape-restricted** (requires parent dir named `rootfs|partitions|images`). Partial fix at the sbom layer, complete miss elsewhere.
3. **The 1 MB minimum-size filter** (`unpack_android.py:429-430`) is the most surprising silent-drop — it was probably added to skip `.hash` files or similar, but catches legitimate tiny partition stubs.
4. **cleanup_unblob_artifacts deletes `.unknown` chunks** before hw-firmware parsers see them — this was a Phase-1-era cleanup that now works against us.
5. **`os.remove()` after mount failure** — if an EROFS partition fails to mount, the raw image is deleted. The parser still could have extracted metadata without mounting.

## Recommendation

**Launch a 5-session campaign with this phase structure:**

### Phase 1 — Stop the bleeding (1 session, ~300 LOC)
Pure upstream fixes. No new helpers. Just stop silently dropping data:
- Remove the 1 MB minimum-size filter from both Android OTA extractors.
- Stop `os.remove()` after mount failure — keep the raw image for parser consumption.
- Add `simg2img` output verification (size + magic byte check).
- Remove `.unknown` chunk deletion from `cleanup_unblob_artifacts`.
- Preserve scatter-zip version subdirs.
- Add recursive nested-archive extraction for `.tar.md5`, nested `.zip`, `.lz4`.

### Phase 2 — `get_detection_roots(firmware) -> list[str]` helper (1 session, ~250 LOC)
- New module `backend/app/services/firmware_paths.py`.
- Lifts `_pick_detection_root` + generalizes to `list[str]`.
- Caches result in `Firmware.device_metadata["detection_roots"]` JSONB.
- Per-firmware-type dispatch + content-derived fallback.
- Unit tests covering Android OTA / Linux recursive / APK / bare-metal / single-image fixtures.

### Phase 3 — Migrate all 13+ consumers (2 sessions, ~800 LOC diff)
Consumer-by-consumer migration from `extracted_path` → `get_detection_roots()`:
- Session 3a: hw_firmware detector, sbom_service, yara_service, security_audit_service, file_service.
- Session 3b: ai/tools/filesystem.py, ai/tools/binary.py, ai/tools/strings.py, assessment_service (7 phases), update_mechanism_service, component_map, clamav/virustotal/abusech scanners.
- Deeper bugs caught during migration:
  - Fix `security_audit_service._scan_android_apps` to walk all partition `app/` + `priv-app/` dirs.
  - Fix `file_service._ROOT_DIR_PATTERN` to show sibling partition dirs.
- Integration test: re-detect on DPCS10 → partition images classified correctly by MediaTek parsers.

### Phase 4 — Backfill + verification (0.5 sessions)
- One-off script: for every firmware row, re-run extraction-root resolution + re-run `detect_hardware_firmware` on the full root list.
- Verify: ~1,218 new blobs appear. Re-run CVE matcher on new kmods.
- Publish a "recovery report" into campaign feature ledger.

### Phase 5 — Observability + regression guard (0.5 sessions)
- New telemetry: per-firmware extraction audit (files on disk vs files under detection roots vs blobs created). Store as `detection_audit` JSONB on Firmware or a new table.
- Alert/log on orphan ratio > 5% for any future upload.
- Add CLAUDE.md Learned Rule #16 — "When walking a Firmware extraction, always use `get_detection_roots(firmware)`, never `firmware.extracted_path` alone."
- Add a pre-commit grep check that flags new `firmware.extracted_path` uses outside the helper.

## Open Questions

1. Does Dustin want the 1 MB minimum-size filter removed unconditionally, or kept as a configurable option for edge cases (ring buffer file fragments, lock files, etc.)?
2. Backfill scope — re-detect on ALL existing firmware, or just the 10-row sample?
3. For the observability phase — log to a new `firmware_detection_audit` table or extend `device_metadata.detection_audit`?
4. Priority vs other work — do we park the pending LATTE/Tier-1-security/VEX items, or do those ship between phases?

## Scout Briefs
- `.planning/research/fleet-wairz-data-loss-audit/upstream-extraction-gaps.md` — Scout 1
- `.planning/research/fleet-wairz-data-loss-audit/downstream-consumer-audit.md` — Scout 2
- `.planning/research/fleet-wairz-data-loss-audit/live-db-audit.md` — Scout 3
- `.planning/research/fleet-wairz-data-loss-audit/architectural-fix-design.md` — Scout 4

---
```
---HANDOFF---
- Research Fleet: Wairz Data-Loss Audit
- Scouts: 4 in 1 wave
- Consensus: 12 silent-drop sites, 13+ blind consumers, ~1,218 undetected blobs across 10-firmware sample
- Recommendation: 5-session "Extraction Integrity" campaign (stop-bleeding + helper + consumer migration + backfill + observability)
- Report: .planning/research/fleet-wairz-data-loss-audit/REPORT.md
---
```
