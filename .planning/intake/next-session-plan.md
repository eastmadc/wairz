# Next Session Plan

> Created: 2026-04-01
> Updated: 2026-04-03 (session 4 — zip bomb prevention + campaign housekeeping)
> Resume with: /do continue

## Session 4 Completed

### Campaign Housekeeping
- Closed Security Hardening campaign (phases 2-3 done, phase 4 tests done, YARA deferred)
- Marked Device Acquisition v2 as blocked (phases 1-9 done, phase 10 needs manual hardware test)
- Verified P2 Flow Robustness: concurrent unpack race (SELECT FOR UPDATE) and disk space check (shutil.disk_usage) were already implemented in prior sessions

### Zip Bomb Prevention (P2 remaining item)
- Added 3 config settings: max_extraction_size_mb (10GB), max_extraction_files (500K), max_compression_ratio (200:1)
- Added `check_extraction_limits()` in unpack_common.py — post-extraction validator using recursive os.scandir
- Added `check_tar_bomb()` in unpack_linux.py — pre-extraction tar member inspection
- Added pre-extraction ZIP bomb check in firmware_service.py `_extract_archive()`
- Integrated guards at all 5 extraction points in unpack.py (Android OTA, partition dump tar, rootfs tar, binwalk, unblob)
- Wrote 18 tests (all passing): 8 for check_extraction_limits, 6 for check_tar_bomb, 4 for ZIP extraction

### SquashFS Extraction Fix (bug found during SBOM comparison investigation)
- **Root cause:** Dockerfile used devttys0/sasquatch fork which failed silently on ARM64 (-Werror build flags)
- **Fix:** Switched to onekey-sec/sasquatch fork (maintained by unblob team), added liblz4-dev + libzstd-dev build deps
- Added 5 missing unblob extractor deps: lz4, zstd, lziprecover, unar, partclone
- All 15/15 unblob external dependencies now satisfied (was 10/15)
- Verified fix: re-extracted test11 firmware → SquashFS rootfs now properly extracted (11,840 files vs 287)
- Re-generated SBOM: test11 now has 319 components (was 9) and 2,415 vulns (was 19) — matches test4 reference

## Session 3 Completed

### Quality Sprint (this session)
- Fixed 6 bare exception handlers (fuzzing_service, firmware_service, emulation_service) — added exc_info=True and diagnostic logging
- Extracted 95-line embedded shell script from emulation_service.py to `backend/app/templates/wairz_init_wrapper.sh`
- Refactored VulnerabilitiesTab: extracted 15 props to Zustand store (`stores/vulnerabilityStore.ts`), reduced to 2 props
- Investigated N+1 queries — already safe (explicit JOINs in place)

### Research Fleet (this session)
- 3 parallel agents investigated: tool ecosystem gaps, security assessment gaps, architecture quality
- Top findings: YARA integration (CRITICAL), Unblob validation (HIGH), Androguard (HIGH)
- Competitive gap vs EMBA: missing malware detection, SELinux/AppArmor, firewall analysis
- 36 exception handlers audited, 11 services identified with zero test coverage

### Device Acquisition v2 Campaign (this session)
- Deep research on MTKClient (bkerler/mtkclient): 100+ chipsets, subprocess wrapping, USB VID:PID detection
- Qualcomm EDL: recommend import-only (75-85% of devices block unsigned firehose)
- Full campaign plan written: `.planning/campaigns/device-acquisition-v2.md` (10 phases, 4-6 sessions)

## Session 5 Priorities

### P1: YARA Malware Scanning (Security Hardening Phase 1)
- Needs yara-python dependency in backend + Dockerfile change
- 30+ built-in rules for firmware backdoors/malware
- `scan_with_yara` MCP tool

### P2: Frontend Polish
- VulnerabilitiesTab already extracted to Zustand (session 3) — verify in browser
- Test file search UI in browser
- Test Load More button on vuln page

### P3: Progress reporting for long extractions
- Binwalk/unblob fallback chain can take 30+ min
- Frontend shows no progress during extraction — just "unpacking"

### P4: Squash clean-history branch
- Many commits need squashing into logical groups
- Push to fork

### P5: Android A/B OTA testing
- payload-dumper-go installed but untested with real A/B OTA
- Needs Pixel OTA download

### P6: Device Acquisition v2 — Phase 10
- Manual hardware test with real MediaTek device
- Blocked until hardware available

### P5: Remaining Android Campaign
- A/B OTA testing (needs Pixel firmware download)
- boot.img extraction (not started)

## Priority 1: Vuln UI + Data Quality — DONE (session 2)

### A. Vuln list pagination — DONE
- Added Load More button with limit/offset pagination in SbomPage.tsx
- Wired up limit/offset params in frontend API client (api/sbom.ts)

### B. Filter Grype false positives — DONE
- Added CPE vendor extraction + mismatch filtering in grype_service.py
- Skips vulns where Grype vendor (e.g. "adobe") doesn't match component vendor (e.g. "google")

### C. CVE detail readability
- NOT DONE — expandable rows deferred (lower priority, existing modal works)

## Priority 2: Android Campaign Completion — MOSTLY DONE (session 2)

### A. Android ZIP detection in upload flow — DONE
- Added `_is_android_firmware_zip()` to firmware_service.py
- Android ZIPs now preserved intact for unpack pipeline

### B. Partition naming — DONE
- Added `_identify_partition_by_content()` to unpack.py
- Renames partition_N_fstype to system/vendor/product based on contents

### C. A/B OTA testing — NOT DONE
- payload-dumper-go installed but untested with real A/B OTA
- Needs Pixel OTA download to verify

## Priority 3: Stabilize + Test (1 session, /fleet)

### A. Squash and push clean history
- 18 commits on clean-history branch need squashing into logical groups
- Push to fork, consider which commits are ready for upstream PRs

### B. Run test suite — DONE (session 2)
- 209 tests passing (169 existing + 25 new Android + 15 other)
- 10 pre-existing failures (sandbox/registry tests from prior changes)
- Added test_firmware_classification.py (12 tests) and test_android_sbom.py (13 tests)

### C. Clean slate test
- docker compose down -v && docker compose up --build
- Upload embedded Linux firmware → verify everything still works
- Upload Android firmware → verify full pipeline
- Run SBOM + vuln scan on both

## Priority 4: Quality Loops (per-session, /improve)

These are independent and can be done anytime:

### A. /improve backend/app/services/emulation_service.py
- 115-line embedded shell scripts should be external files
- First ouroboros/improve loop target

### B. /improve backend/app/workers/unpack.py
- File is now very large after Android additions
- Could split into unpack_linux.py, unpack_android.py, unpack_common.py

### C. /improve frontend SBOM page
- VulnerabilitiesTab receives 12 props (code smell from review)
- Component state management could use Zustand store

## Priority 5: Features (future sessions)

### A. Unblob as secondary extractor
- Handles 78+ formats vs binwalk's ~30
- Encrypted D-Link, QNAP, EROFS, etc.

### B. Androguard integration
- Deep APK analysis (permissions, activities, intents, receivers)
- Would enrich the APK inventory significantly

### C. Search functionality (GitHub issue #2)
- File content search in the file explorer
- Backend already has search_files MCP tool

### D. CFS scheduler fix (GitHub issue #15)
- Breaks docker compose on kernels without CPU CFS
- Affects Raspberry Pi deployments

## Citadel Routing Guide

| Task | Command |
|------|---------|
| Resume Android campaign | `/do continue` |
| Vuln UI fixes | `/marshal fix vuln pagination + false positives + readability` |
| Run test suite | `/do test` |
| Quality loop | `/improve emulation_service.py` |
| Clean slate test | `/do test the app with real firmware` |
| Squash + push | `/do commit` then `! git push myfork clean-history:main --force` |
