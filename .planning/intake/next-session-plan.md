# Next Session Plan

> Created: 2026-04-01
> Updated: 2026-04-01 (session 2 completed P1-P5)
> Resume with: /do continue

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
