# Wairz Master Plan

> Created: 2026-04-01
> Updated: 2026-04-13 (session 35 — production hardening, comparison tests, bugfix, campaign cleanup)
> Resume with: /do continue

---

## Session 35 Handoff (2026-04-13)

**What was done:**
1. Committed S34 upload fix (`92f3dc4`) — MAX_UPLOAD_SIZE_MB 500→2048
2. Production hardening of docker-compose.yml:
   - Log rotation (json-file, 50m/5 files) on all 8 long-running containers
   - Frontend healthcheck (wget against nginx)
   - Backend healthcheck (curl against /health)
   - Backend + worker memory limits (4096M each)
   - Redis sysctl (net.core.somaxconn=511) + host vm.overcommit_memory=1 documented
3. Comparison service unit tests — 61 tests covering:
   - diff_filesystems (10 tests: added/removed/modified/permissions/edge cases)
   - diff_text_file (6 tests: basic diff, identical, added, removed, large, truncation)
   - is_diffable_text (8 tests: extensions, binary detection, path matching)
   - _extract_function_hashes (6 tests: extraction, hashing, stripped binary)
   - _extract_section_hashes (4 tests)
   - _extract_imports/exports (5 tests: including shared lib exports)
   - _extract_basic_blocks (4 tests: Capstone block splitting)
   - diff_binary integration (6 tests: function diff, stripped fallback)
   - diff_function_instructions (5 tests: Capstone assembly diffs)
4. **Bugfix found by tests:** LIEF API `is_imported`/`is_exported` renamed to `imported`/`exported` in LIEF 0.15+ — import/export extraction was silently broken
5. Campaign housekeeping: binary-diff-enhancement + security-hardening moved to completed/
   - YARA Phase 1 marked done (4990 rules verified S34)
   - Binary diff phases and feature ledger updated to done

---

## Blocked
- Device Acquisition v2 Phase 10 — needs physical MediaTek device in BROM mode

## Project Status After S35
- Campaigns: 15/15 completed (only Device Acquisition v2 Phase 10 hardware-blocked)
- MCP tools: 160+
- Stack: deployed and production-hardened on x86_64 Ubuntu 22.04
- Test suite: 463+ tests (61 new for comparison service)
- Upload limit: 2GB
- YARA scanning: verified (4990 rules)

## Remaining Work (priority order)
1. CI/CD pipeline improvements (Phase 5.2) — SARIF output, severity thresholds
2. Docker image size optimization
3. Pre-existing test failures to fix: test_android_sbom (version format), test_yara_service (empty rules dir)
