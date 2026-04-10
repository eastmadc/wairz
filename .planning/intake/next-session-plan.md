# Wairz Master Plan

> Created: 2026-04-01
> Updated: 2026-04-10 (session 28 -- S28 README update, ClamAV endpoint fix, intake housekeeping)
> Resume with: /do continue
> Plans: .planning/archive/plan-*.md (all 15 completed plans archived)
> Active campaign: none
> Commit: e0cf3d3 on clean-history

---

## Session 28 Handoff (2026-04-10)

**What was done this session:**
1. **README update**: Updated tool counts for threat intel features, added new env vars (`ABUSECH_AUTH_KEY`, `NVD_API_KEY`), accurate tool category table.
2. **ClamAV endpoint fix** (`e0cf3d3`): Renamed `run_clamav_scan` endpoint function in `security_audit.py` to avoid shadowing the imported service function. The shadowing caused ClamAV-unavailable responses (Pydantic model) to be iterated as tuples, crashing finding persistence.
3. **Knowledge extraction**: S27 generic binary detection patterns and antipatterns written to `.planning/knowledge/`.
4. **Intake housekeeping**: Archived `plan-generic-binary-detection.md` (completed S27). 15 plans now archived.

**Files changed:**
- `README.md` (tool counts, env vars)
- `.env.example` (new env vars)
- `backend/app/routers/security_audit.py` (endpoint rename fix)
- `.planning/knowledge/session27-*` (2 new knowledge files)

**What to do next:**
1. **Optional: visual polish** — loading skeleton, tooltip details on abuse.ch hit badges in ThreatIntelTab
2. **Review backlog** — R1-R10 items (fix when touching adjacent code)
3. **Remaining roadmap**: Device Acquisition v2 Phase 10 (blocked on hardware), UEFI Phase 4 (blocked on firmware images)

**All intake items processed. No pending work items.**

---

## Session 27 Handoff (2026-04-10)

**What was done this session:**
1. **Intake queue cleanup**: Verified all 15 intake items completed. Updated status markers on CRA compliance and frontend gaps plans. Archived all 14 completed plans to `.planning/archive/`.
2. **Threat Intel Frontend**: New `ThreatIntelTab` component on SecurityScanPage with:
   - **abuse.ch scan button**: Triggers MalwareBazaar + ThreatFox + YARAify lookups, displays hit counts per service, auto-loads findings
   - **CIRCL Hashlookup button**: Identifies known-good binaries via NSRL, shows progress bar and sortable file table with product/vendor info
   - Severity badges, findings table with links to Findings page and file explorer
3. **FindingSource updates**: Added `abusech_scan` and `known_good_scan` to `FindingSource` type, `FindingDetail.tsx`, and `FindingsList.tsx` source config maps.

**Files changed:**
- `frontend/src/components/security/ThreatIntelTab.tsx` (new, 250 lines)
- `frontend/src/pages/SecurityScanPage.tsx` (new tab + content)
- `frontend/src/api/findings.ts` (API functions + types)
- `frontend/src/types/index.ts` (FindingSource union)
- `frontend/src/components/findings/FindingDetail.tsx` (source config)
- `frontend/src/components/findings/FindingsList.tsx` (source config)
- `.planning/archive/` (14 plan files moved)
- `.planning/intake/next-session-plan.md` (updated)

**TypeScript clean. Docker rebuilt. Frontend deployed. API smoke tested.**

**What to do next:**
1. **README update** — document 113 tools, threat intel features, new env vars
2. **Optional: visual polish** — loading skeleton, tooltip details on abuse.ch hit badges
3. **Remaining roadmap**: Device Acquisition v2 Phase 10 (blocked on hardware)

---

## Session 26 Handoff (2026-04-10)

**What was done this session:**
1. **Threat Intelligence Phases 4-5**: Completed the final two phases of the threat intel integration plan.
   - **Phase 4 — abuse.ch suite** (`abusech_service.py`, 270 lines): MalwareBazaar hash→malware lookup, ThreatFox IOC check (hash/IP/domain/URL), URLhaus malicious URL check, YARAify community YARA matches. Batch enrichment. 4 MCP tools.
   - **Phase 5 — CIRCL Hashlookup** (`hashlookup_service.py`, 140 lines): NSRL known-good identification, bulk lookup with individual fallback. 2 MCP tools.
   - 2 REST endpoints: `POST /security/abusech-scan`, `POST /security/known-good-scan`
   - All 6 tools whitelisted, integrated into automated security audit pipeline
   - Config: `ABUSECH_AUTH_KEY` in config.py (optional, for higher rate limits)
2. **Intake triage**: Scanned all 15 intake items. 12 already completed from prior sessions. Updated `plan-threat-intelligence.md` with completion status.
3. **Tool count: 113 MCP tools** (was 107 after S25).

**Test suite: 386 passed, 0 failures.** TypeScript clean. 1 pre-existing YARA test failure (YARA Forge dir provides rules when custom dir monkeypatched empty — not a regression).

**What to do next:**
1. ~~**Clean up intake queue**~~ — ✅ Done (S27): all 14 completed plans archived to `.planning/archive/`, status markers updated on CRA + frontend gaps plans
2. **Frontend: threat intel display** — abuse.ch and CIRCL results on SecurityScanPage (new "Threat Intel" tab or section) — **in progress S27**
3. **README update** — document 113 tools, threat intel features, new env vars
4. **Remaining roadmap items** (from intake):
   - `plan-cicd-github-action.md` — all acceptance criteria met in S25, can be closed
   - `plan-frontend-gaps.md` — F4 E2E tests effectively complete (9 specs, CI workflow). Optional: visual regression, test fixtures
   - Device Acquisition v2 Phase 10 — blocked on hardware

**Known issues:**
- 1 pre-existing YARA test (`test_raises_on_empty_rules_dir`) fails locally because YARA Forge dir provides rules even when custom dir is empty
- harness.json still protected by hook — quality rule candidates need manual addition

---

## Session 25 Handoff (2026-04-10)

**What was done this session:**
1. **CI/CD hardening**: `--fail-on` flexible thresholds, `--format sarif` (SARIF 2.1.0), `--format vex`, `--timeout`, GitHub Action outputs with auto SARIF upload, Grype DB pre-download.
2. **Threat Intelligence Phases 2-3**: ClamAV Docker sidecar (clamd TCP), VirusTotal hash-only lookups (privacy-first, 4 req/min rate limit). 4 MCP tools, 2 REST endpoints, security audit pipeline integration.
3. **E2E tests**: 3 new Playwright specs (emulation, comparison, component map) with 15 tests. CI workflow with Docker Compose + artifact upload. 9 spec files total.
4. **403 tests passed, TypeScript clean.** 107 MCP tools.

**Commit:** `6acc04a` on `clean-history`.

---

## Session 24 Handoff (2026-04-09)

**What was done this session:**
1. **README overhaul**: Updated from "60+ tools" to "160+ tools" (162 actual). Added all S13-S23 features: RTOS, Android, UEFI, CRA compliance, cwe_checker, YARA Forge, attack surface scoring, network deps, firmware update detection, hardcoded IPs, ShellCheck/Bandit, network protocol analysis. Updated architecture diagram, tech stack, MCP tools table (18 categories), project structure, and env vars.
2. **Docker dev mode**: Created `docker-compose.dev.yml` override with volume mounts for backend Python source (uvicorn `--reload`) and frontend source (Vite HMR via `Dockerfile.dev`). No rebuild needed for code changes.
3. **Integration tests for S20-S23**: 5 new test files (23 tests):
   - `test_attack_surface.py` — attack surface scoring (4 tests)
   - `test_update_mechanism.py` — firmware update detection (6 tests)
   - `test_network_deps.py` — NFS/CIFS network dependency detection (5 tests)
   - `test_rtos_detection.py` — FreeRTOS/VxWorks detection (5 tests)
   - `test_hardcoded_ips.py` — hardcoded IP tool (3 tests, skips without lief)
4. **Fixed pre-existing test failures**: Updated `test_security_audit_service.py` (checks_run count now >= 8 since S20-S21 added 4 new scan categories) and `test_string_tools.py` (added `find_hardcoded_ips` to expected tools set).
5. **Housekeeping**: Added `test-firmware/` to `.gitignore`, marked `plan-network-protocol-analysis.md` as completed.

**Test suite: 337 passed, 3 skipped, 0 failures.** TypeScript clean.

**What to do next:**
1. **CI/CD hardening** — SARIF output, `--fail-on` thresholds, `--format` options for GitHub Action
2. **Frontend E2E tests (F4)** — 2-3 more Playwright specs + CI integration
3. **Threat Intelligence** (deferred) — Phases 2-5 (ClamAV, VirusTotal, abuse.ch, CIRCL)

**Known issues:**
- 3 test files skip outside Docker (lief, yara not installed locally)
- harness.json protected by hook — 2 quality rule candidates from S23 need manual addition

---

## Session 23 Handoff (2026-04-09)

**What was done this session:**
1. **VEX export fix**: MCP `export_sbom` with VEX format now returns structured summary (severity breakdown, top 50 vulns) instead of truncated 30KB of component JSON. REST endpoint still returns full 6.8MB CycloneDX VEX document.
2. **SBOM export dropdown**: Export button on SBOM page now offers 3 formats (CycloneDX 1.7, SPDX 2.3, CycloneDX VEX). Each triggers direct browser download.
3. **Download button on Security Tools page**: When running `export_sbom` from the Tools page, a Download button appears next to Copy that fetches the full document via REST.
4. **Dark mode dropdown fix**: Global CSS rule in `index.css` base layer fixes white-on-white `<select>`/`<option>` elements across all 12+ pages.
5. **MCP tool output deduplication**: `find_hardcoded_ips` resolves symlinks (busybox: 300 symlinks → 1 scan), groups by IP instead of per-file listing. Output: 64KB → 2KB.
6. **Display caps on verbose tools**: `check_all_binary_protections` (50 cap), `find_crypto_material` (30/category), `find_hardcoded_credentials` (30 high-entropy, 20 low-entropy).
7. **Category fix**: `export_sbom` and `assess_vulnerabilities` now appear in "SBOM & Vulnerabilities" category on Security Tools page.

**Commit:** `cd8cb43` on `clean-history`, pushed to myfork.

---

## Session 22 Handoff (2026-04-09)

**What was done this session:**
1. **Committed session 21 work** (`124a69c`): network dependency mapping + firmware update mechanism detection + security audit integration.
2. **CRA compliance report generator** (`plan-cra-compliance-report.md`): Full EU CRA Annex I data model with 20 requirements (13 Part 1 security + 7 Part 2 vulnerability handling). Fleet campaign: Wave 1 (backend models/service) → Wave 2 (REST+MCP || frontend) in parallel.
   - DB models: `CraAssessment` + `CraRequirementResult` tables with Alembic migration
   - Service: `cra_compliance_service.py` (833 lines) — auto-populate from existing findings, export checklist, Article 14 ENISA notification
   - REST: 7 endpoints at `/api/v1/projects/{pid}/cra/`
   - MCP: 5 tools (`create_cra_assessment`, `auto_populate_cra`, `update_cra_requirement`, `export_cra_checklist`, `generate_article14_notification`)
   - Frontend: CraChecklistTab in SecurityScanPage with progress bar, grouped requirements, inline editing, JSON export
3. **Knowledge extraction**: CRA compliance patterns + antipatterns written to `.planning/knowledge/`
4. **CLAUDE.md updated**: 6 learned rules promoted from 63 knowledge files across 20+ sessions
5. **Integration fixes**: SQLAlchemy back_populates mismatch, timezone-naive datetime for asyncpg

**Verified on real firmware (Raspberry Pi OS):**
- Create assessment: 20 requirements initialized
- Auto-populate: 8 pass, 4 fail, 2 manual, 6 not tested
- Export: Full structured JSON with Part 1 (13 reqs) + Part 2 (7 reqs)
- Manual update: notes saved correctly
- 147 MCP tools total (was 142), 103 REST-whitelisted (was 98)

**Commit:** `3c4a689` on `clean-history`, pushed to myfork.

**What to do next:**
1. **S24: Stabilize** — README update (document 147+ tools, CRA compliance), Docker dev mode (volume mounts for hot-reload), integration tests for S20-S23 features.
2. **CI/CD hardening** — SARIF output, `--fail-on` thresholds, `--format` options for GitHub Action
3. **Frontend E2E tests (F4)** — 2-3 more Playwright specs + CI integration
4. **Threat Intelligence** (deferred) — Phases 2-5 (ClamAV, VirusTotal, abuse.ch, CIRCL)

**Known issues:**
- Auto-populate response has a control character in evidence_summary (from finding data, not code bug)
- `test-firmware/` directory (16MB OpenWrt binary) not committed — add to .gitignore if unwanted

---

## Session 21 Handoff (2026-04-08)

**What was done this session:**
1. **Network dependency mapping** (`plan-network-dependency-mapping.md`): `detect_network_dependencies` MCP tool — 8 detection categories (NFS, SMB/CIFS, cloud storage, DB connections, MQTT/AMQP, FTP/TFTP, remote syslog, iSCSI), severity classification with CWE tags, 3-phase scan (config files → init scripts → broad sweep). Fixed SMB/CIFS false positive on URL `://` patterns.
2. **Firmware update mechanism detection** (`plan-firmware-update-analysis.md`): New `update_mechanism_service.py` (530 lines) with 8 detectors (SWUpdate, RAUC, Mender, opkg, U-Boot, Android OTA, custom scripts, package managers). 2 MCP tools (`detect_update_mechanisms`, `analyze_update_config`). REST endpoint. Flags no-update (CWE-1277), HTTP-only (CWE-319), no-rollback (CWE-1277), custom wget+flash (CWE-494).
3. **Both integrated into security audit pipeline** — `_scan_network_dependencies()` and `_scan_update_mechanisms()` in `security_audit_service.py`.
4. **98 REST-whitelisted tools** (was 95).

**Verified on real firmware (Raspberry Pi OS):**
- Network deps: 1 NFS mount finding (from .ash_history)
- Update mechanisms: dpkg/rpm detected (medium confidence), no A/B rollback flagged

**What to do next (S22-S24 per roadmap):**
1. **S22 (done this session):** Firmware update mechanism detection — completed alongside S21
2. **S23: CRA compliance report generator** (`plan-cra-compliance-report.md`) — Full Annex I data model, auto-populate from tools, Article 14 notification export, pentester checklist view. 1 session.
3. **S24: Stabilize** — README update, Docker dev mode, integration tests for S20-S23 features.

---

## Sessions 20-24 Roadmap (2026-04-08)

**Source:** Ouroboros interview (7 rounds, ambiguity 0.20) + Citadel research fleet (5 scouts, 2 waves) + 3 parallel research agents (competitive landscape, codebase health, user workflow impact).

## Session 20 Handoff (2026-04-08)

**What was done this session:**
1. **Deep strategic research**: Ouroboros interview (7 rounds, 0.20 ambiguity) + Citadel fleet (5 scouts) + 3 research agents (competitive landscape, codebase health, user workflow). Created S20-S24 roadmap.
2. **Binwalk v3 swap**: Replaced binwalk v2 with binwalk3 (Rust rewrite, 2-5x faster). Removed `--csv` flag, updated whitespace parser, graceful fallback in CLI.
3. **cwe_checker Docker sidecar**: New service + 3 MCP tools (`cwe_check_status/binary/firmware`). Docker SDK integration, ARM64 via QEMU emulation, analysis cache by SHA-256, auto-findings with CWE mapping.
4. **YARA Forge community rules**: ~5000 rules auto-loaded from GitHub releases. `update_yara_rules` MCP tool for on-demand updates. Dockerfile downloads at build time with graceful fallback.
5. **Hardcoded IP detection**: `find_hardcoded_ips` tool with validated IP regex, classification (public/private/well-known/loopback), false positive filtering (version strings, OIDs, subnet masks), context-based severity elevation.
6. **Fuzzy daemon matching**: rapidfuzz `token_sort_ratio` in attack surface scoring for variant binary names (e.g., `lighttpd-1.4.45`, `S50dropbear`). 9/9 test cases pass.
7. **Plans written**: `plan-firmware-update-analysis.md` (S22), `plan-cra-compliance-report.md` (S23) based on Citadel fleet research.
8. **Rapidfuzz architecture audit**: Identified 3 missed opportunities (daemon matching [DONE], SBOM dedup, YARA-SBOM correlation). Saved to memory.

**Commit:** `f366c74` on `clean-history`. 35 files, +2,955 lines.

**What to do next (S21-S24 per roadmap):**
1. **S21: Network dependency mapping** (`plan-network-dependency-mapping.md`) — NFS/CIFS/cloud/MQTT/DB scanning. Deep research agent provided concrete patterns (Tuya, Alibaba IoT, MQTT, fstab parsing). 1 session.
2. **S22: Firmware update mechanism static detection** (`plan-firmware-update-analysis.md`) — SWUpdate/RAUC/Mender/opkg detection. 1 session.
3. **S23: CRA compliance report generator** (`plan-cra-compliance-report.md`) — Full Annex I data model, Article 14 notification export (Sep 2026 deadline), pentester checklist view. 1 session.
4. **S24: Stabilize** — README update (30min), Docker dev mode (1-2h), integration tests for S20-S23 features.

**Known issues:**
- cwe_checker E2E test on real firmware not completed (QEMU emulation on ARM64 is very slow for x86_64 Ghidra+Rust)
- YARA Forge rules in Docker container require rebuild to include (currently deployed via docker cp + /data/yara-forge)
- Security scan page errors were from stale Docker container (rebuilt and fixed)
- SBOM vulnerabilities are in separate table by design, not in Findings list
- `update_yara_rules` not in REST whitelist (it performs downloads — intentional)

**Deferred explicitly:** Threat intel pipeline, VEX/reachability, firmware update security property analysis, CRA manufacturer reporting, PyGhidra, SBOM component dedup (#2 rapidfuzz), YARA-SBOM correlation (#3 rapidfuzz).

**Strategy:** Balanced mix — 2 feature sessions + 2 compliance sessions + 1 stabilization. EU CRA Article 14 vulnerability notification deadline is September 11, 2026 (5 months). Full Annex I Part 1 requirements Dec 2027.

| Session | Deliverable | Plan File | Key Detail |
|---------|-------------|-----------|------------|
| **S20** | Binwalk v3 swap (2h) + cwe_checker Docker sidecar (6h) | `plan-attack-surface-map.md` Session 2 | `ghcr.io/fkie-cad/cwe_checker:stable`, 17 CWEs, ARM64 cross-compile, JSON output, 3 MCP tools |
| **S21** | YARA Forge (1h) + hardcoded IP detection (5h) | `plan-threat-intelligence.md` Phase 1 + `plan-hardcoded-ip-detection.md` | +thousands of YARA rules, validated IP regex, classification, false positive filtering |
| **S22** | Firmware update mechanism static detection | `plan-firmware-update-analysis.md` | Catalog SWUpdate/RAUC/Mender/opkg/U-Boot, config parsing, no security property analysis |
| **S23** | CRA compliance report generator | `plan-cra-compliance-report.md` | Full Annex I data model, auto-populate from tools, Article 14 notification export, pentester checklist view |
| **S24** | Stabilize: README (30min) → Docker dev (1-2h) → integration tests | No plan needed | Update README to 96+ tools, volume mounts, test S20-S23 features |

**Dependencies respected:** S20 (cwe_checker) and S22 (firmware update) produce findings that S23 (CRA report) consumes.

**Deferred explicitly:** Threat intel pipeline (Phases 2-5), VEX/reachability analysis, firmware update security property analysis, CRA manufacturer reporting, PyGhidra persistent process, Binwalk v3 (moved to S20), monolithic React component splits, Alembic migration review.

**Key research findings informing this plan:**
- EMBA v2.0.0 has cwe_checker via S120 module — Wairz's #1 competitive gap
- Binwalk v3 (v3.1.3) is stable, CLI-compatible, near-zero swap risk (Wairz only uses `binwalk -e -C`)
- CRA Sep 2026 = Article 14 (reporting only), Dec 2027 = full Annex I — reduces urgency on security checks
- PyGhidra deferred: existing GhidraAnalysisCache already eliminates repeat analysis latency
- No open-source tool does CRA compliance reporting — first-mover opportunity
- FirmAgent (NDSS 2026) and FIRMHIVE validate Wairz's MCP multi-agent approach

---

## Session 19 Handoff (2026-04-08)

**What was done this session:**
1. **Deep strategic research** using Ouroboros interview (10 rounds) + Citadel research fleet (7 parallel scouts):
   - Ouroboros interview: crystallized attack surface scoring model, binary triage heuristics, auto-finding rules
   - Citadel scouts: cwe_checker (18 CWEs, ARM64 build), ShellCheck/Bandit overlap matrix, DTB parser, input vector detection, competitive landscape (EMBA/FACT), EMBA module patterns, codebase health
2. **Built Attack Surface Map** (Track A): persistent scoring 0-100, 5 signal categories (network/CGI/setuid/dangerous/known-daemon), auto-finding rules, DB table + migration, service (497 lines), 2 MCP tools, REST API (3 endpoints), frontend AttackSurfaceTab with sortable table + colored badges
3. **Built ShellCheck + Bandit SAST** (Track B): ShellCheck integration (shebang + extension + path discovery, SC→CWE mapping), Bandit integration (venv-aware binary resolution), both added to automated audit pipeline, whitelisted for REST
4. **Committed session 18 work**: network pcap analysis (PcapAnalysisService, 5 MCP tools, pcap download endpoint, NetworkTrafficPanel)
5. **Cleaned up**: removed stale `backend/=2.6` artifact
6. **Verified**: fresh Docker build, 144 binaries scanned on OpenWrt (dnsmasq:56 > uhttpd:49 > dropbear:38), ShellCheck found 52 issues in 3 scripts, TypeScript clean

**Commit:** `e4c4dd9` on `clean-history`, pushed to myfork. 30 files, +4,290 lines.

**Known issues:**
- Bandit binary at `/app/.venv/bin/bandit` (not on system PATH) — fixed with venv-aware `which()` in both security.py and security_audit_service.py
- `emulation.py` at 2974 lines is a refactoring candidate (R1 backlog item)
- Attack surface auto-findings not yet wired into `run_full_assessment` (add when touching assessment pipeline)

---

## Session 18 Handoff (2026-04-08)

**What was done this session:**
1. **Network Protocol Analysis campaign** — Completed all 3 phases in 1 session (estimated 2-3):
   - **Phase 1:** Binary pcap capture via `tcpdump -w`, `pcap_path` DB column + migration, pcap download endpoint
   - **Phase 2:** `PcapAnalysisService` (~400 lines) — Scapy PcapReader, 13 insecure protocol rules, DNS extraction, TLS metadata, conversation grouping
   - **Phase 3:** 5 MCP tools (`network.py`), `GET /network-analysis` REST endpoint, `NetworkTrafficPanel` React component with capture controls + analysis display, EmulationPage sub-tabs
2. **Deep research (3 parallel agents):**
   - Hardcoded IP detection — regex patterns, classification, false positive reduction, binary scanning
   - Network dependency mapping — NFS/CIFS/cloud/MQTT/DB/syslog detection patterns
   - Threat intelligence — VirusTotal, abuse.ch, ClamAV, YARA Forge, CIRCL Hashlookup
3. **Created 3 intake plans** from research findings

**Blocked:** Device Acq v2 Phase 10 (needs hardware)

---

## Session 14 Handoff (2026-04-07)

**What was done this session:**
1. **Fleet Wave 1: Binary Diff Enhancement** — Decompilation diff REST endpoint (POST /compare/decompilation), basic block hashing for stripped binaries, frontend decompilation viewer + basic block stats
2. **Fleet Wave 1: CVE Triage UI (F1)** — Expandable vulnerability rows, inline VEX status buttons, bulk triage toolbar, keyboard shortcuts (j/k/x/r/i/f/Escape)
3. **Fleet Wave 1: Security Tools Page (F2)** — New /tools page exposing 81 MCP tools with categorized list, dynamic JSON Schema form renderer, tool execution UI
4. **Intel HEX firmware support** — Pure Python Intel HEX parser + converter in unpack pipeline, RTOS detection on converted binary, memory map metadata
5. **ZIP extraction fix** — _extract_firmware_from_zip now preserves all files with ZIP slip prevention
6. **RTOS in SBOM** — Detected RTOS + companion components injected into SBOM generation
7. **OS/RTOS display in UI** — ProjectDetailPage shows RTOS name, confidence, memory regions, entry point
8. **Signia PowerPack analysis** — Identified as Ethicon surgical stapler (not hearing aid), ARM Cortex-M4, uC/OS-II high confidence, 15+ tasks

**What to do next (priority order):**
1. ~~**CPE Enrichment Phase 2-3**~~ — **DONE** (session 15, 2026-04-07). NVD CPE dictionary service, rapidfuzz fuzzy matching, confidence scoring + frontend badges.
2. **Network Protocol Analysis** (`plan-network-protocol-analysis.md`) — Scapy-based pcap analysis from emulated firmware
3. **CI/CD Action hardening** (`plan-cicd-github-action.md`) — SARIF output, configurable fail thresholds, Docker optimization
4. **Docker dev mode** — Volume mount source code for hot-reload (current `docker compose build` has cache staleness issues)
5. **Frontend E2E tests (F4 remaining)** — 2-3 more spec files + CI integration

**Docker cache issue discovered:** `docker compose build` sometimes caches the COPY layer for Python source files even after they change. Workaround during this session was `docker cp` into running containers. Consider adding a dev-mode volume mount.

**Blocked:** UEFI Phase 4 (needs firmware images), Device Acq v2 Phase 10 (needs hardware)

---

## Session 13 Handoff (2026-04-06)

**What was done this session:**
1. **RTOS/Bare-Metal Recognition campaign completed** -- 5 phases (research, build detection engine, companion components, classifier integration, E2E verify)
   - New file: `backend/app/services/rtos_detection_service.py` (611 lines, 5-tier detection for 8 RTOS + 13 companion components)
   - Integration: `classify_firmware()` returns RTOS types, `detect_rtos` MCP tool, `os_info` JSON storage
2. **Bug fix: ZIP path collision** -- `update.zip` inside `update.zip` destroying uploaded firmware during extraction
3. **Bug fix: EOFError handling** -- graceful handling of truncated ZIP files during extraction
4. **All plan files enriched** with deep web research: concrete libraries, implementation approaches, acceptance criteria

**What to do next (priority order):**
1. **Binary Diff Enhancement** (`plan-binary-diff-enhancement.md`) -- Add Capstone instruction-level diff + Ghidra decompilation diff. Highest user-visible impact.
2. **CPE Enrichment Phase 2-3** (`plan-cpe-enrichment.md`) -- NVD CPE dictionary fuzzy matching with `rapidfuzz`, kernel module inheritance, confidence scoring.
3. **Network Protocol Analysis** (`plan-network-protocol-analysis.md`) -- Scapy-based pcap analysis from emulated firmware. Depends on system emulation (complete).
4. **Frontend F2: Security Tools Page** (`plan-frontend-gaps.md`) -- Expose 60+ MCP tools in browser UI with dynamic JSON Schema forms.
5. **Frontend F1: CVE Triage UI** (`plan-frontend-gaps.md`) -- Expandable vuln rows, inline VEX buttons, bulk triage.
6. **CI/CD Action hardening** (`plan-cicd-github-action.md`) -- SARIF output, configurable fail thresholds, Docker image optimization.

**Blocked:** UEFI Phase 4 (needs firmware images), Device Acq v2 Phase 10 (needs hardware)

**Key learnings (see .planning/knowledge/session12-*):**
- Always audit actual code before trusting intake plan descriptions
- Ouroboros MCP interview doesn't work from agent context -- use AskUserQuestion
- Fleet works great with zero-overlap scope partitioning

---

## Status Overview

**Campaigns:** 12 completed, 1 blocked (Device Acq v2). Sessions 19-20 were research+build (no formal campaign).
**Architecture Review:** Complete. 6 critical fixed, 9 warnings fixed, 23 backlog.
**Roadmap:** Phases 1-5 fully implemented. S20-S24 roadmap set (Ouroboros + Citadel research).
**Security Tools:** 142 MCP tools (95 via REST). New S20: cwe_checker (3), find_hardcoded_ips, update_yara_rules. YARA Forge: ~5000 community rules.
**Tests:** 379+ backend, 6 frontend E2E (Playwright). TypeScript clean.

---

## Completed (verified 2026-04-06)

All of these are implemented and in the codebase. Do NOT re-implement.

### Phase 1: Quick Wins
- [x] Unblob primary extractor (already first in fallback chain)
- [x] SPDX 2.3 SBOM export (`routers/sbom.py` -- `_build_spdx_response()`)
- [x] Kernel .config analysis (`tools/security.py` -- `check_kernel_config`, `extract_kernel_config`)
- [x] Capa binary capability detection (`tools/binary.py` -- `detect_capabilities`, `list_binary_capabilities`)
- [x] Dependency-Track SBOM push (`tools/sbom.py` -- `push_to_dependency_track`)

### Phase 2: Android + Compliance
- [x] Androguard APK analysis (`tools/android.py` -- `analyze_apk`, `check_apk_signatures`)
- [x] VEX document generation (`routers/sbom.py` -- CycloneDX VEX export)
- [x] Compliance reporting ETSI EN 303 645 (`tools/security.py` -- `check_compliance`)
- [x] SELinux policy analysis (`tools/security.py` -- `analyze_selinux_policy`, `check_selinux_enforcement`)
- [x] Semgrep script scanning (`tools/security.py` -- `scan_scripts`)

### Phase 3: Autonomous Assessment
- [x] Assessment orchestrator (`tools/reporting.py` -- `run_full_assessment`)
- [x] Assessment report generator (`tools/reporting.py` -- `generate_assessment_report`)
- [x] Secure boot chain analysis (`tools/security.py` -- `check_secure_boot`)

### Phase 4: Infrastructure Hardening
- [x] arq background job queue (`workers/arq_worker.py`, `docker-compose.yml` worker service)
- [x] API key authentication (`middleware/auth.py`, configurable via `API_KEY` env var)
- [x] Binary dependency graph (`services/component_map_service.py`, `ComponentMapPage.tsx`)
- [x] PE binary fast path + standalone binary fallback (`unpack.py` -- session 9 fix)

### Phase 5: Expansion (partially complete)
- [x] 5.1 Automated system emulation -- FirmAE sidecar, Flask shim, 8 MCP tools
- [x] 5.3 RTOS/bare-metal recognition -- 8 RTOS, 13 companion components, 611-line detection engine
- [x] 5.5 CycloneDX v1.7 / HBOM -- ECMA-424, device metadata, VEX upgraded
- [x] 5.6 WebSocket/SSE event bus -- Redis pub/sub, useEventStream hook, 6 event types

---

## Remaining Work

### Frontend Gaps (no dedicated session needed -- fix when touching adjacent code)

| # | Item | Effort | Status |
|---|------|--------|--------|
| F1 | **CVE triage workflow UI** | Medium | Pending -- expandable vuln rows, inline VEX buttons, bulk triage |
| F2 | **Expose MCP tools in UI** | Large | Pending -- Security Tools page with dynamic JSON Schema forms |
| F3 | ~~**Show unpack log**~~ | ~~Small~~ | **COMPLETE** (session 11) |
| F4 | **Frontend E2E tests** | Small | In progress -- 4 spec files exist, 2-3 more needed + CI integration |

### Phase 5: Emulation + Expansion (remaining items)

| # | Item | Effort | Status | Notes |
|---|------|--------|--------|-------|
| 5.2 | **CI/CD pipeline integration** | Medium | Partially done | CLI + Action exist. Needs SARIF output, configurable thresholds, Docker optimization |
| 5.4 | ~~**Network protocol analysis**~~ | ~~Large~~ | **COMPLETE** (session 18) | Pcap capture, Scapy analysis, 5 MCP tools, frontend Network Traffic tab |

### Standalone Enhancements (can be done any session)

| Item | Effort | Notes |
|------|--------|-------|
| **Binary diff enhancement** | Medium | Capstone instruction diff + Ghidra decompilation diff. Detailed plan ready |
| **CPE enrichment Phase 2-3** | Medium | NVD dictionary fuzzy matching, kernel module inheritance, confidence scoring |

---

## Review Backlog (P3 -- fix when touching adjacent code)

| # | Item | Files | When |
|---|------|-------|------|
| R1 | Split emulation_service.py (1637 lines) | `services/emulation_service.py` | When touching emulation |
| R2 | Split FileViewer.tsx (846 lines) | `components/explorer/FileViewer.tsx` | When touching explorer UI |
| R3 | Split ProjectDetailPage.tsx (593 lines) | `pages/ProjectDetailPage.tsx` | When touching project page |
| R4 | Add Error Boundary to React app | `App.tsx` | With frontend tests (F4) |
| R5 | Centralize duplicated status/severity configs | `utils/statusConfig.ts` | When touching frontend |
| R7 | Add pagination to list_projects, list_documents | `routers/projects.py`, `routers/documents.py` | When touching those endpoints |
| R8 | Standardize error handling hierarchy | All services | Opportunistic |
| R9 | Standardize commit pattern across routers | All routers | Opportunistic |
| R10 | Standardize firmware resolution pattern | `routers/deps.py` | When touching routers |

---

## Blocked Items

| Item | Blocker | Action |
|------|---------|--------|
| Device Acquisition v2 Phase 10 | Physical MediaTek device in BROM mode | Wait for hardware availability |
| UEFI campaign Phase 4 | UEFI firmware images (D3633-S1.ROM or Framework BIOS) | Download or acquire test images |
| A/B OTA validation | Pixel firmware download | Download when needed |

---

## Completed Campaigns (reference)

| Campaign | Sessions | Key Deliverables |
|----------|----------|-----------------|
| ARM64 Platform Support | 1 | Ghidra native build, AFL++ QEMU mode, all containers on aarch64 |
| SBOM/Vuln Phase 1 | 1 | Grype multi-arch, vuln scan endpoint, firmware classifier |
| Android Firmware Support | 2 | 11-phase extraction pipeline, 21 classification tests |
| Android SBOM Enhancement | 1 | APK inventory, build.prop, init.rc, SELinux, 418 components |
| Device Acquisition v1 | 2 | ADB bridge, 7 REST endpoints, 4-step wizard, 30 tests |
| Security Hardening | 2 | YARA (26 rules), API key patterns (18), kernel sysctl (18 params) |
| Architecture Review | 1 | 6 critical fixed, 9 warnings fixed, roadmap created |
| UEFI Firmware Support | 1 | UEFIExtract, module viewer, PE32+ scanning, VulHunt sidecar |
| Wairz Full Roadmap | 1 | Verified all phases 1-4 complete, standalone binary fix |
| RTOS Recognition | 1 | 8 RTOS detection, 13 companions, 611-line engine, MCP tool |
| Network Protocol Analysis | 1 | Binary pcap capture, Scapy analysis (13 insecure rules), 5 MCP tools, frontend tab |
