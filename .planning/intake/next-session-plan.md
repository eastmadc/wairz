# Wairz Master Plan

> Created: 2026-04-01
> Updated: 2026-04-06 (session 13 -- RTOS recognition completed, plans enriched with research)
> Resume with: /do continue
> Plans: .planning/intake/plan-*.md (6 detailed plans for all remaining items)

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

**Campaigns:** 9 completed (including RTOS recognition), 1 blocked (Device Acq v2), 1 blocked (UEFI Phase 4)
**Architecture Review:** Complete. 6 critical fixed, 9 warnings fixed, 23 backlog.
**Roadmap:** Phases 1-4 fully implemented. Phase 5 (expansion) partially done: 5.1 (system emulation), 5.3 (RTOS recognition), 5.5 (CycloneDX 1.7), 5.6 (SSE event bus) all complete.
**Tests:** 379 backend (353 pass + 1 pre-existing failure), 20 frontend E2E (Playwright). TypeScript clean.

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
| 5.4 | **Network protocol analysis** | Large | Pending | Pcap capture + Scapy analysis + insecure protocol detection. Detailed plan ready |

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
