# Wairz Master Plan

> Created: 2026-04-01
> Updated: 2026-04-06 (session 11 — CycloneDX 1.7, SSE event bus, unpack log viewer)
> Resume with: /do continue
> Plans: .planning/intake/plan-*.md (6 detailed plans for all remaining items)

---

## Status Overview

**Campaigns:** 8 completed, 1 blocked (Device Acq v2 — needs hardware), 1 blocked (UEFI Phase 4 — needs firmware images)
**Architecture Review:** Complete. 6 critical fixed, 9 warnings fixed, 23 backlog.
**Roadmap:** Phases 1-4 fully implemented. Phase 5 (expansion) is the remaining frontier.
**Tests:** 379 backend, 0 frontend. All passing.

---

## Completed (verified 2026-04-04)

All of these are implemented and in the codebase. Do NOT re-implement.

### Phase 1: Quick Wins
- [x] Unblob primary extractor (already first in fallback chain)
- [x] SPDX 2.3 SBOM export (`routers/sbom.py` — `_build_spdx_response()`)
- [x] Kernel .config analysis (`tools/security.py` — `check_kernel_config`, `extract_kernel_config`)
- [x] Capa binary capability detection (`tools/binary.py` — `detect_capabilities`, `list_binary_capabilities`)
- [x] Dependency-Track SBOM push (`tools/sbom.py` — `push_to_dependency_track`)

### Phase 2: Android + Compliance
- [x] Androguard APK analysis (`tools/android.py` — `analyze_apk`, `check_apk_signatures`)
- [x] VEX document generation (`routers/sbom.py` — CycloneDX VEX export)
- [x] Compliance reporting ETSI EN 303 645 (`tools/security.py` — `check_compliance`)
- [x] SELinux policy analysis (`tools/security.py` — `analyze_selinux_policy`, `check_selinux_enforcement`)
- [x] Semgrep script scanning (`tools/security.py` — `scan_scripts`)

### Phase 3: Autonomous Assessment
- [x] Assessment orchestrator (`tools/reporting.py` — `run_full_assessment`)
- [x] Assessment report generator (`tools/reporting.py` — `generate_assessment_report`)
- [x] Secure boot chain analysis (`tools/security.py` — `check_secure_boot`)

### Phase 4: Infrastructure Hardening
- [x] arq background job queue (`workers/arq_worker.py`, `docker-compose.yml` worker service)
- [x] API key authentication (`middleware/auth.py`, configurable via `API_KEY` env var)
- [x] Binary dependency graph (`services/component_map_service.py`, `ComponentMapPage.tsx`)
- [x] PE binary fast path + standalone binary fallback (`unpack.py` — session 9 fix)

---

## Remaining Work

### Frontend Gaps (no dedicated session needed — fix when touching adjacent code)

| # | Item | Effort | Notes |
|---|------|--------|-------|
| F1 | **CVE triage workflow UI** | Medium | Expandable vuln rows, inline VEX status buttons, bulk triage. Backend VEX tools exist, frontend doesn't expose them. |
| F2 | **Expose MCP tools in UI** | Large | "Security Tools" page with buttons to trigger scans (kernel config, secure boot, capa, SELinux, Semgrep, ETSI, full assessment). All backend tools exist. |
| F3 | ~~**Show unpack log for successful extractions**~~ | ~~Small~~ | **COMPLETE** (session 11). Collapsible log viewer for all firmware in ProjectDetailPage. |
| F4 | **Frontend E2E tests (Playwright)** | Medium | No frontend tests exist. Basic smoke test: create project → upload → explore → scan → findings. |

### Phase 5: Emulation + Expansion (2-3 sessions)

**Goal:** Match EMBA's automated emulation. Expand to new firmware types.

| # | Item | Effort | Notes |
|---|------|--------|-------|
| 5.1 | ~~**Automated system emulation**~~ | ~~Large~~ | **COMPLETE** (session 10). FirmAE sidecar, Flask shim, 8 MCP tools, mode toggle UI. E2E verified with OpenWrt Archer C7 MIPS. |
| 5.2 | **CI/CD pipeline integration** | Medium | GitHub Action `wairz-scan`. Inputs: firmware URL or artifact. Outputs: SBOM, findings, compliance status, pass/fail gate. |
| 5.3 | **RTOS/bare-metal recognition** | Large | Detect FreeRTOS, Zephyr, VxWorks, ThreadX from binary patterns. Version extraction. Basic SBOM generation. |
| 5.4 | **Network protocol analysis** | Large | Capture pcap from emulated firmware. Service fingerprinting. Depends on 5.1. |
| 5.5 | ~~**CycloneDX v1.7 / HBOM**~~ | ~~Small~~ | **COMPLETE** (session 11). Upgraded all exports to CycloneDX 1.7 (ECMA-424). HBOM device metadata in main component. Tools format updated. |
| 5.6 | ~~**WebSocket/SSE event bus**~~ | ~~Small~~ | **COMPLETE** (session 11). SSE push for unpacking/fuzzing/emulation events. useEventStream hook. Polling reduced to 5-10s fallback. |

---

## Review Backlog (P3 — fix when touching adjacent code)

| # | Item | Files | When |
|---|------|-------|------|
| R1 | Split emulation_service.py (1637 lines) | `services/emulation_service.py` | When touching emulation (Phase 5) |
| R2 | Split FileViewer.tsx (846 lines) | `components/explorer/FileViewer.tsx` | When touching explorer UI |
| R3 | Split ProjectDetailPage.tsx (593 lines) | `pages/ProjectDetailPage.tsx` | When touching project page |
| R4 | Add Error Boundary to React app | `App.tsx` | With frontend tests (F4) |
| R5 | Centralize duplicated status/severity configs | `utils/statusConfig.ts` | When touching frontend |
| R6 | ~~Add missing DB indexes~~ | ~~Done (session 8)~~ | ~~Complete~~ |
| R7 | Add pagination to list_projects, list_documents | `routers/projects.py`, `routers/documents.py` | When touching those endpoints |
| R8 | Standardize error handling hierarchy | All services | Opportunistic |
| R9 | Standardize commit pattern across routers | All routers | Opportunistic |
| R10 | Standardize firmware resolution pattern | `routers/deps.py` | When touching routers |
| R11 | Show unpack log for successful extractions | `pages/ProjectDetailPage.tsx` | → Moved to F3 above |

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
