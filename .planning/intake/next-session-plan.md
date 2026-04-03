# Wairz Master Plan

> Created: 2026-04-01
> Updated: 2026-04-03 (session 8 — architecture review + roadmap convergence)
> Resume with: /do continue

---

## Status Overview

**Campaigns:** 6 completed, 1 blocked (Device Acq v2 — needs hardware)
**Architecture Review:** Complete. 6 critical fixed, 9 warnings fixed, 23 backlog.
**Roadmap:** 22 features across 4 tiers, sourced from competitive analysis + real assessment output.
**Tests:** 355+ backend, 0 frontend. All passing.

---

## Phase 1: Quick Wins + Extraction (1 session)

**Goal:** Ship the easiest high-impact items. No new architecture needed.

| # | Item | Source | Effort | What to do |
|---|------|--------|--------|------------|
| 1.1 | **Unblob primary extractor** | F1.2 | Small | Swap extraction order in `unpack.py`: try unblob first, binwalk as fallback. All 15 deps already satisfied (session 4). |
| 1.2 | **SPDX SBOM export** | F1.3 | Small | Add `/api/v1/projects/{id}/firmware/{fw_id}/sbom/export?format=spdx-json` endpoint. Generate SPDX 2.3 JSON from existing component data. |
| 1.3 | **Kernel .config analysis** | F3.5 | Small | New MCP tool `check_kernel_config`. Extract config from vmlinuz (`scripts/extract-ikconfig` pattern) or `/proc/config.gz`. Run against kconfig-hardened-check rules. |
| 1.4 | **Capa binary capability detection** | F2.5 | Small | `pip install flare-capa`. New MCP tool `detect_binary_capabilities`. Run capa on selected binaries, return capability summary. |
| 1.5 | **Dependency-Track SBOM push** | F1.6 | Small | New service method + MCP tool. POST CycloneDX JSON to DT's `/api/v1/bom` endpoint. Config: `DEPENDENCY_TRACK_URL` + `DEPENDENCY_TRACK_API_KEY` in settings. |

**Verification:** Upload test firmware, run full SBOM export in both formats, verify capa on a binary.

---

## Phase 2: Android + Compliance (2 sessions)

**Goal:** Close the Android gap. Start compliance story.

### Session A: Androguard + VEX

| # | Item | Source | Effort | What to do |
|---|------|--------|--------|------------|
| 2.1 | **Androguard APK analysis** | F1.1 | Medium | `pip install androguard`. New `androguard_service.py`. MCP tools: `analyze_apk` (manifest, permissions, intents, activities, receivers, services), `check_apk_signatures`, `list_apk_permissions`. Enrich existing APK inventory in SBOM with version + permissions. |
| 2.2 | **VEX document generation** | F1.4 | Medium | Add VEX status field to `SbomVulnerability` model (`not_affected`, `affected`, `fixed`, `under_investigation`). New endpoint to export CycloneDX VEX or OpenVEX format. MCP tool: `set_vulnerability_status` to triage CVEs. |
| 2.3 | **Frontend: CVE triage workflow** | Backlog | Small | Expandable rows in vuln table showing CVE description + CVSS vector. Inline status buttons (Affected/Not Affected/Investigating). Bulk triage via checkbox select. |

### Session B: Compliance + SELinux

| # | Item | Source | Effort | What to do |
|---|------|--------|--------|------------|
| 2.4 | **Compliance reporting (ETSI EN 303 645)** | F2.1 | Medium | Map existing findings to ETSI's 13 provisions. New MCP tool `check_compliance` + REST endpoint. Provision mapping: no default passwords → Provision 1, vulnerability disclosure → Provision 2, secure updates → Provision 3, etc. Generate compliance report as project document. |
| 2.5 | **SELinux policy analysis** | F2.3 | Medium | New `selinux_service.py`. Parse `sepolicy` binary with `sesearch`/`seinfo` (install in Dockerfile). MCP tools: `analyze_selinux_policy` (permissive domains, unconfined, domain transitions), `check_selinux_enforcement`. |
| 2.6 | **Semgrep for firmware scripts** | F2.6 | Small | `pip install semgrep`. New MCP tool `scan_scripts`. Scan `.sh`, `.lua`, `.php`, `.cgi`, `.py` files with firmware-specific Semgrep rules (command injection, hardcoded paths, eval usage). |

**Verification:** Run full assessment on GL.iNet firmware. VEX triage 50 CVEs. Generate ETSI compliance report. Analyze SELinux from Android firmware.

---

## Phase 3: Autonomous Assessment (1-2 sessions)

**Goal:** The killer feature. AI runs a full assessment without user interaction.

| # | Item | Source | Effort | What to do |
|---|------|--------|--------|------------|
| 3.1 | **Autonomous assessment orchestrator** | F2.2 | Medium | New MCP tool `run_full_assessment`. Orchestrates: credential scan → crypto scan → init script analysis → binary protections → kernel hardening → filesystem permissions → SBOM generation → CVE scan → YARA scan → compliance check. Returns structured findings. The GL.iNet report proves this workflow — automate what the AI already does manually. |
| 3.2 | **Assessment report generator** | F2.2 | Medium | New MCP tool `generate_assessment_report`. Takes all findings + SBOM + compliance results and produces a structured markdown report (matching the GL.iNet report format). Save as project document. |
| 3.3 | **Secure boot chain analysis** | F2.4 | Medium | New MCP tool `check_secure_boot`. Detect U-Boot verified boot, dm-verity, UEFI Secure Boot. Parse certificate chains. Check for known-weak signing keys. |
| 3.4 | **WebSocket event bus** | F0.3 | Small | Replace polling with Server-Sent Events or WebSocket push for: unpacking progress, emulation status, fuzzing stats, assessment progress. Pub/sub via Redis. |

**Verification:** Upload a firmware image, invoke `run_full_assessment`, get a complete report without any other manual steps.

---

## Phase 4: Infrastructure Hardening (1-2 sessions)

**Goal:** Production-readiness for multi-user and LAN deployment.

| # | Item | Source | Effort | What to do |
|---|------|--------|--------|------------|
| 4.1 | **Background job queue (arq)** | F0.2 | Medium | `pip install arq`. Replace all `asyncio.create_task` for heavy ops (Ghidra, SBOM, YARA, Grype, unpack) with arq jobs. Redis already provisioned. Retry logic, timeout, progress tracking. |
| 4.2 | **Authentication** | F0.1 | Medium | API key auth for REST API (header-based). Optional OAuth2/OIDC for web UI. Start simple: single admin API key from env var, upgrade later. |
| 4.3 | **Frontend E2E tests (Playwright)** | F0.4 | Medium | Install Playwright. Write tests for: project create → firmware upload → wait for unpack → explore files → run security scan → view findings → export report. Use Citadel's `citadel:qa` skill. |
| 4.4 | **Binary dependency graphing** | F3.2 | Medium | New MCP tool `map_binary_dependencies`. Parse ELF NEEDED entries for all binaries. Build adjacency graph. Return as ReactFlow-compatible JSON for frontend visualization. |

**Verification:** Full pipeline test with arq queue. Auth-protected API. Playwright tests green.

---

## Phase 5: Emulation + Expansion (2-3 sessions)

**Goal:** Match EMBA's automated emulation. Expand to new firmware types.

| # | Item | Source | Effort | What to do |
|---|------|--------|--------|------------|
| 5.1 | **Automated system emulation** | F1.5 | Large | Research FirmAE integration or build auto-config pipeline. Detect architecture + kernel from firmware, select matching QEMU machine type + kernel, configure network, start container automatically. Target: 50%+ success rate on common router firmware. |
| 5.2 | **CI/CD pipeline integration** | F3.3 | Medium | GitHub Action: `wairz-scan`. Inputs: firmware URL or artifact. Outputs: SBOM, findings summary, compliance status, pass/fail gate. Uses Wairz REST API. |
| 5.3 | **RTOS/bare-metal recognition** | F3.1 | Large | Detect FreeRTOS, Zephyr, VxWorks, ThreadX from binary patterns. Extract version info. Basic SBOM generation. Ghidra analysis works today — add firmware type classification. |
| 5.4 | **Network protocol analysis** | F3.6 | Large | Capture pcap from emulated firmware. Service fingerprinting. Depends on F1.5 automated emulation. |
| 5.5 | **CycloneDX v1.7 / HBOM** | F3.4 | Small | Upgrade CycloneDX export to v1.7 (ECMA-424). Add HBOM (hardware BOM) fields for device metadata. |

---

## Review Backlog (P3 — do when touching adjacent code)

These are from the architecture review. Not worth dedicated sessions — fix opportunistically.

| # | Item | Files | When |
|---|------|-------|------|
| R1 | Split emulation_service.py (1637 lines) | `services/emulation_service.py` | When touching emulation (Phase 5) |
| R2 | Split FileViewer.tsx (846 lines) | `components/explorer/FileViewer.tsx` | When touching explorer UI |
| R3 | Split ProjectDetailPage.tsx (593 lines) | `pages/ProjectDetailPage.tsx` | When touching project page |
| R4 | Add Error Boundary to React app | `App.tsx` | Phase 4 (frontend tests) |
| R5 | Centralize duplicated status/severity configs | `utils/statusConfig.ts` | When touching frontend |
| R6 | Add missing DB indexes | `firmware.sha256`, `emulation_session.firmware_id` | Phase 4 (Alembic migration) |
| R7 | Add pagination to list_projects, list_documents | `routers/projects.py`, `routers/documents.py` | When touching those endpoints |
| R8 | Standardize error handling hierarchy | All services | Phase 4 |
| R9 | Standardize commit pattern across routers | All routers | Phase 4 |
| R10 | Standardize firmware resolution pattern | `routers/deps.py` | When touching routers |

---

## Blocked Items

| Item | Blocker | Action |
|------|---------|--------|
| Device Acquisition v2 Phase 10 | Physical MediaTek device in BROM mode | Wait for hardware availability |
| A/B OTA validation | Pixel firmware download | Download when needed |
| Frida integration | Not prioritized | Defer to Phase 5+ |
| Samsung Odin protocol | Not prioritized | Defer to v3 |
| Qualcomm EDL live acquisition | Research-only, most devices block | Defer indefinitely |

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
| Architecture Review (session 8) | 1 | 6 critical fixed, 9 warnings fixed, roadmap created |

---

## Citadel Routing Guide

| What you want | Command |
|---|---|
| Start Phase 1 quick wins | `/citadel:fleet` with 3 parallel agents (unblob, SPDX, capa) |
| Start Androguard campaign | `/citadel:archon` with phase plan from Phase 2 |
| Run autonomous assessment | After Phase 3: MCP tool `run_full_assessment` |
| Run frontend tests | `/citadel:qa` with Playwright |
| Fix a review backlog item | `/citadel:refactor` on the specific file |
| Check competitive position | `.planning/research/security-assessment-roadmap.md` |
| Check architecture review | Session 8 review output (in conversation history) |
