# Wairz: Security Assessment & Feature Roadmap

> Date: 2026-04-03
> Based on: GL.iNet GLKVM RM10 real-world assessment, full architecture review, competitive analysis
> Confidence: HIGH (grounded in actual assessment output + competitor feature comparison)

---

## Part 1: Current State Assessment

### What Wairz Produces Today

The GL.iNet GLKVM RM10 assessment demonstrates Wairz's current production capabilities:

| Capability | Evidence from Assessment | Quality |
|---|---|---|
| Firmware extraction (MTD/SquashFS) | 10 partitions identified, rootfs extracted | Strong |
| Credential scanning (shadow/passwd + patterns) | Found empty root password, DingTalk token | Strong |
| Crypto material detection | Found shared VNC private key | Strong |
| Init script / boot service analysis | 81 services inventoried, auth gaps flagged | Strong |
| Binary protection audit | 1,066 ELFs scanned, scored 0-5 | Strong |
| Kernel hardening check | 18 sysctl params, 3/18 secure | Good |
| SBOM generation | 351 components, 246 with CPE | Good |
| CVE scanning (Grype + NVD) | 1,673 CVEs found | Good (needs triage) |
| Filesystem permission audit | setuid/setgid/world-writable | Good |
| Firewall analysis | Empty iptables detected | Basic |
| Report generation | 1000-line structured markdown | Good |

### What the Assessment Reveals Is Missing

The report's Section 2.1 explicitly marks **"Dynamic emulation/validation: Pending"** — the assessment is entirely static. Section 3 lists open-source tools for every finding category, implicitly showing which external tools Wairz should integrate or replicate.

---

## Part 2: Competitive Position

### The Landscape (2024-2026)

| Platform | Status | Architecture | Wairz Advantage | Their Advantage |
|---|---|---|---|---|
| **EMBA** | Very active, v2.0, ~3K stars | CLI + EMBArk web viewer | Interactive UI, MCP AI, fuzzing, UART, device acq | 95% auto-emulation, VEX, SPDX, 70+ modules, Dep-Track |
| **FACT** | Active, Fraunhofer FKIE | Flask web UI + plugins | Modern stack, AI, emulation, fuzzing | Deep firmware comparison, plugin ecosystem |
| **ONEKEY** | Commercial | Cloud platform | Open source, self-hosted | Compliance wizards (CRA/ETSI/IEC), enterprise scale |
| **Trommel/FirmWalker** | Maintenance mode | CLI scripts | Full platform vs single script | Nothing |
| **HALucinator/Fuzzware** | Academic | Research code | Production-ready | MCU/RTOS fuzzing |

### Wairz's Moat: MCP-First Architecture

No competitor offers 60+ tools exposed via Model Context Protocol. This enables:
- Conversational firmware reverse engineering
- Autonomous AI-driven security assessments
- Integration with any MCP-compatible AI (Claude, future GPT integrations)

EMBA's GPT integration is module-level (upload a file, get analysis back). Wairz's approach is fundamentally different — the AI *drives* the analysis interactively.

### Critical Gaps vs EMBA

| Gap | Impact | Effort |
|---|---|---|
| No automated system emulation (EMBA: 95% auto) | Can't validate static findings dynamically | Large (FirmAE integration) |
| No VEX document support | Can't mark false positives permanently | Medium |
| No SPDX export | Blocks US gov/CISA compliance | Small |
| No Dependency-Track integration | No enterprise SBOM lifecycle | Medium |
| No SELinux/AppArmor policy analysis | Missing MAC security assessment | Medium |
| No kernel .config analysis | Only sysctl, not kernel build options | Small |

---

## Part 3: Feature Roadmap

### Tier 0 — Foundation (blocks everything else)

These aren't features users see, but they prevent "demo tool" from becoming "production platform."

| # | Item | Why | Effort |
|---|---|---|---|
| F0.1 | **Authentication (API key + optional OAuth)** | Zero auth = unusable beyond localhost. Multi-user, LAN, or cloud deployment impossible. | Medium |
| F0.2 | **Background job queue (arq + Redis)** | `asyncio.create_task` doesn't survive restarts, has no retry, no observability. Every heavy operation (Ghidra, SBOM, YARA, Grype) needs this. Redis already provisioned. | Medium |
| F0.3 | **WebSocket event bus** | Replace 2s polling with instant push. Reduces load, improves UX for emulation/fuzzing/unpacking status. | Small |
| F0.4 | **Frontend test coverage (Playwright E2E)** | Zero frontend tests. Citadel has `citadel:qa` skill with Playwright. | Medium |

### Tier 1 — Competitive Parity with EMBA

Close the gaps that make users choose EMBA over Wairz.

| # | Item | Why | Effort |
|---|---|---|---|
| F1.1 | **Androguard APK analysis** | Deferred 3+ sessions. Transforms Android from inventory to security assessment. Manifest parsing, permissions, intents, signature verification. | Medium |
| F1.2 | **Unblob as primary extractor** | 78+ formats vs binwalk's ~30. Already a dependency. Session 4 verified all 15 deps satisfied. | Small |
| F1.3 | **SPDX SBOM export** | CISA 2025 requires SPDX 3.0+ or CycloneDX 1.5+. EMBA supports both. | Small |
| F1.4 | **VEX document generation** | Mark CVE false positives permanently. Required by CRA (2027 deadline). CycloneDX VEX or CSAF format. | Medium |
| F1.5 | **Automated system emulation** | EMBA achieves 95% on FirmAE corpus. Current Wairz requires manual QEMU config. Research FirmAE integration or build auto-configuration pipeline. | Large |
| F1.6 | **Dependency-Track SBOM push** | Enterprise standard for continuous vulnerability management. REST API integration. | Small |

### Tier 2 — Differentiation (features no open-source competitor has)

| # | Item | Why | Effort |
|---|---|---|---|
| F2.1 | **Compliance reporting (ETSI EN 303 645 / EU CRA / NIST IR 8259)** | No open-source tool does this. ONEKEY charges enterprise prices. Map findings to framework provisions automatically. The GL.iNet assessment already implicitly maps to ETSI (no default passwords = Provision 1, etc.). | Medium |
| F2.2 | **Autonomous assessment mode** | Leverage MCP architecture: AI agent runs all relevant tools automatically, produces structured report like the GL.iNet one. No user interaction required. The GL.iNet report proves the workflow works manually — automate it. | Medium |
| F2.3 | **SELinux/AppArmor policy analysis** | Parse `sepolicy`, detect overly permissive rules, unconfined domains, missing transitions. No competitor does this well. Android firmware especially. | Medium |
| F2.4 | **Secure boot chain analysis** | Verify UEFI Secure Boot, dm-verity, firmware signing certs. Check for known-weak keys. NSA/CISA published new guidance Dec 2025. | Medium |
| F2.5 | **Capa integration (binary capability detection)** | Mandiant's tool identifies capabilities (C2, anti-analysis, persistence) via rules. Complements YARA (byte patterns) with behavioral detection. Python API available. | Small |
| F2.6 | **Semgrep for firmware scripts** | Static analysis on shell scripts, Lua, PHP/CGI, Python configs. Current analysis is binary-focused. Many firmware vulns are in scripts. | Medium |

### Tier 3 — Forward-Looking

| # | Item | Why | Effort |
|---|---|---|---|
| F3.1 | **RTOS/bare-metal firmware recognition** | FreeRTOS, Zephyr, VxWorks, ThreadX. Even basic recognition + SBOM extraction expands scope significantly. Full emulation is a research problem. | Large |
| F3.2 | **Binary dependency graphing** | Map shared library deps across all binaries. FACT has this. Useful for understanding attack surface propagation. | Medium |
| F3.3 | **CI/CD pipeline integration** | GitHub Actions / GitLab CI for automated firmware security gates. ByteSweep's original (abandoned) vision. | Medium |
| F3.4 | **CycloneDX v1.7 / HBOM** | Hardware Bill of Materials emerging alongside SBOM. Ecma standard (ECMA-424). | Small |
| F3.5 | **Kernel .config analysis (kconfig-hardened-check)** | Beyond sysctl — analyze kernel build options against KSPP/CLIP OS baselines. Extract config from vmlinuz or /proc/config.gz. | Small |
| F3.6 | **Network protocol analysis from emulation** | Capture pcap from emulated firmware, identify services, fingerprint protocols, test authentication. | Large |

---

## Part 4: Prioritized Implementation Plan

### Phase 1: Foundation + Quick Wins (1-2 sessions)

**Goal:** Production-readiness infrastructure + small high-impact features

1. **F0.2** arq job queue — replaces all `asyncio.create_task` for heavy ops
2. **F1.2** Unblob primary extractor — swap extraction order, binwalk as fallback
3. **F1.3** SPDX export endpoint — alongside existing CycloneDX
4. **F3.5** kconfig-hardened-check integration — small MCP tool addition
5. **F2.5** Capa integration — `pip install capa`, new MCP tool

### Phase 2: Android + SBOM Excellence (2-3 sessions)

**Goal:** Close the Android gap, match EMBA on SBOM/compliance

1. **F1.1** Androguard — APK manifest, permissions, intents, signatures
2. **F1.4** VEX document generation — pair with CycloneDX/SPDX exports
3. **F1.6** Dependency-Track push — REST API integration
4. **F2.1** Compliance reporting — ETSI EN 303 645 provision mapping
5. **F2.3** SELinux policy analysis — `sesearch`/`seinfo` on extracted policies

### Phase 3: Autonomous Assessment (2-3 sessions)

**Goal:** The killer feature — AI-driven autonomous firmware security assessment

1. **F2.2** Autonomous assessment mode — orchestrate MCP tools into automated workflow
2. **F0.3** WebSocket event bus — real-time progress for autonomous runs
3. **F2.6** Semgrep for scripts — expand static analysis coverage
4. **F2.4** Secure boot chain analysis — verify firmware signing

### Phase 4: Emulation + Infrastructure (3-4 sessions)

**Goal:** Match EMBA's automated emulation, production-harden

1. **F1.5** Automated system emulation — FirmAE integration or equivalent
2. **F0.1** Authentication — API key + OAuth for multi-user
3. **F0.4** Playwright E2E tests — frontend quality
4. **F3.2** Binary dependency graphing

### Phase 5: Expansion (ongoing)

1. **F3.1** RTOS/bare-metal recognition
2. **F3.3** CI/CD pipeline integration
3. **F3.6** Network protocol analysis
4. **F3.4** CycloneDX v1.7 / HBOM

---

## Part 5: What Makes Wairz Win

The GL.iNet assessment report proves three things:

1. **The AI-driven approach works.** A single session produced a 1000-line report covering 10 findings, 1,673 CVEs, 81 boot services, 1,066 binary protections, and actionable recommendations with open-source tool mappings. No other tool produces this quality of output without significant manual effort.

2. **The MCP architecture is the moat.** Every finding in the report was discovered by an AI agent calling Wairz MCP tools. The tool mapping section (Section 3) shows exactly which traditional tools the AI replicated — but the AI did it in a fraction of the time with conversational context.

3. **The gap is infrastructure, not capability.** The assessment covered 90% of what EMBA covers. The missing pieces (VEX, SPDX, auto-emulation, policy analysis) are additive features, not fundamental architectural gaps. The foundation is solid.

**The path to "definitive open-source firmware security platform" is:**
- Phase 1-2 (foundation + SBOM): Match EMBA's compliance story
- Phase 3 (autonomous assessment): Leapfrog EMBA with AI-native workflows
- Phase 4-5 (emulation + expansion): Close remaining gaps

---

## Sources

- GL.iNet GLKVM RM10 assessment report (produced by Wairz, 2026-04-03)
- Wairz architecture review (6 agents, 188 files, session 8)
- EMBA v2.0 features: https://github.com/e-m-b-a/emba/wiki/Feature-overview
- EMBA 95% emulation: https://www.heise.de/en/news/EMBA-2-0-Firmware-analyzer-achieves-95-percent-emulation-success-11119751.html
- FACT_core: https://github.com/fkie-cad/FACT_core
- CISA 2025 SBOM requirements: https://sbomgenerator.com/compliance/cisa-2025-requirements
- EU Cyber Resilience Act: https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
- CycloneDX v1.7 (ECMA-424): https://github.com/CycloneDX/specification
- ETSI EN 303 645: https://www.etsi.org/technologies/consumer-iot-security
- FIRMHIVE agent-based analysis: https://www.emergentmind.com/topics/firmhive
- LATTE LLM taint analysis: https://dl.acm.org/doi/10.1145/3711816
- FirmAgent (NDSS 2026): https://netsec.ccert.edu.cn/files/papers/ndss26-firmagent.pdf
- ONEKEY compliance: https://www.onekey.com/platform-overview
- NSA/CISA UEFI guidance: https://media.defense.gov/2025/Dec/11/2003841096/-1/-1/0/CSI_UEFI_SECURE_BOOT.PDF
