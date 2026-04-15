# APK Security Scanning — Deep Research & Seed Specification

**Date:** 2026-04-14
**Interview ID:** interview_20260414_231546
**Seed ID:** seed_9f99b1d82824
**Ambiguity Score:** 0.195

---

## Summary

Deep research into whether Wairz should integrate MobSF, mobsfscan, or similar mobile security scanning tools. Conducted via Ouroboros interview with extensive web research on tooling, architecture, and validation approaches.

## Key Findings

### MobSF vs Wairz
- MobSF is a full **app security scanner** (Django web app, 1.5GB+ Docker image) — too heavy to integrate as a runtime dependency
- Wairz is a **firmware RE platform** — different mission with partial overlap on Android APK analysis
- The real gaps are manifest security auditing and code pattern SAST, not the full MobSF stack

### mobsfscan (Standalone SAST CLI)
- Works **only on source code** (.java, .kt, .xml), NOT compiled APKs
- 43 semgrep rules + 2 libsast patterns across 9 categories
- Requires semgrep as dependency (Wairz already has semgrep)
- Can scan jadx output directories independently — no MobSF needed
- pip installable, lightweight

### Androguard Bytecode Analysis
- Can detect insecure API calls at DEX bytecode level WITHOUT decompilation
- Uses analysis.find_methods() + xrefto/xrefrom for pattern detection
- Covers ~60% of insecure API patterns (Cipher.getInstance ECB, custom X509TrustManager, WebView misconfigs)
- Cannot detect complex multi-line logic patterns

### jadx Decompilation
- JDK 21 already in Dockerfile (for Ghidra)
- Adds ~15-20MB to Docker image
- 20-40s per APK, 1-2GB RAM per APK
- Output is 3-5x DEX payload size

### False Positive Handling
- Firmware system apps need DIFFERENT FP handling than third-party apps
- Platform-signed components with signatureOrSystem protection get reduced severity
- LAUNCHER activities with intent-filters are intentionally exported
- Flag everything but include confidence levels (high/medium/low)

---

## Architecture Decisions

### Phase 1: Manifest Security Auditing
- **What:** 18 manifest checks matching MobSF's full rule set
- **Where:** Extend existing androguard_service.py (no new dependencies)
- **Trigger:** On-demand MCP tool + REST API + frontend UI (NOT auto during extraction)
- **Output:** Dual — MCP text response for AI + findings written to existing findings system
- **Severity:** Static base per check + context bump (+1 for priv-app, -1 for platform-signed)
- **Confidence:** Each finding includes high/medium/low confidence field

### Phase 2a: Androguard Bytecode Patterns
- **What:** Bytecode-level insecure API call detection
- **Where:** Extend androguard_service.py with find_dangerous_api_calls()
- **Dependencies:** None new (Androguard already installed)
- **Coverage:** ~60% of code-level security patterns

### Phase 2b: jadx + mobsfscan
- **What:** Full decompilation + 43-rule SAST pipeline
- **Dependencies:** jadx CLI (~15MB), mobsfscan (pip)
- **Storage:** AnalysisCache JSONB (same pattern as Ghidra decompilation caching)
- **Lifecycle:** On-demand persistent — lazy decompilation, results cached in DB
- **Granularity:** Per-APK on demand

---

## Validation Plan

### Test APKs
1. **DIVA** — 13 vulnerabilities (insecure logging, hardcoded creds, SQLi, exported components)
2. **InsecureBankv2** — 6 HIGH + 7 WARNING (exported components, AES-CBC zero IV, debuggable)
3. **OVAA** (Oversecured) — 15+ vulns (deeplink exploit, path traversal, hardcoded AES)

### Performance Targets
- Phase 1 manifest checks: < 500ms per APK
- Phase 2a bytecode analysis: < 30s per APK
- Phase 2b full jadx+mobsfscan: < 3 minutes per APK

### Correctness Bar
- Findings must be a **superset** of MobSF manifest-category findings for same APKs
- Zero missed critical/high manifest issues
- False positive rate under 20%

### Methodology
- Cross-reference with MobSF output on same test APKs
- Majority voting across multiple tools for confirmation
- Manual verification of high-priority findings

---

## 18 Manifest Security Checks (Phase 1 Scope)

1. allowBackup misconfiguration (missing or enabled)
2. debuggable mode enabled
3. usesCleartextTraffic enabled
4. testOnly flag detection
5. minSdkVersion below threshold (API 26 = WARNING, API 29 = ERROR)
6. Exported activities without permission guards
7. Exported services without permission guards
8. Exported receivers without permission guards
9. Exported content providers without permission guards
10. StrandHogg 1.0 task hijacking (taskAffinity + launchMode)
11. StrandHogg 2.0 detection
12. Network security config: cleartext traffic allowed
13. Network security config: user certificate trust
14. Network security config: certificate pinning bypass
15. Network security config: domain-specific policy weaknesses
16. App links validation
17. Custom permissions with weak protectionLevel
18. Missing networkSecurityConfig declaration

---

## Seed YAML Location

Generated seed stored in Ouroboros session: seed_9f99b1d82824
Interview session: interview_20260414_231546
