---
Status: completed
Direction: Execute the full Wairz feature roadmap — Phases 1-5 from master plan
Estimated Sessions: 8
Type: build
---

# Campaign: Wairz Full Roadmap

## Direction

Ship the complete Wairz feature roadmap: quick wins, Android/compliance tooling,
autonomous assessment, infrastructure hardening, and emulation expansion.
Sourced from `.planning/intake/next-session-plan.md`.

## Phases

| # | Type | Description | Status |
|---|------|-------------|--------|
| 1 | build | Unblob primary extractor swap | complete (already first) |
| 2 | build | SPDX SBOM export endpoint | complete (already exists) |
| 3 | build | Kernel .config analysis MCP tool | complete (already exists) |
| 4 | build | Capa binary capability detection | complete (already exists) |
| 5 | build | Dependency-Track SBOM push | complete (already exists) |
| 6 | verify | Phase 1 verification | complete (all pre-existing) |
| 7 | build | Androguard APK analysis + VEX documents | complete (already exists) |
| 8 | build | Compliance (ETSI) + SELinux + Semgrep | complete (already exists) |
| 9 | build | Autonomous assessment + report generator | complete (already exists) |
| 10a | build | Background job queue (arq) | complete (already exists) |
| 10b | build | API key authentication | complete (already exists) |
| 10c | build | Binary dependency graph | complete (already exists) |

## Feature Ledger

| Feature | Phase | Status | Files |
|---------|-------|--------|-------|
| Unblob primary extractor (already first) | 1 | done | `unpack.py` |
| PE binary fast path + standalone binary fallback | 1 | done | `unpack.py` |
| SPDX 2.3 export | 2 | done | `routers/sbom.py` |
| check_kernel_config + extract_kernel_config | 3 | done | `tools/security.py` |
| detect_capabilities + list_binary_capabilities | 4 | done | `tools/binary.py` |
| push_to_dependency_track | 5 | done | `tools/sbom.py` |
| analyze_apk + check_apk_signatures (androguard) | 7 | done | `tools/android.py` |
| VEX export (CycloneDX VEX) | 7 | done | `routers/sbom.py` |
| check_compliance (ETSI EN 303 645) | 8 | done | `tools/security.py` |
| analyze_selinux_policy + check_selinux_enforcement | 8 | done | `tools/security.py` |
| scan_scripts (Semgrep) | 8 | done | `tools/security.py` |
| run_full_assessment + generate_assessment_report | 9 | done | `tools/reporting.py` |
| arq job queue with fallback | 10a | done | `workers/arq_worker.py`, `routers/firmware.py` |
| API key auth middleware | 10b | done | `middleware/auth.py`, `main.py` |
| Component dependency graph | 10c | done | `services/component_map_service.py` |

## Decision Log

| Decision | Reason |
|----------|--------|
| All phases pre-existing | Prior sessions (1-8) already implemented the entire roadmap |
| Campaign completed in 1 session | Verification-only — no new code besides standalone binary fix |
| Standalone binary fix added | Bug: single binary uploads (malware samples) failing with "no filesystem root" |

## Completion Summary

The entire 5-phase roadmap was already implemented across 8 prior sessions.
This campaign verified that all features exist and are registered. The only new
code was a bug fix for standalone binary uploads (PE fast path + small file fallback).
