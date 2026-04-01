# Campaign: Android SBOM Enhancement

Status: completed
Started: 2026-04-01
Completed: 2026-04-01
Direction: Add Android-aware SBOM generation — APK inventory, build.prop metadata, init services, multi-partition scanning
Estimated sessions: 1
Type: build

## Phases

| # | Type | Description | Status | End Conditions |
|---|------|-------------|--------|----------------|
| 1 | build | APK inventory + build.prop + init services scanner | done | Commit d7402ba — `_scan_android_components()` with APK, build.prop, init.rc, kernel module, SELinux scanning |
| 2 | build | Multi-partition Syft scanning | done | Multi-partition Syft added in same commit. 418 total components on MediaTek firmware (290 Syft + 128 Android-specific) |
| 3 | verify | Test on MediaTek firmware | done | Verified: 62 APKs, 64 init services, 1 build.prop (Android 15), 1 SELinux policy. 13 unit tests passing. |

## Decision Log
- Used directory-name-based APK detection (not manifest parsing) — sufficient for inventory, version extraction deferred to future Androguard integration
- init.rc parsing extracts service name + binary path only — class/options ignored as not useful for SBOM
- SELinux detected by directory presence, not policy content analysis

## Feature Ledger
- `_scan_android_components()` in sbom_service.py (lines 734-820)
- `_parse_build_prop()` in sbom_service.py (lines 822-879)
- `_parse_android_init_rc()` in sbom_service.py (lines 881-911)
- 13 tests in `tests/test_android_sbom.py`

## Continuation State
Campaign complete. Future enhancement: Androguard for APK manifest parsing + version extraction.
