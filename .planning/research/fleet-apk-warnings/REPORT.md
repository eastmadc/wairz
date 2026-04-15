# Research Fleet: APK Security Scanning Warning Fixes

> Question: Correct approaches for fixing 5 code review warnings in the APK security scanning implementation
> Date: 2026-04-14
> Scouts: 3 across 1 wave
> Confidence: high

## Consensus Findings

All 3 scouts agree on their respective domains:

1. **Platform signing detection** must use manifest heuristics (`_has_signature_or_system_protection()`), not debug-signing negation
2. **Priv-app path detection** must check actual partition prefixes (system/, product/, vendor/, system_ext/), not just "priv-app" anywhere in path
3. **androguard_service.py** at 3,375 lines is 2.6x the next largest service (sbom_service at 2,318) and should be split
4. **_APK_DIRS/_find_apk()** are byte-for-byte identical across 3 files — extract to shared helper
5. **Pydantic models** should go to `schemas/apk_scan.py` per the project convention (9/10 routers use schemas/)

## Conflicts

None — all scouts produced consistent findings.

## Key Findings by Angle

### Angle 1: Android priv-app & platform signing detection
- `_is_priv_app_path()` should match `[partition]/priv-app` where partition is system, product, vendor, or system_ext
- Platform signing detection should call `_has_signature_or_system_protection()` from the service (3-tier heuristic: declared permissions, requested platform permissions, shared UID)
- Keep privilege detection (path-based) and platform signing (manifest-based) as separate signals
- Severity bump uses privilege level; severity reduction uses platform signing confirmation

### Angle 2: Code organization
- androguard_service.py: 3,375 lines (outlier; next largest is 2,318)
- Split boundary: keep core APK analysis in androguard_service.py, extract manifest security checks to new file
- No existing shared helper pattern in ai/tools/ — creating _android_helpers.py is a first but appropriate

### Angle 3: Router conventions
- 9/10 Wairz routers import models from schemas/ — apk_scan.py should follow suit
- Create schemas/apk_scan.py with all response models
- Eliminates forward reference issue and follows project convention

## Recommendation

Fix all 5 warnings:
1. Fix `_is_priv_app_path()` to check partition/priv-app pairs
2. Replace debug-signing negation with `_has_signature_or_system_protection()` call
3. Extract `_APK_DIRS`/`_find_apk()` to `_android_helpers.py`
4. Split manifest checks out of androguard_service.py into manifest_checks.py
5. Move apk_scan Pydantic models to schemas/apk_scan.py

## Open Questions

None — all findings are clear and actionable.
