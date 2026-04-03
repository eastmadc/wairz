# Patterns: Android SBOM Enhancement Campaign

> Extracted: 2026-04-03
> Campaign: .planning/campaigns/android-sbom.md
> Postmortem: none

## Successful Patterns

### 1. Directory-name detection over manifest parsing for initial inventory
- **Description:** APK inventory used directory names and file presence rather than parsing AndroidManifest.xml. This was sufficient for SBOM component listing without adding Androguard as a dependency.
- **Evidence:** Decision Log: "Used directory-name-based APK detection — sufficient for inventory." 62 APKs detected on MediaTek firmware.
- **Applies when:** Building initial inventory of embedded components where full parsing would require heavy dependencies. Ship the 80% solution first, add deep parsing later.

### 2. Multi-partition scanning for Android firmware
- **Description:** Android firmware has multiple partition images (system, vendor, product). Syft scanning was extended to scan all partitions, not just the first extracted root.
- **Evidence:** 418 total components (290 Syft + 128 Android-specific) across multiple partitions.
- **Applies when:** Any analysis tool that needs to see the full firmware. Always check for multiple partition roots, not just the top-level extracted path.

### 3. Minimal init.rc parsing for SBOM
- **Description:** Parsed only service name + binary path from init.rc files, ignoring class/options/triggers.
- **Evidence:** Decision Log: "class/options ignored as not useful for SBOM." 64 init services extracted with minimal parser.
- **Applies when:** Parsing config files for inventory purposes. Extract only what the consuming feature needs. Full parsing can be added when a feature requires it.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Directory-name APK detection | Avoid Androguard dependency for v1 | Correct — 62 APKs found, version extraction deferred |
| Minimal init.rc parsing | SBOM needs name+path only | Correct — 64 services, no wasted complexity |
| SELinux by directory presence | Policy content analysis not needed for SBOM | Correct — binary presence/absence is sufficient |
