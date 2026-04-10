# Anti-patterns: Android SBOM Enhancement Campaign

> Extracted: 2026-04-10
> Campaign: .planning/campaigns/android-sbom.md

## Failed Patterns

### 1. Single-Partition Assumption for Android Firmware
- **What was done:** Initial SBOM scanning only processed the top-level extracted path, missing system/vendor/product partitions.
- **Failure mode:** Syft found 290 components from one partition. After enabling multi-partition scanning, 128 additional Android-specific components were found (62 APKs, 64 init services, etc.).
- **Evidence:** Phase 2 added multi-partition Syft scanning. Final count: 418 total vs initial ~290.
- **How to avoid:** Android firmware always has multiple partitions. Any analysis tool must enumerate and scan all extracted partition directories, not just the root.

### 2. Over-Parsing Config Files for Inventory Purposes
- **What was done:** Initial approach considered full AndroidManifest.xml parsing with Androguard for APK inventory.
- **Failure mode:** Not a runtime failure, but would have added a heavy dependency (Androguard) for v1 when directory-name detection was sufficient for SBOM listing.
- **Evidence:** Decision Log: "Used directory-name-based APK detection — sufficient for inventory, version extraction deferred."
- **How to avoid:** For inventory/cataloging, start with the simplest detection method (file presence, directory names). Add deep parsing only when a consuming feature actually needs the parsed data.
