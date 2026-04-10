# Plan: SBOM CPE Enrichment Across All Firmware Types

**Priority:** High | **Effort:** Medium (~10h) | **Status:** completed (2026-04-07)
**Route:** `/citadel:archon` (3 phases)

## Problem

SBOM components from Syft/custom scanners often have auto-generated garbage CPEs
(e.g., `cpe:2.3:a:bluetooth:bluetooth:2.22`) that don't match NVD entries.
Vulnerability scanning returns 0 results for most components because Grype can't
match them. Only components with correct CPEs (linux-kernel, android, openssl) produce
real vulnerability results.

**Proven impact:** Adding proper kernel CPE went from 0 vulns to 2,891 vulns on the
DPCS10 MediaTek firmware. Most firmware has similar blind spots.

## Current State (verified 2026-04-06)

Session 12 (commit b26930f) delivered:
- **50+ vendor mappings** in `CPE_VENDOR_MAP` dict in `sbom_service.py` (lines 24-100+)
- **Multi-partition Android scanning** -- scans all extracted partitions, not just root
- **4-strategy enrichment post-processor**: exact match, version normalization, library name patterns, binary string extraction

What remains:
- No fuzzy CPE lookup against NVD CPE dictionary
- No kernel module -> parent kernel CPE inheritance
- No APK `targetSdkVersion` -> Android CPE mapping
- No enrichment confidence scoring
- No CPE validation against NVD CPE dictionary (check if CPE actually exists in NVD)

## Phase 1: NVD CPE Dictionary Integration (~4h)

**Goal:** Validate enriched CPEs against the official NVD CPE dictionary and add fuzzy matching.

**Implementation approach:**
1. Download NVD CPE dictionary (JSON feed from `https://nvd.nist.gov/feeds/json/cpematch/1.0/`) at container startup or on first use
2. New service `cpe_dictionary_service.py`:
   - Load CPE dictionary into memory (compressed ~50MB, uncompressed ~300MB)
   - Build inverted index: `product_name -> list[CPE entries]`
   - Exact match: `lookup_cpe(vendor, product, version) -> CPE | None`
   - Fuzzy match: `fuzzy_lookup_cpe(component_name, version) -> list[(CPE, confidence)]`
     - Use `rapidfuzz` library (pip-installable, C-accelerated) for fuzzy string matching
     - Match component names against CPE product names with token_sort_ratio
     - Threshold: confidence >= 85% for auto-enrichment, 70-85% for "suggested" flag
3. Store dictionary in Redis for fast lookup (avoid reloading on every scan)
4. Refresh mechanism: download new dictionary weekly via background task

**Libraries:**
- `rapidfuzz>=3.0` -- fast fuzzy string matching (Levenshtein, token_sort_ratio, partial_ratio)
- `orjson` -- fast JSON parsing for large NVD dictionary file (already a dependency)

**NVD API considerations (2025 reality):**
- NVD stopped enriching most CVEs with CPE data in March 2024
- Only 29% of CVEs published in Jan 2025 had CPE associations
- Local Grype DB is more reliable than NVD API for vulnerability matching
- NVD CPE Dictionary itself is still maintained and useful for CPE validation
- `NVD_API_KEY` env var already supported for higher rate limits

## Phase 2: Kernel Module CPE Inheritance (~2h)

**Goal:** Kernel modules (`.ko` files) inherit the parent kernel version CPE.

**Implementation approach:**
1. During SBOM generation, detect kernel version from:
   - `/proc/version` in extracted filesystem
   - `uname -r` equivalent from kernel binary strings
   - `/lib/modules/{version}/` directory name
   - Build properties (`build.prop` for Android, `.config` for Linux)
2. For every detected `.ko` module, add a `dependsOn` relationship to the kernel component
3. Set CPE to `cpe:2.3:o:linux:linux_kernel:{kernel_version}:*:*:*:*:*:*:*` for the kernel
4. For modules, add the kernel CPE as a "related" CPE (modules share kernel vulnerabilities)

**Key insight:** Kernel modules are part of the kernel attack surface. A CVE in `net/ipv4/tcp.c` affects any firmware running that kernel version, regardless of which modules are loaded.

## Phase 3: Enrichment Confidence Scoring + Validation (~4h)

**Goal:** Track enrichment source and confidence, validate against NVD.

**Implementation approach:**
1. Add `enrichment_source` field to SBOM component metadata:
   - `"exact_match"` -- component name matched CPE_VENDOR_MAP exactly
   - `"version_pattern"` -- version extracted from binary strings
   - `"fuzzy_match"` -- CPE found via fuzzy dictionary lookup (include confidence %)
   - `"inherited"` -- CPE inherited from parent component (e.g., kernel module)
   - `"manual"` -- user-provided CPE override
2. Add `cpe_confidence: float` field (0.0-1.0) to component metadata
3. Validation pass: check each enriched CPE exists in NVD CPE dictionary
   - If CPE exists in dictionary: confidence += 0.2
   - If CPE has known CVEs in Grype DB: confidence += 0.1 (confirms it's a real product)
4. Frontend indicator: show confidence badge on SBOM components (green/yellow/red)
5. MCP tool enhancement: `get_sbom_components` includes enrichment metadata

**Android-specific enrichment:**
- Parse `AndroidManifest.xml` for `targetSdkVersion` -> map to Android API level -> CPE
- Parse `build.prop` for `ro.build.version.release` -> Android version CPE
- Parse `ro.build.version.security_patch` -> security patch level (useful for vuln filtering)

## Key Files

- `backend/app/services/sbom_service.py` -- main SBOM generation + CPE_VENDOR_MAP (extend)
- `backend/app/services/grype_service.py` -- Grype integration (unchanged)
- New: `backend/app/services/cpe_dictionary_service.py` -- NVD CPE dictionary lookup
- `backend/app/workers/unpack_android.py` -- partition extraction (already scans multiple)
- `backend/app/models/sbom.py` -- SbomComponent model (add enrichment metadata fields)
- `backend/app/schemas/sbom.py` -- response schemas (add confidence, source fields)

## Impact

- All firmware types benefit (Linux, Android, UEFI, RTOS)
- Grype goes from 0 results to thousands of real CVEs for most firmware
- Confidence scoring prevents false positive CPE matches from polluting results
- NVD dictionary validation catches garbage auto-generated CPEs before they reach Grype
- Existing scan infrastructure unchanged (Grype, NVD API)

## Acceptance Criteria

- [ ] Fuzzy CPE lookup matches "libssl1.1" to `cpe:2.3:a:openssl:openssl:1.1.*`
- [ ] Kernel modules show inherited kernel CPE with `enrichment_source: "inherited"`
- [ ] CPE confidence scores visible in SBOM component list (frontend badge)
- [ ] NVD CPE dictionary loaded once, cached in Redis, refreshed weekly
- [ ] `rapidfuzz` fuzzy matching with >= 85% threshold for auto-enrichment
- [ ] Android APK `targetSdkVersion` mapped to correct Android CPE
- [ ] No regression in existing CPE_VENDOR_MAP exact matches (50+ mappings)
