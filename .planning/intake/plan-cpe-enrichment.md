# Plan: SBOM CPE Enrichment Across All Firmware Types

**Priority:** High | **Effort:** Medium (~10h) | **Status:** pending
**Route:** `/ouroboros:interview` → `/citadel:archon` (3 phases)

## Problem

SBOM components from Syft/custom scanners often have auto-generated garbage CPEs
(e.g., `cpe:2.3:a:bluetooth:bluetooth:2.22`) that don't match NVD entries.
Vulnerability scanning returns 0 results for most components because Grype can't
match them. Only components with correct CPEs (linux-kernel, android, openssl) produce
real vulnerability results.

**Proven impact:** Adding proper kernel CPE went from 0 vulns → 2,891 vulns on the
DPCS10 MediaTek firmware. Most firmware has similar blind spots.

## What Needs to Change

### Phase 1: Known-Good CPE Mapping Database
Build a mapping of common firmware component names → correct CPEs:
- **Kernel modules** → `cpe:2.3:o:linux:linux_kernel:{version}`
- **BusyBox** → `cpe:2.3:a:busybox:busybox:{version}`
- **OpenSSL/LibreSSL** → `cpe:2.3:a:openssl:openssl:{version}`
- **OpenWrt packages** → map to upstream CPEs
- **Android framework** → `cpe:2.3:o:google:android:{version}`
- **U-Boot** → `cpe:2.3:a:denx:u-boot:{version}`
- **dnsmasq, dropbear, lighttpd, nginx** → standard CPEs
- **Common IoT libraries** (libcurl, zlib, libpng, etc.)

### Phase 2: Multi-Partition SBOM Scanning
Currently `SbomService` only scans `extracted_root` (one partition).
For Android firmware with 8+ partitions, it misses vendor, product, system_ext.
- Scan all extracted partitions, not just the root
- Deduplicate across partitions
- Track which partition each component came from

### Phase 3: CPE Enrichment Post-Processing
After SBOM generation, run an enrichment pass:
- Match component names against known-good CPE database
- For unmatched components with versions, attempt fuzzy CPE lookup
- For kernel modules, inherit kernel version CPE from parent kernel
- For Android APKs, check `AndroidManifest.xml` for `targetSdkVersion`
- Store enrichment source in component metadata

## Key Files
- `backend/app/services/sbom_service.py` — main SBOM generation
- `backend/app/services/grype_service.py` — Grype integration
- `backend/app/workers/unpack_android.py` — partition extraction

## Impact
- All firmware types benefit (Linux, Android, UEFI)
- Grype goes from 0 results → thousands of real CVEs
- Existing scan infrastructure unchanged (Grype, NVD)
