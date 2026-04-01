# Campaign: SBOM/Vuln Phase 1

Status: completed
Started: 2026-03-31
Completed: 2026-03-31
Direction: Install Grype for local vuln scanning, add CycloneDX SBOM export, add firmware type classifier
Type: build

## Phases

| # | Type | Description | Status |
|---|------|-------------|--------|
| 1 | build | Install Grype in backend Dockerfile (multi-arch) | complete |
| 2 | build | Create GrypeVulnerabilityService | complete |
| 3 | wire | Wire Grype into vuln scan endpoint + config | complete |
| 4 | build | CycloneDX JSON export | already existed |
| 5 | build | Firmware type classifier | complete |

## Decision Log
- Grype 0.87.0 chosen (ARM64 + x86_64 binaries, ~25MB)
- NVD API kept as fallback via VULNERABILITY_BACKEND config
- CycloneDX export already existed — no work needed
- Firmware classifier added: linux_rootfs_tar, linux_blob, elf_binary, intel_hex, pe_binary
- ELF binaries skip filesystem extraction (bare metal path)

## Feature Ledger
- [x] Grype installed in Dockerfile (multi-arch)
- [x] grype_service.py with scan_with_grype()
- [x] Vuln scan endpoint uses Grype by default
- [x] Config: vulnerability_backend, grype_db_cache_dir, grype_timeout
- [x] classify_firmware() with 5 firmware types
- [x] ELF binary path skips extraction
- [x] detect_architecture_from_elf() for single-binary analysis
