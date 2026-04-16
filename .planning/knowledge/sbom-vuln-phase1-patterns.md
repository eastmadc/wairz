# Patterns: SBOM/Vuln Phase 1

> Extracted: 2026-04-15
> Campaign: .planning/campaigns/completed/sbom-vuln-phase1.md
> Postmortem: none

## Successful Patterns

### 1. Multi-Arch Binary Installation With Fallback
- **Description:** Grype 0.87.0 installed in Dockerfile with explicit ARM64 + x86_64 binary URLs, selecting the right one based on `dpkg --print-architecture`.
- **Evidence:** Phase 1 complete, works on both platform targets.
- **Applies when:** Installing Go/Rust binaries that ship platform-specific releases.

### 2. Backend Config Toggle for Service Implementations
- **Description:** Used `VULNERABILITY_BACKEND` config variable to switch between Grype (local) and NVD API (remote) for vulnerability scanning, keeping both implementations available.
- **Evidence:** Phase 3 — wired with config, NVD kept as fallback.
- **Applies when:** Replacing an external API dependency with a local tool — always keep the original as a fallback behind a config toggle.

### 3. Skip Extraction for Bare Binary Firmware
- **Description:** Added firmware type classifier that detects ELF binaries and skips filesystem extraction (which would fail or produce garbage). Routes directly to single-binary analysis.
- **Evidence:** Phase 5 — `classify_firmware()` with 5 types, ELF path confirmed.
- **Applies when:** Processing firmware uploads — not all uploads are filesystem images. Detect type first, then choose the appropriate analysis pipeline.

### 4. Check for Existing Functionality Before Building
- **Description:** Phase 4 (CycloneDX export) was planned but discovered the feature already existed in the codebase. Marked as "already existed" and moved on.
- **Evidence:** Phase 4 status: "already existed".
- **Applies when:** Always grep the codebase for existing implementations before building new features. Prevents wasted effort and duplicate code.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Grype 0.87.0 (not latest) | Specific version with known ARM64 + x86_64 binaries | Worked — stable, multi-arch |
| NVD API kept as fallback | Some environments may not have Grype installed or may prefer remote scanning | Correct — provides flexibility without code changes |
| 5 firmware type classifications | Covers the major categories seen in real firmware uploads: rootfs tarballs, raw blobs, ELF binaries, Intel HEX, PE binaries | Sufficient — no gaps reported |
| ELF binaries skip extraction | `binwalk` on a bare ELF produces noise, not a filesystem | Correct — cleaner analysis path for single binaries |
