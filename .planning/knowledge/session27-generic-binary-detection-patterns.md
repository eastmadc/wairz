# Patterns: Session 27 — Generic Binary Version Detection

> Extracted: 2026-04-10
> Commit: cbad4ee on clean-history
> Work: Generic fallback detector in sbom_service.py, SBOM gap analysis across 5 tools

## Successful Patterns

### 1. Empirical tool comparison before building
- **Description:** Tested rssh detection against 5 real tools (Syft, Trivy, Grype, cve-bin-tool, Wairz) on actual firmware before writing any code. Confirmed 0/5 detect it. This validated the gap is real and industry-wide, not just a Wairz issue.
- **Evidence:** All 5 tools returned 0 rssh matches on project 98180e8b firmware.
- **Applies when:** Before building any detection/scanning feature, test what existing tools actually do with real data.

### 2. Filename-anchored regex for false positive control
- **Description:** Instead of a generic `{word} {semver}` pattern (high false positive rate), anchored the regex to the binary's own filename. This means `rssh 2.3.4` is only matched when scanning `/usr/bin/rssh`, not when that string appears inside some other binary.
- **Evidence:** sshd binary contains `OPENSSL_1.0.1` and `GLIBC_2.4` — both correctly filtered because they don't match `sshd` filename.
- **Applies when:** Any string-based detection where the target string can appear in unrelated contexts.

### 3. Three-layer false positive defense
- **Description:** Combined three independent filters: (L1) exclude known library/symbol prefixes, (L2) require filename match, (L3) CPE dictionary validation. Each layer catches different false positive types.
- **Evidence:** 15 generic detections, 3 CPE-validated, 0 false positives from library deps.
- **Applies when:** Building any heuristic detection system where precision matters.

### 4. Confidence tiering with promotion
- **Description:** Generic detections start at "low" confidence (below curated patterns at "medium"). If NVD CPE dictionary validates the product exists, confidence promotes to "medium". This prevents generic detections from displacing higher-quality ones.
- **Evidence:** rssh promoted from low→medium after NVD found `cpe:2.3:a:pizzashack:rssh:2.3.4`.
- **Applies when:** Adding new detection heuristics that are less reliable than existing methods.

### 5. Debugging scan limits with position analysis
- **Description:** When rssh wasn't detected despite the code being correct, diagnosed by counting the binary's alphabetical position vs MAX_BINARIES_SCAN. Discovered rssh was at position ~201 while limit was 200.
- **Evidence:** `psplash-default` was the 200th binary scanned; rssh comes after alphabetically.
- **Applies when:** Any scanning system with a limit — always verify that the target is within the scan window.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Raise MAX_BINARIES_SCAN from 200 to 500 | 200 was insufficient for firmware with 300+ ELF binaries in /usr/bin alone | rssh now scanned; ~336 binaries in this firmware |
| Generic detections at "low" confidence by default | Avoid displacing curated "medium" confidence detections | Clean separation; promotion on CPE validation |
| Exclude `lib*` prefix names entirely | Library deps (libcrypto, libssl) appear inside many binaries as dependency strings | Eliminates ~80% of false positives |
| One detection per binary in generic fallback | Multiple matches per binary increase false positive risk | First valid match wins; sufficient for SBOM |
| Yocto suffix name support (hexdump.util-linux → util-linux) | Yocto-built firmware uses compound filenames with package as suffix | Correctly detects util-linux 2.25.2 from hexdump binary |
