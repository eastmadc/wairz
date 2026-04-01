# Patterns: Full Session (review → infra → ARM64 → bugs → SBOM → vuln)

> Extracted: 2026-04-01
> Campaigns: review-fixes, infra-improvements, arm64-platform-support, sbom-vuln-phase1
> Fleet sessions: review-fixes, infra-improvements, test-gen

## Successful Patterns

### 1. Test in the real environment, not just syntax checks
- **Description:** After every code change, rebuilt Docker containers and tested against a real firmware upload. This caught issues (tar.xz rootfs detection, absolute symlinks, Ghidra -m32 flag) that syntax checks and code review could never find.
- **Evidence:** 5+ bugs found only through live testing: symlink crash, binwalk vs tarfile, Ghidra build flags, grype_service model mismatch, FindingSource crash
- **Applies when:** Always. Docker rebuild + real firmware test after every significant change.

### 2. Iterative fix-test-fix on firmware extraction
- **Description:** The tar.xz rootfs handling required 4 iterations: initial detection → wrapper directory fix → absolute symlink fix → upload timing fix. Each iteration found a new issue only visible with real firmware.
- **Evidence:** Commits 54f594a → 3e2d5b1 → 8e020ce → c4e9c30
- **Applies when:** Firmware extraction changes. Always test with real firmware containing symlinks, nested dirs, and large file counts.

### 3. Match data model before writing service code
- **Description:** The Grype service was written without reading the SQLAlchemy models first, causing 3 consecutive crashes: `fix_version` not a column, `category` not a column, response schema mismatch. Each required a separate commit to fix.
- **Evidence:** Commits a654ad0, 28bfc24, 3fe4671 — all model alignment fixes
- **Applies when:** Any new service that writes to the DB. Read the model FIRST, then write the service.

### 4. Frontend type unions must match backend source values
- **Description:** Grype created findings with `source="grype_scan"` but the frontend `FindingSource` type union didn't include it. `SOURCE_CONFIG[f.source]` returned undefined, crashing React and making the entire Findings page blank.
- **Evidence:** Commit c687e91 (crash), 4924840 (proper fix: use sbom_scan + add fallback)
- **Applies when:** Any time a backend creates records with new enum/source values. Check all frontend Record<Type, ...> lookups.

### 5. Don't leak implementation details into the data model
- **Description:** Initially used `source="grype_scan"` to distinguish from `source="sbom_scan"`. But both do the same thing — scan SBOM for vulnerabilities. The user doesn't care which tool ran. Using a generic source keeps the model clean and avoids frontend crashes.
- **Evidence:** Commit 4924840 — changed to sbom_scan
- **Applies when:** Adding new backend implementations. If two tools do the same conceptual operation, use the same source/type value.

### 6. Syft + custom scanner hybrid is the right SBOM approach for firmware
- **Description:** Syft handles 30+ package ecosystems (Go, Java, Node, Rust, etc.) but misses firmware-specific patterns (buildroot/yocto markers, binary version strings, service risk). The hybrid approach (Syft first as medium confidence, custom overrides as high confidence) captures both.
- **Evidence:** 90 → 319 components after adding Syft. Custom scanner still provides the firmware-specific 16 components that Syft misses.
- **Applies when:** SBOM generation for embedded firmware. Neither tool alone is sufficient.

### 7. Research before building multi-arch Dockerfiles
- **Description:** ARM64 Ghidra build failed twice (wrong -m32 flag, missing bfd.h) because the build was attempted without understanding Ghidra's Makefile assumptions. Research first would have identified these issues.
- **Evidence:** Phase 1 of arm64 campaign needed 3 iterations
- **Applies when:** Any Dockerfile change that involves building native code from source on a non-x86 platform.

## Anti-patterns

### 1. Writing DB service code without reading the model
- **What was done:** Created grype_service.py with `fix_version`, `category`, `source`, `metadata` columns that don't exist on the actual SQLAlchemy models
- **Failure mode:** 3 consecutive 500 errors, each requiring a separate fix commit
- **Evidence:** Commits a654ad0, 28bfc24, 3fe4671
- **How to avoid:** ALWAYS read the SQLAlchemy model definition before writing any service that creates/updates records. Include model column names in the agent prompt.

### 2. Adding new enum values without checking all frontend consumers
- **What was done:** Added `source="grype_scan"` in backend without checking that the frontend `FindingSource` type and `SOURCE_CONFIG` Record handle it
- **Failure mode:** Entire Findings page crashed (blank/black screen) because SOURCE_CONFIG returned undefined for unknown source
- **Evidence:** Commit c687e91 (crash fix), then 4924840 (proper fix)
- **How to avoid:** Search for all `Record<EnumType, ...>` in frontend when adding new enum values. Add fallback to all strict Record lookups.

### 3. Using subprocess piping that swallows errors
- **What was done:** Ghidra ARM64 build used `make ... 2>&1 | tail -5` which hid the actual `-m32` compiler error
- **Failure mode:** Build failed with "Error 1" but no useful diagnostic info
- **Evidence:** Had to rebuild without the pipe to see the real error
- **How to avoid:** Never pipe build output through tail in Dockerfiles. Use full output or redirect to a file.

### 4. Pagination default changes breaking UI
- **What was done:** Added `limit=100` default to list_findings and list_vulnerabilities endpoints. The SBOM page showed "100" next to the Vulnerabilities tab instead of the total count.
- **Failure mode:** Misleading UI — user sees "100" but there are 2,404 vulns
- **Evidence:** Fix in commit 2069345
- **How to avoid:** When adding pagination to an existing endpoint, check all frontend consumers that use `.length` of the response array for counts. Use summary stats instead.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Syft + Wairz custom (not Syft replacing custom) | Syft misses firmware-specific patterns; custom misses ecosystem packages | Correct — 90 → 319 components |
| Grype over Trivy for vuln scanning | Smaller binary, no supply chain concerns, Syft compatibility | Correct — 2,404 CVEs in seconds |
| Grype findings use source=sbom_scan | Don't leak tool names into data model | Correct — cleaner abstraction |
| tarfile filter="data" replaced with custom filter | firmware rootfs needs absolute symlinks which filter="data" rejects | Required — firmware symlinks are legitimate |
| 10,000 directory listing limit (up from 200) | react-arborist virtualizes the tree; 200 was too restrictive for /usr/bin | Correct — user wanted all files visible |
| Clean slate test (docker compose down -v) | Validates fresh install experience after many changes | Found issues that incremental testing missed |
| Firmware type classifier in unpack.py | Routes ELF binaries to direct Ghidra analysis, skipping FS extraction | Foundation for bare metal support |
