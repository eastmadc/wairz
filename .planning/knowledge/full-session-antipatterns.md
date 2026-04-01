# Anti-patterns: Full Session

> Extracted: 2026-04-01
> Source: 25 commits across 4 campaigns + ad-hoc work

## Failed Patterns

### 1. Agent writes DB service without reading model schema
- **What was done:** Grype service agent wrote code with column names that don't exist (fix_version, category, source, metadata)
- **Failure mode:** 3 consecutive 500 errors, each a separate fix commit
- **Evidence:** Commits a654ad0, 28bfc24, 3fe4671
- **How to avoid:** Include full SQLAlchemy model definition in agent prompts. Or better: have agents read the model file first before writing any service code.

### 2. New backend enum values crash frontend Record lookups
- **What was done:** Backend used source="grype_scan", frontend FindingSource union didn't include it
- **Failure mode:** SOURCE_CONFIG[f.source] returned undefined → React crash → blank page
- **Evidence:** Commit c687e91
- **How to avoid:** 1) Use existing enum values when possible (sbom_scan, not grype_scan). 2) Add ?? fallback to all Record<Type, ...> lookups. 3) Search frontend for all strict type lookups when adding new backend values.

### 3. Piping build output hides real errors
- **What was done:** `make decomp_opt 2>&1 | tail -5` in Dockerfile
- **Failure mode:** Saw "Error 1" but not the actual `-m32` compiler error
- **Evidence:** ARM64 Ghidra build phase 1
- **How to avoid:** Never pipe build commands through tail/head in Dockerfiles. Full output or no pipe.

### 4. Pagination breaks UI that uses array.length for counts
- **What was done:** Added limit=100 to list endpoints
- **Failure mode:** Tab showed "100" instead of "2404" — the array was capped but the UI used .length for display
- **Evidence:** Commit 2069345
- **How to avoid:** When adding pagination, audit all frontend consumers. Use summary/aggregate stats for display counts, not array.length.

### 5. Python tarfile filter="data" rejects firmware symlinks
- **What was done:** Used filter="data" for tar extraction (Python 3.12 security feature)
- **Failure mode:** "is a link to an absolute path" error on firmware rootfs with /bin -> /usr/bin symlinks
- **Evidence:** Commit 8e020ce
- **How to avoid:** Firmware archives need absolute symlinks. Use a custom filter that allows symlinks but still prevents path traversal and device nodes.

### 6. Testing SBOM scan without verifying response schema match
- **What was done:** Grype service returned different field names than VulnerabilityScanResponse expected
- **Failure mode:** 500 error on scan endpoint — Pydantic validation failed
- **Evidence:** Commit 3fe4671
- **How to avoid:** When creating a new backend for an existing endpoint, read the response schema first. Write the return dict to match exactly.
