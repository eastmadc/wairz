# Patterns: Docker Image Optimization

> Extracted: 2026-04-14
> Campaign: .planning/campaigns/completed/docker-image-optimization.md
> Postmortem: none

## Successful Patterns

### 1. ldd-before-multistage
- **Description:** Before moving a build tool (cmake, qt6) to a builder stage, run `ldd` on the produced binary to verify it has no runtime dependency on the removed packages. UEFIExtract was assumed to need Qt at runtime (per a Dockerfile comment), but `ldd` proved it only links libstdc++/libc.
- **Evidence:** Decision Log #2 — saved ~400 MB by disproving a false assumption
- **Applies when:** Converting any Dockerfile to multi-stage; any time a comment says "keep X because Y needs it" — verify with `ldd`

### 2. cross-compiler-builder-stage
- **Description:** Cross-compilers (gcc-mipsel, gcc-mips, gcc-arm, gcc-aarch64) installed solely for building .so files can be isolated in a builder stage. Only the produced binaries are COPY'd to the final image.
- **Evidence:** Phase 4 — system-emulation 1.7 GB → 1.03 GB (670 MB saved)
- **Applies when:** Any Dockerfile that installs cross-compilers for a one-time compilation

### 3. apt-block-consolidation
- **Description:** Merging multiple `apt-get update && apt-get install` blocks into fewer blocks eliminates redundant apt cache downloads. Each `apt-get update` creates a new layer with the full package index.
- **Evidence:** Phase 1 — consolidated pkg-config/libfontconfig1-dev into base block; Phase 2 — merged OpenJDK + Android tools into one block (eliminated 2 `apt-get update` calls)
- **Applies when:** Any Dockerfile with more than 2 `apt-get update` calls

### 4. verify-tool-dependencies-after-refactor
- **Description:** After moving build tools to a builder stage, verify all downstream tools still build. keystone-engine (for Qiling) silently depended on cmake being present from the UEFIExtract build. Removing cmake broke keystone-engine's source build.
- **Evidence:** Phase 2 regression — keystone-engine failed with `--no-binary :all:` after cmake was moved to builder stage. Fixed by adding cmake back to the main apt block.
- **Applies when:** Any multi-stage refactor where build tools are removed from the final image

### 5. research-before-migration
- **Description:** For complex third-party tools (FirmAE), research compatibility before attempting base image migration. FirmAE's scripts assume Ubuntu paths and tools; Debian slim migration would require extensive patching for ~300 MB savings — poor risk/benefit.
- **Evidence:** Decision Log #5, #6 — skipped Debian slim and PostgreSQL externalization after analysis showed high risk
- **Applies when:** Considering base image changes for containers that wrap third-party tools with extensive shell scripts

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Ghidra requires JDK, not JRE | launch.sh passes `jdk` as java-type param; analyzeHeadless fails without JDK | Reverted JRE change; avoided broken Ghidra |
| UEFIExtract safe for multi-stage | ldd shows no Qt runtime dependency; only libstdc++/libc | Saved ~400 MB in backend image |
| binwalk3 needs libfontconfig at runtime | ldd shows libfontconfig.so.1 dependency | Kept libfontconfig1-dev in base apt block |
| Keep tests in Docker image | Tests run inside container via `uv run pytest` | Removed tests/ from .dockerignore |
| Keep Ubuntu 22.04 for system-emulation | FirmAE scripts assume Ubuntu paths/tools | Avoided risky migration |
| Keep internal PostgreSQL in system-emulation | FirmAE hardcodes localhost postgres | Avoided ~80 MB savings with high complexity |
| Move cross-compilers to builder stage | Only needed for libnvram .so build | Saved 670 MB in system-emulation |
| Restore cmake in final image | keystone-engine source build needs cmake | Fixed Qiling regression at ~40 MB cost |
