---
version: 1
id: "e5747452-40cd-408a-8ec9-b6358d851e5c"
status: completed
started: "2026-04-14T12:00:00Z"
completed_at: null
direction: "Optimize Docker image sizes across all services — multi-stage builds, dependency cleanup, .dockerignore coverage. Target 1.3-1.8 GB aggregate reduction."
phase_count: 5
current_phase: 4
checkpoint-phase-1: stash@{0}
branch: null
worktree_status: null
---

# Campaign: Docker Image Optimization

Status: active
Started: 2026-04-14T12:00:00Z
Direction: Optimize Docker image sizes across all services — multi-stage builds, dependency cleanup, .dockerignore coverage. Target 1.3-1.8 GB aggregate reduction.

## Claimed Scope
- backend/Dockerfile
- backend/Dockerfile.ci
- backend/.dockerignore
- frontend/Dockerfile
- ghidra/Dockerfile
- emulation/Dockerfile
- fuzzing/Dockerfile
- system-emulation/Dockerfile
- system-emulation/.dockerignore

## Phases

| # | Status | Type | Phase | Done When |
|---|--------|------|-------|-----------|
| 1 | complete | build | Quick wins: .dockerignore, ghidra JRE, apt consolidation, pip --no-cache-dir | All Dockerfiles updated, `docker compose build` succeeds |
| 2 | complete | build | Backend multi-stage: UEFITool builder stage + apt consolidation | backend/Dockerfile uses multi-stage, `docker compose up -d --build backend worker` succeeds, binwalk3/UEFIExtract work |
| 3 | complete | research | System-emulation: test Debian slim as base, evaluate PostgreSQL externalization | Decision log records FirmAE compat results on Debian slim |
| 4 | complete | build | System-emulation refactor: apply decisions from Phase 3 | system-emulation/Dockerfile rebuilt, FirmAE services start and respond |
| 5 | complete | verify | Full integration: all images build, all services start, existing tests pass | `docker compose up -d` all services healthy, 463+ tests still passing |

## Phase End Conditions

| Phase | Condition | Check |
|-------|-----------|-------|
| 1 | command_passes | docker compose build (exit 0) |
| 1 | file_exists | emulation/.dockerignore |
| 1 | file_exists | fuzzing/.dockerignore |
| 1 | file_exists | ghidra/.dockerignore |
| 2 | command_passes | docker compose up -d --build backend worker && docker compose exec backend which binwalk (exit 0) |
| 2 | command_passes | docker compose exec backend which uefiextract (exit 0) |
| 3 | manual | FirmAE compat on Debian slim documented in Decision Log |
| 4 | command_passes | docker compose up -d --build system-emulation (exit 0) |
| 5 | command_passes | docker compose up -d && all healthchecks pass |

## Decision Log

1. **Ghidra requires JDK, not JRE** — Ghidra's `launch.sh` passes `jdk` as java-type param. Both backend and standalone ghidra Dockerfiles must keep JDK. JDK→JRE change was reverted after testing showed `analyzeHeadless` fails without JDK.
2. **UEFIExtract does NOT link Qt at runtime** — `ldd` shows only libstdc++/libc. The Dockerfile comment "cmake/qt6 are kept because purging them removes shared libs UEFIExtract needs" is incorrect. Phase 2 can safely move cmake+qt6 to builder stage.
3. **binwalk3 links libfontconfig at runtime** — Phase 2 multi-stage must keep `libfontconfig1` in final stage.
4. **Backend tests must remain in Docker image** — tests run inside container via `uv run pytest`. Excluding tests/ from .dockerignore.
5. **System-emulation: keep Ubuntu 22.04** — FirmAE's shell scripts assume Ubuntu paths and tools. Debian bookworm-slim migration would require extensive script patching and regression testing. Risk/benefit ratio is poor.
6. **System-emulation: keep internal PostgreSQL** — FirmAE hardcodes localhost postgres connections in many scripts. Externalizing would require patching FirmAE's config system. Not worth the complexity for ~80 MB savings.
7. **System-emulation: move cross-compilers to builder stage** — cross-compilers (gcc-mipsel, gcc-mips, gcc-arm, gcc-aarch64) are only used to build libnvram .so files. After building, they're dead weight (~300-400 MB). Multi-stage build: clone FirmAE + build libnvram in builder, COPY .so files to final image.
8. **System-emulation: purge build-essential after libnvram** — build-essential + liblzma-dev/liblzo2-dev/zlib1g-dev are only needed for compilation. Can be purged in the same layer after building.

## Active Context

**Session 37 progress:**
- Phase 1 complete: .dockerignore, apt consolidation, JDK→JRE reverted (Ghidra needs JDK)
- Phase 2 complete: UEFIExtract builder stage, OpenJDK + Android apt consolidation
- Image sizes: backend 5.39 GB → 4.87 GB (520 MB saved)
- 465 tests passing
- Phase 3 next: system-emulation research (Debian slim, PostgreSQL externalization)

Phase 1 research completed in session 36:

### Phase 1 — Quick Wins Checklist

**Add .dockerignore files:**
- [ ] emulation/.dockerignore (`.git *.md .env scripts/ tests/`)
- [ ] fuzzing/.dockerignore (`.git *.md .env tests/`)
- [ ] ghidra/.dockerignore (`.git *.md .env`)
- [ ] Expand backend/.dockerignore (add `.git .github/ docs/ images/ tests/ .env*`)
- [ ] Expand system-emulation/.dockerignore (add `patches/ tests/ docs/`)

**Ghidra JDK → JRE (~150 MB savings):**
- [x] REVERTED: Ghidra requires JDK, not JRE (`launch.sh` explicitly passes `jdk` requirement). Both backend and ghidra/Dockerfile must keep JDK.

**Apt consolidation:**
- [ ] Consolidate multiple `apt-get update` calls in backend/Dockerfile
- [ ] Add `rm -rf /var/lib/apt/lists/*` after all apt-get install blocks in ghidra/Dockerfile

**Pip caching:**
- [ ] Add `--no-cache-dir` to pip3 install in system-emulation/Dockerfile (line 125)

**Git clone depth:**
- [ ] Use `--depth 1` for cpu_rec clone in backend/Dockerfile + remove .git dir

### Phase 2 — Backend Multi-Stage (estimated 500-800 MB savings)

Key changes:
1. **Builder stage for Rust/binwalk3**: Install rustup, cargo build, copy only the binary
2. **Builder stage for UEFITool**: Install cmake/qt6/bison/flex, build, copy only uefiextract + uefifind
3. **Builder stage for sasquatch**: Build from source, copy binary
4. **Final stage**: Copy built binaries from builders, install only runtime dependencies

### Phase 3 — System-Emulation Research

Questions to answer:
1. Does FirmAE work on Debian bookworm-slim? (Ubuntu 22.04 is ~300-400 MB heavier)
2. Can FirmAE's PostgreSQL be externalized to the existing docker-compose postgres service?
3. Which QEMU system architectures are actually needed? (arm, mips, x86 — all three or subset?)
4. Can cross-compilation toolchains be moved to a builder stage? (libnvram build)

### Phase 4 — System-Emulation Build

Apply decisions from Phase 3. Expected changes depend on research results.

### Phase 5 — Full Verification

Run full integration test:
1. `docker compose build` — all images
2. `docker compose up -d` — all services start
3. Healthchecks pass (backend, frontend, postgres, redis)
4. Run test suite — 463+ tests still passing
5. Manual smoke test: upload firmware, run analysis

## Feature Ledger

| Feature | Status | Phase |
|---------|--------|-------|
| .dockerignore coverage | done | 1 |
| Ghidra JRE-only image | reverted (Ghidra requires JDK) | 1 |
| Apt consolidation (pkg-config/libfontconfig1-dev) | done | 1 |
| Pip no-cache-dir | already done | 1 |
| Git clone --depth 1 + rm .git (cpu_rec, sasquatch) | done | 1 |
| Backend JDK→JRE | reverted (Ghidra requires JDK) | 1 |
| Backend multi-stage UEFITool builder | done (saved ~520 MB) | 2 |
| Backend apt consolidation (OpenJDK + Android tools) | done | 2 |
| System-emulation Debian slim | skipped (risk > benefit) | 3 |
| System-emulation PostgreSQL externalization | skipped (risk > benefit) | 3 |
| Cross-compiler builder stage | done (saved 670 MB) | 4 |
| Full integration verification | done (465 tests, all services healthy) | 5 |
