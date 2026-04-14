---
version: 1
id: "e5747452-40cd-408a-8ec9-b6358d851e5c"
status: active
started: "2026-04-14T12:00:00Z"
completed_at: null
direction: "Optimize Docker image sizes across all services — multi-stage builds, dependency cleanup, .dockerignore coverage. Target 1.3-1.8 GB aggregate reduction."
phase_count: 5
current_phase: 1
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
| 1 | pending | build | Quick wins: .dockerignore, ghidra JRE, apt consolidation, pip --no-cache-dir | All Dockerfiles updated, `docker compose build` succeeds |
| 2 | pending | build | Backend multi-stage: Rust toolchain + UEFITool builder stages | backend/Dockerfile uses multi-stage, `docker compose up -d --build backend worker` succeeds, binwalk3/UEFIExtract work |
| 3 | pending | research | System-emulation: test Debian slim as base, evaluate PostgreSQL externalization | Decision log records FirmAE compat results on Debian slim |
| 4 | pending | build | System-emulation refactor: apply decisions from Phase 3 | system-emulation/Dockerfile rebuilt, FirmAE services start and respond |
| 5 | pending | verify | Full integration: all images build, all services start, existing tests pass | `docker compose up -d` all services healthy, 463+ tests still passing |

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

(empty — decisions recorded as phases execute)

## Active Context

Phase 1 ready to start. Research completed in session 36:

### Phase 1 — Quick Wins Checklist

**Add .dockerignore files:**
- [ ] emulation/.dockerignore (`.git *.md .env scripts/ tests/`)
- [ ] fuzzing/.dockerignore (`.git *.md .env tests/`)
- [ ] ghidra/.dockerignore (`.git *.md .env`)
- [ ] Expand backend/.dockerignore (add `.git .github/ docs/ images/ tests/ .env*`)
- [ ] Expand system-emulation/.dockerignore (add `patches/ tests/ docs/`)

**Ghidra JDK → JRE (~150 MB savings):**
- [ ] Change `eclipse-temurin:17-jdk-jammy` → `eclipse-temurin:17-jre-jammy` in ghidra/Dockerfile
- [ ] Verify Ghidra headless works with JRE only (analyzeHeadless doesn't need javac)

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
| .dockerignore coverage | pending | 1 |
| Ghidra JRE-only image | pending | 1 |
| Apt cache cleanup | pending | 1 |
| Pip no-cache-dir | pending | 1 |
| Backend multi-stage Rust builder | pending | 2 |
| Backend multi-stage UEFITool builder | pending | 2 |
| System-emulation Debian slim | pending | 3-4 |
| System-emulation PostgreSQL externalization | pending | 3-4 |
| Cross-compiler builder stage | pending | 4 |
| Full integration verification | pending | 5 |
