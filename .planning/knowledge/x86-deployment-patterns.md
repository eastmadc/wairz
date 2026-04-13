# Patterns: x86_64 Multi-Platform Deployment (Session 33)

> Extracted: 2026-04-13
> Source: Session work — deploying Wairz stack from ARM64 Kali to x86_64 Ubuntu VM

## Successful Patterns

### 1. Parallel Research Scouts for Platform Migration
- **Description:** Spawned 4 concurrent research agents to audit different compatibility surfaces simultaneously: system inventory, Docker config, codebase platform-specific code, and QEMU/emulation architecture. Each agent had a focused scope, and findings were synthesized in the parent context.
- **Evidence:** All 4 agents returned comprehensive results in ~2 minutes wall-clock time. The synthesis identified the key issue (binwalk3 missing CLI) before the build even started.
- **Applies when:** Any cross-platform migration or large deployment audit where multiple independent surfaces need investigation.

### 2. Environment Variable Parameterization for Port Conflicts
- **Description:** Instead of hardcoding port changes or creating a separate compose file, used Docker Compose variable substitution with defaults: `${POSTGRES_HOST_PORT:-5432}`. This makes docker-compose.yml portable — works with defaults on clean machines, and configurable via .env on machines with port conflicts.
- **Evidence:** Ports 5432, 5433, 6379 were all occupied on the target VM. Using 5434/6380 in .env while keeping defaults for other deployments.
- **Applies when:** Any Docker Compose deployment targeting shared infrastructure where ports may conflict.

### 3. Docker Socket GID Runtime Detection
- **Description:** The entrypoint.sh detects the Docker socket GID at runtime via `stat -c %g /var/run/docker.sock` and adjusts the container's docker group GID to match. This eliminates the need to know the host GID at build time.
- **Evidence:** Docker GID was 141 on Ubuntu VM vs 999 default. The runtime detection handled this automatically without any code changes.
- **Applies when:** Any container that needs Docker socket access across different host environments.

### 4. Multi-Arch Detection in Dockerfile with Graceful Fallback
- **Description:** The backend Dockerfile uses `uname -m` to detect architecture and branches between ARM64 (compile Ghidra natives from source) and x86_64 (use pre-built binaries). Go binaries (Grype, Syft, etc.) use explicit arch mapping. All steps have `|| echo "WARN: ..."` fallbacks.
- **Evidence:** The same Dockerfile builds successfully on both ARM64 and x86_64 without any modifications. The x86_64 build skips the ARM64 Ghidra compilation entirely.
- **Applies when:** Any Dockerfile that needs to support multiple architectures with different tool availability.

### 5. Incremental Stack Bring-Up
- **Description:** Started with core services first (postgres, redis, backend, frontend), verified each was healthy, then addressed secondary issues (binwalk3 CLI missing). Didn't attempt to build all images (emulation, fuzzing) upfront.
- **Evidence:** Stack was serving requests within minutes. The binwalk3 fix was done as a targeted rebuild while the rest of the stack was already operational.
- **Applies when:** First deployment on a new platform — get core functionality working before building optional/heavy images.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Keep docker-compose.yml in git with variable substitution | Shared hook/service config benefits all contributors; per-machine differences go in .env (gitignored) | Portable — works on Pi and Ubuntu VM with different .env files |
| Build binwalk3 from Rust source in Dockerfile | pip package only ships Windows binary; no Linux release binaries available | Adds ~20s to build time but provides binwalk 3.1.0 CLI on both architectures |
| Use `external: true` for emulation_net | Backend dynamically spawns emulation containers outside compose; they need to join this network | Correct — network must pre-exist for dynamic container attachment |
| Remap host ports instead of stopping existing services | Greenbone, EMBA, Nessus are actively used tools on this VM | No disruption to existing services; Wairz accessible on 8000/3000 |
