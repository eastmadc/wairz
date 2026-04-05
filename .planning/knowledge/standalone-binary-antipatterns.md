# Anti-patterns: Standalone Binary Environment Synthesis

> Extracted: 2026-04-04
> Campaign: .planning/campaigns/standalone-binary-env-synthesis.md, standalone-binary-phases234.md

## Failed Patterns

### 1. Migration merging non-head revisions
- **What was done:** Archon agent created a merge migration with `down_revision = ("c4d5e6f7a8b9", "81f49fd099f5")`, attempting to merge two revisions that were mid-chain (not actual heads).
- **Failure mode:** Alembic would fail with "Can't locate revision" because those revisions already had children. The actual head was `8da8627326d4`.
- **Evidence:** Review caught this before running. The migration also used `g7b8c9d0e1f2` as revision ID which contains 'g' (not valid hex).
- **How to avoid:** Before creating a migration, always trace the full chain with `grep down_revision` across all migration files. The head is the revision that no other migration depends on. Never use non-hex characters in revision IDs.

### 2. LIEF enum case sensitivity
- **What was done:** Used lowercase `lief.MachO.Header.CPU_TYPE.x86` and `x86_64` for Mach-O CPU type mapping.
- **Failure mode:** `AttributeError` — the actual enum names are uppercase `X86` and `X86_64`. The error was swallowed by the outer `except Exception` handler, making the Mach-O binary return `architecture: null`.
- **Evidence:** The insulin pump Mach-O binary was detected as `format: "macho"` but `architecture: null` until the fix. Discovered during backfill testing.
- **How to avoid:** When using LIEF enums, print `dir(lief.MachO.Header.CPU_TYPE)` to verify exact member names. The ELF enums (ARCH.ARM, ARCH.I386) use different casing than Mach-O (CPU_TYPE.X86_64, CPU_TYPE.ARM64).

### 3. Mach-O DylibCommand not JSON-serializable
- **What was done:** Used `list(binary.libraries)` for Mach-O dependencies, same pattern as ELF.
- **Failure mode:** `TypeError: Object of type DylibCommand is not JSON serializable` — Mach-O `binary.libraries` returns `DylibCommand` objects, not strings.
- **Evidence:** Crash during backfill of the insulin pump binary. Fixed by using `[lib.name for lib in binary.libraries]`.
- **How to avoid:** Always check the return type of LIEF collection properties. ELF `binary.libraries` returns strings, but Mach-O returns command objects with `.name` attributes.

### 4. Missing Mach-O FatBinary isinstance check
- **What was done:** Checked `isinstance(binary, lief.MachO.Binary)` for Mach-O detection.
- **Failure mode:** `lief.parse()` can return `lief.MachO.FatBinary` for universal binaries, which is NOT a subclass of `MachO.Binary`. These would fall through to the fallback path.
- **Evidence:** Caught during review. Added `isinstance(binary, lief.MachO.FatBinary)` check with `.at(0)` to extract first slice.
- **How to avoid:** Always check for FatBinary before Binary when handling Mach-O. `lief.parse()` returns FatBinary for multi-arch Mach-O files.

### 5. chmod fails as non-root in emulation container
- **What was done:** `container.exec_run(["sh", "-c", "chmod +x /firmware/*"])` to make standalone binaries executable.
- **Failure mode:** `Operation not permitted` — container runs as `emulator` user but firmware files are root-owned from bind mount.
- **Evidence:** The binary had `-rw-rw-r--` permissions, QEMU returned exit code 1 (permission denied). Fixed by adding `user="root"` to the exec_run call.
- **How to avoid:** When running chmod on bind-mounted files in containers with non-root users, always specify `user="root"` in `exec_run()`.

### 6. COPY . . overwrites Docker-built venv
- **What was done:** Docker `COPY . .` copied the host's `.venv/` directory into the container, overwriting the venv built during the Docker build (which had the correct Python version and installed packages).
- **Failure mode:** `ModuleNotFoundError: No module named 'redis'` — the host venv used Python 3.13 while the Docker build installed packages for Python 3.12.
- **Evidence:** Persistent import failures across multiple rebuild attempts. Fixed by adding `.venv` to `.dockerignore`.
- **How to avoid:** Always add `.venv` to `.dockerignore` in Python projects using Docker. This is a critical issue that can cause hours of debugging.

### 7. Qiling dependency conflicts with uv venv
- **What was done:** Tried installing Qiling into the uv-managed venv via pip, then running `uv sync` to restore project deps.
- **Failure mode:** pip and uv manage packages differently. Qiling's deps (gevent, pillow, greenlet) conflicted with the project's deps. `uv sync` couldn't cleanly restore the state after pip modifications.
- **Evidence:** 5+ failed attempts: direct pip install, .pth files, Python version pinning, uv sync after pip. Each attempt had a different failure mode (missing redis, C extension ABI mismatch, wrong Python version).
- **How to avoid:** Never mix pip and uv package management in the same venv. If a package has conflicting deps, install it system-wide and use subprocess isolation.

### 8. uv picks wrong Python version
- **What was done:** Used `uv sync` without specifying Python version in a Docker image with both Python 3.12 (from base image) and 3.13 (from Debian packages).
- **Failure mode:** uv created the venv with Python 3.13 (Debian system Python) instead of 3.12 (Docker base image Python). Packages installed into python3.12/site-packages were invisible to the venv's python3.13.
- **Evidence:** `readlink -f .venv/bin/python3` showed `/usr/bin/python3.13` despite base image being `python:3.12-slim`. Fixed with `uv venv --python /usr/local/bin/python3.12`.
- **How to avoid:** Always specify `--python /usr/local/bin/python3.X` with uv in Dockerfiles. Docker's `python:X.Y-slim` images install Python at `/usr/local/bin/python3.X` but Debian packages may install a different version at `/usr/bin/python3`.
