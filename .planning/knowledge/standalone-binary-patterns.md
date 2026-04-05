# Patterns: Standalone Binary Environment Synthesis

> Extracted: 2026-04-04
> Campaign: .planning/campaigns/standalone-binary-env-synthesis.md, standalone-binary-phases234.md
> Postmortem: none

## Successful Patterns

### 1. Research fleet before implementation
- **Description:** Used citadel:fleet with 3 research waves (binary analysis tools, environment synthesis, fuzzing) before writing any code. Produced a unified research brief with tool inventory, architecture matrix, and phased roadmap.
- **Evidence:** Fleet session produced 4 briefs (wave1-3 + unified) that directly informed implementation decisions (LIEF over angr, Qiling rootfs over custom builds, cpu_rec over Capstone-only).
- **Applies when:** Adding a feature that touches multiple open-source tools/ecosystems where the right choice isn't obvious.

### 2. LIEF as unified binary parser
- **Description:** Used LIEF v0.16.1 for ELF/PE/Mach-O parsing through a single `lief.parse()` call. Added pyelftools as ELF fallback. This avoided three separate parser libraries.
- **Evidence:** binary_analysis_service.py handles all three formats in ~300 lines with graceful fallback chain: LIEF -> pyelftools -> magic byte detection.
- **Applies when:** Any multi-format binary analysis. LIEF's API is case-sensitive (ARCH.I386 not i386, CPU_TYPE.X86_64 not x86_64) — always verify enum names.

### 3. JSONB for extensible binary metadata
- **Description:** Stored binary analysis results as a single JSONB column (`firmware.binary_info`) instead of adding multiple typed columns. Added `extracted_filename` field during review without needing a migration.
- **Evidence:** The JSONB approach allowed adding `arch_candidates`, `arch_detection_method`, and `extracted_filename` fields without schema changes. Phase 3 added cpu_rec fields to the same JSONB seamlessly.
- **Applies when:** Metadata that varies by binary format and will grow over time. Avoid JSONB for data you need to query/index.

### 4. Container flag files for cross-process state
- **Description:** Used `/tmp/.standalone_mode`, `/tmp/.standalone_arch`, `/tmp/.standalone_static` files inside emulation containers to communicate standalone mode to exec_command and WebSocket handlers, avoiding DB roundtrips.
- **Evidence:** The emulation service's `exec_command()` and the WebSocket terminal handler both check flag files to determine execution mode without needing the firmware record.
- **Applies when:** Container-scoped state that multiple processes need but doesn't warrant a DB query per access.

### 5. Subprocess isolation for conflicting Python packages
- **Description:** Qiling and the project's uv-managed venv had irreconcilable dependency conflicts (gevent C extensions, pillow version, greenlet). Resolved by installing Qiling system-wide and invoking it via subprocess using the system Python.
- **Evidence:** Multiple failed attempts to colocate Qiling in the venv (pip install, .pth files, Python version pinning) before settling on subprocess isolation. The subprocess approach is clean and avoids all conflicts.
- **Applies when:** A Python tool has heavy native dependencies that conflict with the project's venv. Subprocess adds ~10ms overhead but guarantees isolation.

### 6. Explicit Python version in uv venv
- **Description:** The Docker base image has Python 3.12 but Debian packages install Python 3.13. uv defaulted to 3.13, causing C extension incompatibility. Fixed with `uv venv --python /usr/local/bin/python3.12`.
- **Evidence:** The venv Python 3.13 couldn't load gevent C extensions compiled for 3.12. After pinning, all imports worked.
- **Applies when:** Docker images based on python:X.Y-slim where system packages also install a different Python version.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| LIEF over angr/CLE for parsing | Lighter weight, unified API, no heavy solver deps | Good — handles ELF/PE/Mach-O in one call |
| Debian multiarch for sysroots | Official packages, 5-15MB per arch, maintained | Good — ARM/AArch64/MIPSel/i386/x86_64 all work. MIPS BE dropped by Debian. |
| Qiling via subprocess not in-process | Dependency conflicts with venv (gevent, pillow, greenlet) | Good — clean isolation, no conflicts |
| cpu_rec from git not pip | Not on PyPI, corpus needs decompression | Good — works reliably at /opt/cpu_rec |
| Static binaries skip sysroot | No shared library deps = no sysroot needed | Good — simplest path, zero config |
| Auto-route PE/Mach-O to Qiling | User sends "user" mode, service detects format and switches | Good — transparent to user, no mode selection needed |
| .dockerignore for .venv | Host .venv overwrote Docker-built venv via COPY . . | Critical fix — without it, Docker venv was corrupted on every build |
