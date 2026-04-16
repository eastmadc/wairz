# Patterns: ARM64 Platform Support

> Extracted: 2026-04-15
> Campaign: .planning/campaigns/completed/arm64-platform-support.md
> Postmortem: none

## Successful Patterns

### 1. Conditional Architecture Builds in Dockerfiles
- **Description:** Used `uname -m == aarch64` guard so ARM64-specific build steps (Ghidra native decompiler compilation) only run on ARM64 hosts, leaving x86_64 builds completely unaffected.
- **Evidence:** Phase 1 completed without breaking existing x86_64 CI/deployments.
- **Applies when:** Adding platform-specific compilation steps to multi-arch Dockerfiles.

### 2. Build From Source When Prebuilt Binaries Don't Exist
- **Description:** Ghidra doesn't ship prebuilt ARM64 decompiler binaries, so the Dockerfile compiles `decompile` and `sleighc` from the Ghidra source tree using the project's own Makefile.
- **Evidence:** Both binaries built successfully (4.5MB decompile, 935KB sleighc) in linux_arm_64/.
- **Applies when:** A third-party tool doesn't provide binaries for the target architecture.

### 3. Cleaning Build Dependencies After Compilation
- **Description:** Build-time deps (bison, flex, binutils-dev) were installed, used for compilation, then cleaned up in the same RUN layer to minimize image bloat.
- **Evidence:** Phase 1 feature ledger confirms cleanup.
- **Applies when:** Any Dockerfile that compiles from source — always clean build deps in the same layer.

### 4. Fix Architecture String Aliases Proactively
- **Description:** Fixed a latent bug where `x86_64` was used in QEMU_TRACE_MAP but QEMU reports the architecture as `i386`. Replaced with the correct alias before it caused runtime failures.
- **Evidence:** Phase 2 — the bug was latent (never triggered on x86_64 because tracing wasn't commonly used), but would have been a confusing failure on ARM64 where all architectures go through QEMU.
- **Applies when:** Working with architecture detection/dispatch code — verify string values match what tools actually report.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Use `sed -i 's/-m32//g'` to strip x86 compiler flags from Ghidra Makefile | Ghidra's Makefile hardcodes `-m32` (x86 assumption) which fails on ARM64 | Worked — compilation succeeds on both architectures |
| Defer Frida mode (Phase 4) | QEMU mode works correctly on ARM64 — Frida is an optimization, not a requirement | Correct call — all 5 QEMU targets build on ARM64, no blocking gaps |
| Keep ARM64 build conditional (not mandatory) | x86_64 hosts don't need the compilation overhead; prebuilt binaries work fine there | Avoids slowing x86_64 builds while supporting ARM64 |
