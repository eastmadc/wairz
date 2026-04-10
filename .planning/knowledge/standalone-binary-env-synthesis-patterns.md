# Patterns: Standalone Binary Environment Synthesis Campaign

> Extracted: 2026-04-10
> Campaign: .planning/campaigns/standalone-binary-env-synthesis.md
> Postmortem: none

## Successful Patterns

### 1. LIEF for Unified Multi-Format Binary Parsing
- **Description:** Used LIEF library for parsing ELF, PE, and Mach-O binaries through a single API, with pyelftools as ELF-only fallback. Verified API surface (ARCH.I386 not i386, Header.ELF_DATA not ELF.ELF_DATA) before coding.
- **Evidence:** Decision Log: "Using LIEF for multi-format binary parsing (ELF+PE+Mach-O unified API). LIEF v0.16.1 API verified." All 6 phases completed successfully.
- **Applies when:** Adding binary format detection/analysis that must handle multiple executable formats. LIEF covers ELF+PE+Mach-O in one dependency. Always verify enum names with `dir()` before using — LIEF's API naming is inconsistent across versions.

### 2. JSONB for Extensible Binary Metadata
- **Description:** Stored binary analysis results as a JSONB field (`binary_info`) on the Firmware model rather than a separate table or typed columns.
- **Evidence:** Decision Log: "lightweight, extensible, avoids join overhead. Only set for standalone binaries."
- **Applies when:** Storing analysis results that vary by firmware type. JSONB avoids schema migrations for new fields and keeps queries simple. Only use for metadata that doesn't need relational queries.

### 3. Container Flag Files for Mode Communication
- **Description:** Standalone emulation mode communicated via flag files in /tmp/ (.standalone_mode, .standalone_arch, .standalone_static) rather than DB lookups from within containers.
- **Evidence:** Decision Log: "avoids passing state through DB for exec_command and WebSocket." Emulation and fuzzing both used this pattern.
- **Applies when:** Container processes need to know runtime mode but don't have DB access. Flag files are simple, fast, and don't introduce coupling to the database layer.

### 4. Debian Multiarch Sysroots for Cross-Architecture Libraries
- **Description:** Built sysroots using Debian multiarch packages (libc6 + libgcc-s1 per architecture) at /opt/sysroots/<arch>/lib/ in emulation and fuzzing containers.
- **Evidence:** Decision Log: "Primary tier: ARM, AArch64, MIPS, MIPSel, x86 (covers 95%+ of firmware binaries)."
- **Applies when:** Emulating dynamically-linked binaries without their original rootfs. Debian packages provide reliable cross-arch libraries. Static binaries skip sysroots entirely.

### 5. Six-Phase Full-Stack Campaign Structure
- **Description:** Organized as backend service → sysroot infra → emulation → fuzzing → frontend → MCP tools. Each phase was independently verifiable.
- **Evidence:** All 6 phases completed in sequence. Feature ledger shows 20+ features across backend, Dockerfiles, frontend, and MCP tools.
- **Applies when:** Features that span the entire stack (backend + containers + frontend + MCP). Phase ordering should follow the dependency chain.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| LIEF over pyelftools-only | Unified ELF+PE+Mach-O API | Good — single dependency handles all formats |
| binary_info as JSONB | Extensible, no join overhead | Good — easy to add fields later |
| Flag files for container mode | No DB coupling in containers | Good — simple, fast, reliable |
| Debian multiarch sysroots | Reliable cross-arch libraries | Good — covers 95%+ of targets |
| Static binaries skip sysroot | No unnecessary library overlay | Good — simpler execution path |
| Merged two Alembic heads | Multiple parallel features created divergent heads | Necessary — always check for multiple heads before migrating |
