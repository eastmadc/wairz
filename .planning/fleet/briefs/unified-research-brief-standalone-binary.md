# Unified Research Brief: Automatic Environment Synthesis for Standalone Binary Emulation & Fuzzing

Date: 2026-04-04
Campaign: RESEARCH ONLY (no code changes)
Status: Complete

---

## 1. Tool Inventory

| Tool | URL | Maturity | Python API | Purpose in Pipeline |
|---|---|---|---|---|
| **LIEF** v1.0.0 | https://github.com/lief-project/LIEF | Production | Yes (pip install lief) | Unified ELF/PE/Mach-O parsing, arch detection, dependency enumeration |
| **pyelftools** v0.32 | https://github.com/eliben/pyelftools | Stable | Yes (already in Wairz) | ELF-specific deep analysis, DT_NEEDED, PT_INTERP detection |
| **pefile** v2024.8 | https://github.com/erocarrera/pefile | Stable | Yes (pip install pefile) | PE import table, DLL dependencies, architecture detection |
| **macholib** v1.16.4 | https://github.com/ronaldoussoren/macholib | Stable | Yes (pip install macholib) | Mach-O LC_LOAD_DYLIB, dependency graph |
| **cpu_rec** | https://github.com/airbus-seclab/cpu_rec | Stable | Yes (standalone or binwalk plugin) | Raw binary architecture detection (70+ arch signatures) |
| **Capstone** v5.x | https://github.com/capstone-engine/capstone | Production | Yes (pip install capstone) | Disassembly engine, brute-force arch heuristic for raw binaries |
| **Qiling** | https://github.com/qilingframework/qiling | Active | Yes (pip install qiling) | Reference: rootfs templates, emulation patterns |
| **angr/CLE** | https://github.com/angr/cle | Production | Yes (pip install angr) | Reference: format auto-detection, dependency resolution |
| **Unicorn** | https://github.com/unicorn-engine/unicorn | Stable | Yes (pip install unicorn) | CPU-only emulation for raw/flat binaries |

### Tools NOT Recommended for Integration
| Tool | Reason |
|---|---|
| Avatar2 | Too heavyweight, designed for full-device re-hosting |
| PANDA | Record-and-replay focus, not standalone binary emulation |
| Firmadyne/FirmAE | Full firmware image emulation, wrong scope |
| Darling | Too immature for production use (Mach-O on Linux) |

---

## 2. Architecture Coverage Matrix

| Capability | ARM | AArch64 | MIPS | MIPSel | x86 | x86_64 | PPC | SH | SPARC |
|---|---|---|---|---|---|---|---|---|---|
| **Format detection (LIEF)** | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| **Raw arch detection (cpu_rec)** | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| **QEMU user-mode** | Y | Y | Y | Y | Y | Y | Y* | Y* | Y* |
| **Sysroot available (Qiling)** | Y | Y | Y | Y | Y | Y | N | N | N |
| **Sysroot available (Alpine)** | Y | Y | N | N | Y | Y | N | N | N |
| **Sysroot available (Debian)** | Y | Y | N** | Y | Y | Y | Y | N | N |
| **AFL++ QEMU mode** | Y | Y | Y | Y | Y | - | N*** | N | N |
| **AFL++ Unicorn mode** | Y | Y | Y | Y | Y | Y | Y | N | Y |
| **Wairz emulation container** | Y | Y | Y | Y | Y**** | Y**** | N | N | N |
| **Wairz fuzzing container** | Y | Y | Y | Y | Y | N | N | N | N |

Y = Supported, N = Not supported, * = QEMU supports but not tested in Wairz, ** = Debian dropped mips big-endian, *** = Wairz builds afl-qemu-trace for i386 only, **** = QEMU installed but no Wairz scripts

**Primary tier (focus here)**: ARM, AArch64, MIPS, MIPSel, x86 -- covers 95%+ of embedded firmware
**Secondary tier (future)**: x86_64, PPC
**Out of scope**: SH, SPARC (very niche)

---

## 3. Recommended Approach Per Binary Format

### ELF Binaries (Primary Target)

```
Upload standalone ELF binary
        |
        v
[1. Format Detection]  -- LIEF.parse() or pyelftools
   |         |
   |         v
   |   Architecture + Endianness extracted from ELF header
   |   e_machine field: EM_ARM, EM_AARCH64, EM_MIPS, EM_386, EM_X86_64
   |
   v
[2. Linkage Detection]
   |
   +-- PT_INTERP present? --> DYNAMIC binary
   |       |
   |       v
   |   [3a. Enumerate Dependencies]
   |       DT_NEEDED tags from .dynamic section
   |       Example: libc.so.6, libpthread.so.0, libdl.so.2
   |       |
   |       v
   |   [4a. Synthesize Sysroot]
   |       Select pre-built sysroot for detected arch
   |       Verify all DT_NEEDED libs present in sysroot
   |       If missing: warn user, attempt Debian debootstrap fallback
   |       Set QEMU_LD_PREFIX to sysroot path
   |
   +-- No PT_INTERP --> STATIC binary
           |
           v
       [3b. No sysroot needed]
           Run directly with qemu-<arch>-static
```

**Implementation path**:
- Step 1-2: Extend existing `get_binary_info` tool (already uses pyelftools)
- Step 3a: New function using pyelftools DynamicSection iterator
- Step 4a: New service to manage pre-built sysroot templates
- Step 3b: Simplest path -- just run it

### PE Binaries (Secondary Target)

```
Upload standalone PE binary
        |
        v
[1. Format Detection]  -- LIEF.parse() or pefile
   |
   v
[2. Architecture Detection]
   PE.FILE_HEADER.Machine: 0x014C (x86), 0x8664 (x64), 0xAA64 (ARM64)
   |
   v
[3. Static Analysis Only (Phase 1)]
   Parse import table for DLL dependencies
   Run through Ghidra for decompilation
   Check binary protections
   |
   v
[4. Emulation (Phase 2, if demand)]
   Wine-CE for x86/x64 PE execution
   Qiling for PE analysis with hooking
```

**Implementation path**:
- Step 1-2: Add LIEF or pefile to requirements
- Step 3: Extend binary analysis tools to handle PE format
- Step 4: Future work, significant effort

### Mach-O Binaries (Tertiary/Deferred)

```
Upload standalone Mach-O binary
        |
        v
[1. Format Detection]  -- LIEF.parse()
   |
   v
[2. Architecture Detection]
   Mach-O header CPU type: ARM64, x86_64
   |
   v
[3. Static Analysis Only]
   Parse LC_LOAD_DYLIB for dependencies
   Run through Ghidra for decompilation
   Check binary protections
```

**Implementation path**: Add LIEF, extend binary tools. No emulation support planned.

### Raw/Flat Binaries (Special Case)

```
Upload raw binary (no ELF/PE/Mach-O headers)
        |
        v
[1. Header Detection Fails]  -- LIEF returns no format
   |
   v
[2. Architecture Heuristics]
   a. Run cpu_rec for statistical arch detection
   b. Confirm with Capstone brute-force (try all arch/mode combos)
   c. If confident (>80%): proceed with detected arch
   d. If ambiguous: present top 3 candidates to user for selection
   |
   v
[3. Analysis Only]
   Load into Ghidra with detected language/compiler spec
   Disassemble with Capstone
   No emulation (no entry point, no OS context)
   |
   v
[4. Emulation (Expert Mode)]
   Unicorn engine for specific address ranges
   Requires manual harness from user/AI
```

**Implementation path**:
- Step 1-2: Add cpu_rec as dependency, implement scoring heuristic
- Step 3: Pass detected arch to Ghidra headless via -processor flag
- Step 4: Future work, very specialized

---

## 4. Rootfs Strategy

### Pre-Built Sysroot Templates (Recommended)

Maintain a set of minimal sysroot directories per architecture, stored in the Wairz
emulation container or downloadable on demand.

**Source of sysroot files**: Qiling framework's rootfs repository contains the most
practical starting point. These are minimal directories with just the dynamic linker
and core shared libraries needed for binary execution.

**Per-architecture sysroot contents**:
```
sysroot-arm/
  lib/
    ld-linux-armhf.so.3 -> ld-2.31.so
    ld-2.31.so
    libc.so.6 -> libc-2.31.so
    libc-2.31.so
    libpthread.so.0 -> libpthread-2.31.so
    libdl.so.2 -> libdl-2.31.so
    libm.so.6 -> libm-2.31.so
    libgcc_s.so.1
    librt.so.1

sysroot-aarch64/
  lib/
    ld-linux-aarch64.so.1
    libc.so.6
    ...

sysroot-mipsel/
  lib/
    ld.so.1
    libc.so.6
    ...

sysroot-mips/
  lib/
    ld.so.1
    libc.so.6
    ...

sysroot-x86/
  lib/
    ld-linux.so.2
    libc.so.6
    ...
```

**Size estimate**: ~5-15 MB per architecture (glibc-based), ~2-5 MB per architecture (musl-based).
**Total for 5 primary architectures**: ~25-75 MB.

### Dependency Gap Resolution

When a standalone binary requires libraries not in the base sysroot:

1. **Check if library exists in sysroot**: Compare DT_NEEDED list against sysroot contents
2. **Common firmware libraries**: Maintain extended sysroot with libssl, libcrypto, libuci, libnvram, libcurl, libz
3. **User notification**: If dependency missing, show which libraries are needed and suggest:
   - Upload the library files manually
   - Use a full Debian rootfs (auto-generated via debootstrap)
4. **Smart matching**: If binary came from a firmware project, check that firmware's extracted rootfs for the needed libraries

### Build Pipeline (for generating sysroots)

For the Wairz Docker image build:
1. Extract core libraries from Debian multiarch packages for each architecture
2. Package into minimal sysroot tarballs
3. Include in the emulation Docker image at `/opt/sysroots/<arch>/`
4. Or: download on first use and cache in the storage volume

---

## 5. Fuzzing Strategy

### Decision Tree for Fuzzing Mode

```
Standalone binary uploaded
        |
        v
[Detect format + architecture]
        |
        +-- Static ELF
        |       |
        |       v
        |   AFL++ QEMU mode (-Q)
        |   No sysroot needed
        |   Detect input method (stdin vs file)
        |   Auto-generate seeds
        |
        +-- Dynamic ELF
        |       |
        |       v
        |   [Synthesize sysroot]
        |       |
        |       v
        |   AFL++ QEMU mode (-Q) with QEMU_LD_PREFIX
        |   Detect input method
        |   Auto-generate seeds
        |   If sysroot incomplete: warn user
        |
        +-- Raw/flat binary
        |       |
        |       v
        |   AFL++ Unicorn mode (-U)
        |   Requires custom harness (AI-assisted generation)
        |   Very manual process
        |
        +-- PE binary
                |
                v
            Not supported for fuzzing (Phase 1)
            Recommend: Wine-CE + AFL++ (future)
```

### Input Method Auto-Detection

Extend the existing `analyze_fuzzing_target` tool:

1. Parse imports with LIEF/pyelftools
2. Classify I/O pattern:
   - **stdin**: imports `read(fd=0)`, `fgets(stdin)`, `scanf` -> AFL++ pipe mode
   - **file**: imports `fopen`, `open` + `read`/`fread` -> AFL++ @@ mode
   - **network**: imports `recv`, `accept`, `bind` -> AFL++ with desock library (already in container)
3. Generate appropriate AFL++ command line

### Seed Generation for Unknown Binaries

Extend existing `generate_seed_corpus` tool:
1. Extract strings from binary, look for format indicators (.xml, .json, .cfg)
2. Check for file magic references in binary data
3. If no indicators: generate generic seeds (empty, single byte, 4 bytes, newline)

### Integration with Existing Wairz Fuzzing Pipeline

The existing fuzzing pipeline in Wairz:
- `fuzzing/Dockerfile`: Already builds afl-qemu-trace for ARM, MIPS, MIPSel, AArch64, i386
- `fuzzing/desock/`: Already has cross-compiled desock libraries for network daemon fuzzing
- `backend/app/services/fuzzing_service.py`: Manages fuzzing campaigns
- `backend/app/ai/tools/fuzzing.py`: MCP tools for fuzzing

**What needs to change for standalone binaries**:
1. Add sysroot templates to the fuzzing container (or mount from shared volume)
2. Set QEMU_LD_PREFIX in the fuzzing container when launching afl-fuzz
3. Add "standalone binary" mode to the fuzzing service that skips firmware rootfs lookup
4. Extend `analyze_fuzzing_target` to work without an extracted firmware filesystem

---

## 6. Risks and Limitations

### High Risk

| Risk | Impact | Mitigation |
|---|---|---|
| **Sysroot library version mismatch** | Binary compiled against glibc 2.31, sysroot has 2.36 -- may crash or behave differently | Maintain multiple glibc versions per arch, or detect required version from binary |
| **Missing uncommon dependencies** | Binary needs vendor-specific .so (libnvram, libuci) not in generic sysroot | Prompt user to upload missing libs. For firmware-derived binaries, search the firmware rootfs. |
| **MIPS ABI variants** | MIPS has O32, N32, N64 ABIs. Wrong ABI = immediate crash | Detect from ELF flags (EI_CLASS + e_flags). Ensure sysroot matches ABI. |
| **CPU feature requirements** | ARM binary needs VFP/NEON, but sysroot libc doesn't support it | Use hard-float vs soft-float sysroot variants |

### Medium Risk

| Risk | Impact | Mitigation |
|---|---|---|
| **Raw binary arch misdetection** | cpu_rec gives wrong architecture for small binaries (<1KB) | Require minimum binary size for auto-detection. Offer manual override. |
| **AFL++ QEMU mode instability** | QEMU crashes on certain syscall patterns | Already an issue with firmware fuzzing. Use AFL_QEMU_PERSISTENT_HOOK for resilience. |
| **PE emulation complexity** | Wine-CE is experimental, may not support IoT-specific Windows CE APIs | Defer PE emulation. Focus on static analysis only. |
| **Sysroot disk space** | 5 architectures x multiple glibc versions = 100-500 MB | Lazy download. Only fetch sysroot when needed. Cache in Docker volume. |

### Low Risk / Known Limitations

| Limitation | Explanation |
|---|---|
| **No Mach-O emulation** | Darling is too immature. Defer indefinitely for firmware security context. |
| **No bare-metal firmware execution** | Raw binaries without OS (MCU firmware, RTOS images) cannot be emulated with QEMU user-mode. Unicorn mode requires manual harness. |
| **No automated harness generation for Unicorn mode** | Unicorn mode needs per-target harness. AI-assisted generation possible but not reliable. |
| **No Windows ARM PE fuzzing** | Wine-CE only supports x86/x64. ARM PE from Windows IoT cannot be fuzzed. |
| **PPC/SH/SPARC not tested** | QEMU supports these but no sysroots maintained, no AFL++ targets built. |

---

## 7. Implementation Roadmap (Suggested)

### Phase 1: ELF Standalone Binary Support (Smallest Viable)
- Add LIEF to backend requirements
- Implement architecture auto-detection for uploaded binaries
- Implement static vs dynamic linking detection
- Add pre-built sysroot templates (5 architectures) to emulation container
- Implement sysroot selection and QEMU_LD_PREFIX configuration
- Extend emulation service with "standalone binary" mode
- Extend fuzzing service with "standalone binary" mode
- Add input method auto-detection to fuzzing target analysis

### Phase 2: PE Static Analysis
- Add pefile to backend requirements
- Extend binary analysis tools to handle PE format
- PE architecture detection, import table parsing, protection checks
- Ghidra headless analysis for PE (already supported by Ghidra)

### Phase 3: Raw Binary Support
- Add cpu_rec to backend requirements
- Implement architecture heuristic pipeline (cpu_rec -> Capstone confirmation)
- User-facing architecture selection UI for ambiguous cases
- Ghidra analysis with auto-detected language

### Phase 4: Advanced (Future)
- PE emulation via Wine-CE
- Unicorn mode fuzzing with AI-assisted harness generation
- Multiple glibc version support per architecture
- LibAFL integration for better fuzzing performance

---

## Sources

### Binary Parsing & Analysis
- [LIEF - GitHub](https://github.com/lief-project/LIEF)
- [LIEF Documentation](https://lief.re/)
- [pyelftools - GitHub](https://github.com/eliben/pyelftools)
- [pefile - GitHub](https://github.com/erocarrera/pefile)
- [pefile - PyPI](https://pypi.org/project/pefile/)
- [macholib - GitHub](https://github.com/ronaldoussoren/macholib)
- [Capstone Engine](https://www.capstone-engine.org/)
- [cpu_rec - GitHub](https://github.com/airbus-seclab/cpu_rec)

### Emulation Frameworks
- [Qiling Framework - GitHub](https://github.com/qilingframework/qiling)
- [Qiling Rootfs Templates](https://github.com/qilingframework/rootfs)
- [angr/CLE - GitHub](https://github.com/angr/cle)
- [Unicorn Engine - GitHub](https://github.com/unicorn-engine/unicorn)
- [pwntools QEMU Utilities](https://docs.pwntools.com/en/stable/qemu.html)
- [Avatar2 - GitHub](https://github.com/avatartwo/avatar2)

### Firmware Analysis Platforms
- [Firmadyne - GitHub](https://github.com/firmadyne/firmadyne)
- [FirmAE - GitHub](https://github.com/pr0v3rbs/FirmAE)

### Rootfs & Sysroot
- [Alpine Linux Downloads](https://alpinelinux.org/downloads/)
- [Debian Multiarch HOWTO](https://wiki.debian.org/Multiarch/HOWTO)
- [Buildroot Manual](https://buildroot.org/downloads/manual/manual.html)
- [QEMU User Mode Documentation](https://www.qemu.org/docs/master/user/main.html)
- [Debian QemuUserEmulation](https://wiki.debian.org/QemuUserEmulation)

### PE & Mach-O Emulation
- [Wine-CE - GitLab](https://gitlab.com/wine-ce/wine-ce)
- [Darling - GitHub](https://github.com/darlinghq/darling)
- [Linaro WoA Emulation](https://linaro.atlassian.net/wiki/spaces/WOAR/pages/28888137940)

### Fuzzing
- [AFL++ - GitHub](https://github.com/AFLplusplus/AFLplusplus)
- [AFL++ QEMU Mode README](https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.md)
- [AFL++ Fuzzing Binary-Only Targets](https://aflplus.plus/docs/fuzzing_binary-only_targets/)
- [LibAFL - GitHub](https://github.com/AFLplusplus/LibAFL)
- [LibAFL QEMU Paper (NDSS BAR 2024)](https://www.ndss-symposium.org/ndss-paper/auto-draft-432/)
- [Fuzzing IoT Binaries with AFL++ Part I](https://blog.attify.com/fuzzing-iot-devices-part-1/)
- [Fuzzing IoT Binaries with AFL++ Part II](https://blog.attify.com/fuzzing-iot-binaries-with-afl-part-ii/)
- [OSS-Fuzz LLM Harness Synthesis](https://blog.oss-fuzz.com/posts/introducing-llm-based-harness-synthesis-for-unfuzzed-projects/)

### Academic
- [cpu_rec Architecture Detection (SSTIC 2017)](https://airbus-seclab.github.io/cpurec/SSTIC2017-Article-cpu_rec-granboulan.pdf)
- [Towards Usable Automated Detection of CPU Architecture (arXiv)](https://arxiv.org/pdf/1908.05459)
- [PromeFuzz - ACM CCS 2025](https://dl.acm.org/doi/10.1145/3719027.3765222)
