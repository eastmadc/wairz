# Wave 1 Brief: Binary Analysis Tools & Dependency Resolution

## Scout 1A: Multi-Format Binary Parsing Tools

### LIEF (v1.0.0, March 2026)
- **URL**: https://github.com/lief-project/LIEF
- **Maturity**: Production (v1.0.0 milestone reached). Active development by Quarkslab.
- **Formats**: ELF, PE, Mach-O, COFF, OAT, DEX, VDEX, ART
- **Python API**: Full bindings. `lief.parse(path)` auto-detects format.
- **Architecture detection**: Each format header exposes target architecture (e.g., `binary.header.machine_type` for ELF, `binary.header.machine` for PE)
- **Dependency enumeration**: ELF DT_NEEDED via `binary.libraries`, PE imports via `binary.imports`, Mach-O LC_LOAD_DYLIB via `binary.libraries`
- **Static vs dynamic**: Check for PT_INTERP segment (ELF), or presence of import table (PE)
- **Verdict**: Best unified API for all three formats. Already used in Wairz's binary.py via pyelftools for ELF; LIEF would extend coverage to PE + Mach-O.

### pyelftools (v0.32)
- **URL**: https://github.com/eliben/pyelftools
- **Maturity**: Stable, pure Python, no dependencies. Already in Wairz.
- **Formats**: ELF only (+ DWARF debug info)
- **Python API**: `ELFFile(open(path, 'rb'))` then query sections, segments, dynamic tags
- **DT_NEEDED**: Via `DynamicSection` iteration, filter for `DT_NEEDED` tags
- **Static detection**: Check for absence of `PT_DYNAMIC` segment or `PT_INTERP`
- **Verdict**: Already integrated, excellent for ELF. Not sufficient alone for PE/Mach-O.

### pefile (v2024.8.26)
- **URL**: https://github.com/erocarrera/pefile
- **Maturity**: Very stable, extensively tested against malformed PEs and malware.
- **Formats**: PE only
- **Python API**: `pe = pefile.PE(path)`, then `pe.DIRECTORY_ENTRY_IMPORT` for DLL deps
- **Architecture**: `pe.FILE_HEADER.Machine` (0x014C=x86, 0x8664=x64, 0x01C4=ARM, 0xAA64=ARM64)
- **Verdict**: Best PE parser for dependency resolution. Handles malformed PE gracefully.

### macholib (v1.16.4)
- **URL**: https://github.com/ronaldoussoren/macholib
- **Maturity**: Stable, pure Python. Used by py2app.
- **Formats**: Mach-O only
- **Python API**: `MachO(path)` then iterate load commands for `LC_LOAD_DYLIB`
- **Dependency graph**: `MachOGraph` class for transitive dependency analysis
- **Verdict**: Good for Mach-O dependency enumeration. LIEF also covers Mach-O and may be simpler.

### Capstone (v5.x)
- **URL**: https://github.com/capstone-engine/capstone
- **Maturity**: Very mature, widely used. 24+ architectures.
- **Purpose**: Disassembly engine, NOT a parser. Requires architecture to be known.
- **Arch identification**: Not built-in. Can be used for brute-force heuristic by trying all arch/mode combos and scoring valid-instruction ratio.
- **Verdict**: Essential for raw binary arch heuristics (secondary tool, not primary parser).

## Scout 1B: Existing Platform Approaches

### Qiling Framework
- **URL**: https://github.com/qilingframework/qiling
- **Maturity**: Active development, good documentation. Based on Unicorn engine.
- **Key concept**: `Qiling(argv=[binary], rootfs=rootfs_path)` - requires a rootfs directory.
- **OS support**: Linux, FreeBSD, macOS, Windows, UEFI, DOS, QNX
- **Arch support**: x86, x64, ARM, ARM64, MIPS
- **Rootfs**: Ships pre-built rootfs templates for Windows and Linux. Users must provide or build rootfs.
- **Verdict**: Closest to what Wairz needs. Could be used as a library or as a reference implementation. Key insight: Qiling's rootfs requirement is exactly the problem we need to solve.

### angr + CLE Loader
- **URL**: https://github.com/angr/angr, https://github.com/angr/cle
- **Maturity**: Production, academic backing (UCSB).
- **Key concept**: CLE auto-detects format and architecture from binary headers. Backends for ELF, PE, Mach-O, CGC, flat blobs.
- **Raw binary**: "Blob" backend requires user-specified architecture (archinfo class).
- **Dependency loading**: CLE automatically resolves and loads shared library dependencies.
- **Verdict**: Excellent for static/symbolic analysis. Overkill for just running a binary, but CLE's format detection logic is a good reference.

### Avatar2 + PANDA
- **URL**: https://github.com/avatartwo/avatar2
- **Maturity**: Research-grade, maintained by EURECOM.
- **Key concept**: Tool orchestrator for dynamic analysis. Synchronizes state between QEMU, GDB, PANDA, angr.
- **Verdict**: Too heavyweight for standalone binary emulation. Better for full device re-hosting.

### Firmadyne / FirmAE
- **URL**: https://github.com/firmadyne/firmadyne, https://github.com/pr0v3rbs/FirmAE
- **Key concept**: Full firmware image emulation (not standalone binaries). FirmAE improved emulation success from 16% to 79% with environment synthesis.
- **FirmAE's approach**: Extract strings from binaries to discover expected filesystem paths, then create those paths/files before emulation.
- **Verdict**: Wrong scope (full firmware, not standalone binaries), but FirmAE's path-synthesis heuristic is relevant.

### pwntools
- **URL**: https://docs.pwntools.com/en/stable/qemu.html
- **Key concept**: `pwnlib.qemu` for seamless QEMU user-mode integration. Auto-detects architecture from ELF headers. For dynamic binaries: expects libs at `/etc/qemu-binfmt/<arch>/`.
- **Verdict**: Good reference for QEMU user-mode integration patterns. Already solves the "run an ELF on foreign arch" problem for CTF-style use.

## Scout 1C: Raw/Flat Binary Analysis

### cpu_rec (Airbus)
- **URL**: https://github.com/airbus-seclab/cpu_rec
- **Maturity**: Stable, standalone or binwalk plugin.
- **Approach**: Statistical analysis of byte patterns against 70+ architecture signatures. Detects arch + endianness.
- **Performance**: ~25s + 1GB RAM for signature generation; ~1min/MB for analysis.
- **Verdict**: Best standalone tool for raw binary arch identification. Can be a binwalk plugin (`binwalk -% file`).

### Ghidra Language Identification
- **Approach**: Ghidra can import raw binaries but requires manual language selection. No built-in auto-detection for headerless binaries.
- **Headless mode**: Can specify language via `analyzeHeadless` with `-processor` flag.
- **Verdict**: Useful once architecture is known. Not useful for auto-detection.

### Capstone Brute-Force Heuristic
- **Approach**: Try all arch/mode combinations, count valid instructions per 1KB block. Highest valid-instruction ratio wins.
- **Implementation**: Not built into Capstone; must be implemented externally.
- **Verdict**: Viable fallback when cpu_rec is inconclusive. Fast for small binaries.

### Combined Raw Binary Pipeline
1. Try ELF/PE/Mach-O headers first (LIEF)
2. If no headers: run cpu_rec for statistical arch detection
3. Confirm with Capstone brute-force on first 4KB
4. If still ambiguous: expose to user for manual selection
