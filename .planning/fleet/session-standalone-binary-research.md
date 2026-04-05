# Fleet Session: Standalone Binary Environment Synthesis Research

Status: completed
Started: 2026-04-04T00:00:00Z
Completed: 2026-04-04
Direction: Research campaign - automatic environment synthesis for standalone binary emulation & fuzzing
Type: RESEARCH ONLY (no code changes)

## Work Queue
| # | Campaign | Scope | Status | Wave | Agent |
|---|----------|-------|--------|------|-------|
| 1 | Binary parsing & arch detection tools | LIEF, pefile, macholib, capstone, pyelftools | completed | 1 | Scout-1A |
| 2 | Existing platform approaches | Qiling, Avatar2, PANDA, angr, FirmAE | completed | 1 | Scout-1B |
| 3 | Raw/flat binary analysis | cpu_rec, Ghidra lang ID, capstone heuristics | completed | 1 | Scout-1C |
| 4 | Minimal rootfs generation | Alpine minirootfs, debootstrap, Buildroot, Docker multi-arch | completed | 2 | Scout-2A |
| 5 | QEMU user-mode minimal sysroots | -L flag, qemu-user-static, binfmt_misc | completed | 2 | Scout-2B |
| 6 | PE & Mach-O emulation | Wine+QEMU, Darling, Qiling, Unicorn | completed | 2 | Scout-2C |
| 7 | AFL++ standalone binary fuzzing | QEMU mode, Unicorn mode, synthesized rootfs | completed | 3 | Scout-3A |
| 8 | Input format detection | stdin/file/network, static analysis, OSS-Fuzz | completed | 3 | Scout-3B |

## Wave 1 Results: Binary Analysis Tools
- LIEF v1.0.0 is the best unified parser (ELF+PE+Mach-O) with Python API and auto-format detection
- pyelftools already in Wairz, sufficient for ELF DT_NEEDED and PT_INTERP detection
- cpu_rec (Airbus) is the best tool for raw binary arch detection (70+ arch signatures)
- Qiling's rootfs templates are the most practical starting point for sysroot synthesis
- angr/CLE provides excellent reference for format auto-detection logic

## Wave 2 Results: Environment Synthesis
- Alpine Linux has NO MIPS support; Debian multiarch dropped mips big-endian
- Qiling pre-built rootfs (github.com/qilingframework/rootfs) covers all 5 primary archs
- QEMU user-mode needs: dynamic linker + libc + binary-specific deps (set via QEMU_LD_PREFIX)
- Static binaries need NO rootfs at all (simplest path)
- PE emulation via Wine-CE is possible but experimental; Mach-O via Darling is too immature
- Recommended: Focus on ELF, defer PE emulation, skip Mach-O emulation

## Wave 3 Results: Fuzzing
- AFL++ QEMU mode with QEMU_LD_PREFIX works for standalone binaries with synthesized sysroot
- Static ELF fuzzing is zero-config (just afl-fuzz -Q)
- Input method detection possible via import analysis (already partially implemented in Wairz)
- Unicorn mode is fallback for raw binaries but requires manual harness
- Wairz fuzzing container already builds afl-qemu-trace for all 5 primary architectures

## Deliverables
- `.planning/fleet/briefs/wave1-binary-analysis-tools.md`
- `.planning/fleet/briefs/wave2-environment-synthesis.md`
- `.planning/fleet/briefs/wave3-fuzzing-standalone.md`
- `.planning/fleet/briefs/unified-research-brief-standalone-binary.md` (primary deliverable)
