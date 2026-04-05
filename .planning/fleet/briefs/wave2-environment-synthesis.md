# Wave 2 Brief: Environment Synthesis & Rootfs Templates

## Scout 2A: Minimal Rootfs Generation

### Alpine Linux Minirootfs
- **URL**: https://alpinelinux.org/downloads/
- **Available architectures**: x86_64, x86, aarch64, armv7, armhf
- **NOT available**: MIPS (no official Alpine MIPS port exists)
- **Size**: ~3-5 MB compressed per architecture
- **Version**: 3.23.3 (January 2026)
- **Key advantage**: musl libc (smaller, simpler than glibc). Pre-built tarballs, no build step needed.
- **Key limitation**: No MIPS. Most firmware targets are MIPS-based routers.

### Debian Multiarch Debootstrap
- **URL**: https://wiki.debian.org/Multiarch/HOWTO
- **Available architectures**: amd64, arm64, armel, armhf, i386, mipsel, mips64el, ppc64el, riscv64, s390x
- **MIPS support**: Yes (mipsel and mips64el). mips big-endian was dropped from Debian in recent releases.
- **Size**: ~150-300 MB for minimal debootstrap (much larger than Alpine)
- **Build time**: Requires network + debootstrap tool. Not a simple tarball download.
- **Key advantage**: glibc-based (matches most embedded firmware). MIPS support.
- **Key limitation**: Large size, requires debootstrap tooling to create.

### Buildroot Custom Rootfs
- **URL**: https://buildroot.org/
- **Available architectures**: All (ARM, MIPS, MIPSel, AArch64, x86, x86_64, PPC, SH, SPARC)
- **Size**: 1.7-3.6 MB uncompressed for minimal config (busybox + musl/uClibc)
- **Build time**: 5-10 minutes for minimal config
- **Key advantage**: Complete control over what's included. Can target any arch. Very small.
- **Key limitation**: Requires build infrastructure (cross-compilers, Buildroot checkout). Cannot download pre-built.

### Docker Multiarch Base Images
- **URL**: https://hub.docker.com (multiarch/debian-debootstrap, etc.)
- **Approach**: Pull a multi-arch Docker image, export the rootfs layer
- **Available architectures**: linux/amd64, linux/arm64, linux/arm/v7, linux/mips64le, linux/386
- **Key advantage**: Pre-built, readily available. Can extract rootfs with `docker export`.
- **Key limitation**: Requires Docker. MIPS support limited to mips64le.

### Qiling Pre-Built Rootfs
- **URL**: https://github.com/qilingframework/rootfs
- **Available**: Linux (x86, x86_64, ARM, ARM64, MIPS, MIPSel), Windows (x86, x86_64), macOS
- **Size**: Minimal. Contains just enough for Qiling's emulation.
- **Key advantage**: Already curated for binary emulation. Include correct ld.so + libc per arch.
- **Key limitation**: Designed for Qiling's API, not raw QEMU user-mode. But the file contents are reusable.
- **CRITICAL FINDING**: This is the most practical starting point. These rootfs templates contain exactly what QEMU user-mode needs.

### Recommended Rootfs Strategy
1. **Primary**: Use Qiling's pre-built rootfs templates as a base (covers all target architectures)
2. **Supplement**: For each architecture, maintain a "sysroot" directory with:
   - Dynamic linker (ld-linux-*.so or ld.so.1)
   - libc (libc.so.6 or libc.so)
   - Common libs: libpthread, libdl, libm, librt, libgcc_s
3. **Fallback**: For binaries with unusual dependencies, use Debian multiarch debootstrap
4. **Build pipeline**: Use Buildroot for custom MIPS/MIPSel rootfs if Qiling templates are insufficient

## Scout 2B: QEMU User-Mode Minimal Sysroots

### How QEMU User-Mode `-L` Works
- `-L path` or `QEMU_LD_PREFIX=path` sets the sysroot prefix
- QEMU intercepts the kernel's ELF loader and prepends this path to the interpreter path
- Example: binary requests `/lib/ld-linux-armhf.so.3` -> QEMU looks at `$QEMU_LD_PREFIX/lib/ld-linux-armhf.so.3`
- All subsequent library loads by ld.so also use this prefix

### Minimum Files for Dynamic ELF Execution
1. **Dynamic linker**: `/lib/ld-linux-*.so.*` or `/lib/ld.so.1` (arch-dependent)
2. **libc**: `/lib/libc.so.6` (glibc) or `/lib/ld-musl-*.so.1` (musl, which IS the linker)
3. **Binary-specific dependencies**: Whatever DT_NEEDED entries the binary has
4. **Optional**: `/etc/ld.so.cache` for faster library resolution (not strictly needed)

### Architecture-Specific Linker Paths
| Architecture | Linker Path |
|---|---|
| ARM (32-bit, hard-float) | /lib/ld-linux-armhf.so.3 |
| ARM (32-bit, soft-float) | /lib/ld-linux.so.3 |
| AArch64 | /lib/ld-linux-aarch64.so.1 |
| MIPS (big-endian) | /lib/ld.so.1 |
| MIPSel (little-endian) | /lib/ld.so.1 |
| x86 | /lib/ld-linux.so.2 |
| x86_64 | /lib64/ld-linux-x86-64.so.2 |

### Static Binary Handling
- Static binaries need NO rootfs at all
- Detection: absence of PT_INTERP segment in ELF headers (check with pyelftools/LIEF)
- QEMU user-mode can run static binaries directly: `qemu-<arch>-static ./binary`

### Key Insight: Firmware Rootfs as Sysroot
- When a binary comes FROM a firmware image, the firmware's extracted rootfs IS the sysroot
- Set `QEMU_LD_PREFIX` to the extracted firmware root
- This is what Wairz already does for full firmware emulation
- For STANDALONE binaries (no rootfs), we need the synthesized sysroot

## Scout 2C: PE and Mach-O Emulation

### PE Binary Emulation Options

#### Wine + QEMU (Practical for x86/x64)
- Wine translates Windows API calls to Linux syscalls
- For x86 PE on x86 Linux: Wine alone suffices
- For x86 PE on ARM Linux: Wine + QEMU user-mode (Wine-CE project)
- **Wine-CE**: Specifically designed for cross-architecture PE execution
- **Performance**: ~10x overhead compared to native execution
- **Verdict**: Practical for x86/x64 PE. Experimental for ARM PE.

#### Qiling for PE (Best option for analysis)
- Qiling can emulate Windows PE binaries using its Windows rootfs
- Requires Windows DLL files (must be sourced from a Windows installation due to licensing)
- Supports x86, x64 Windows PE
- **Verdict**: Best for security analysis (hooking, tracing). Not for full execution.

#### Unicorn Engine (OS-less, CPU-only)
- Emulates raw CPU instructions without OS context
- No syscall handling, no library loading, no file I/O
- Useful for: decrypting strings, analyzing specific functions, hash calculation
- **Verdict**: Good for targeted analysis of specific code sections. Not for full binary execution.

### Mach-O Binary Emulation Options

#### Darling (macOS Compatibility Layer for Linux)
- **URL**: https://github.com/darlinghq/darling
- **Status**: v0.1.20251023 (October 2025). Active but immature.
- **Capability**: Console/CLI applications work. GUI applications largely fail.
- **How**: Loads Mach-O via a lightweight loader, uses Apple's open-source dyld
- **Verdict**: Best available option for Mach-O CLI tools. Very experimental.

#### Qiling for Mach-O
- Supports macOS Mach-O emulation
- Requires macOS framework files (licensing concerns)
- **Verdict**: Possible for analysis. Not practical for distribution.

### Practical Assessment for PE/Mach-O in Wairz

| Format | Full Execution | Static Analysis | Fuzzing | Practical? |
|---|---|---|---|---|
| PE (x86/x64) | Wine-CE | LIEF + Ghidra | Unicorn mode | Yes (analysis), Partial (execution) |
| PE (ARM) | Qiling | LIEF + Ghidra | Unicorn mode | Analysis only |
| Mach-O (x86_64) | Darling | LIEF + Ghidra | Unicorn mode | Experimental |
| Mach-O (ARM64) | Darling | LIEF + Ghidra | Unicorn mode | Very experimental |

### Recommendation
- **Phase 1**: Focus on ELF binaries (95%+ of firmware targets)
- **Phase 2**: Add PE static analysis (LIEF + Ghidra already work)
- **Phase 3**: Add PE emulation via Wine-CE (if demand exists)
- **Defer**: Mach-O emulation (too experimental, very niche for firmware)
