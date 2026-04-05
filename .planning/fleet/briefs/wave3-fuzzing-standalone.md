# Wave 3 Brief: Fuzzing Standalone Binaries

## Scout 3A: AFL++ Capabilities for Standalone Foreign-Arch Binaries

### AFL++ QEMU Mode (-Q flag)
- **How it works**: AFL++ uses a modified QEMU (qemuafl) to instrument basic blocks at runtime
- **Architecture support**: ARM, AArch64, MIPS, MIPSel, i386 (Wairz already builds all five in fuzzing/Dockerfile)
- **Performance**: 2-5x overhead vs native AFL (much better than DynamoRIO/PIN)
- **Instrumentation scope**: Follows only .text section of the first ELF binary (not shared libs by default)

### QEMU Mode with Synthesized Sysroot
- **Critical finding**: AFL++ QEMU mode uses `QEMU_LD_PREFIX` the same way raw QEMU user-mode does
- **Proven pattern**: `QEMU_LD_PREFIX=./squashfs-root/ afl-fuzz -Q -i input/ -o output/ -- ./squashfs-root/usr/sbin/target @@`
- **For standalone binaries**: Set QEMU_LD_PREFIX to the synthesized sysroot (from Wave 2 strategy)
- **For static binaries**: No sysroot needed at all. Just run: `afl-fuzz -Q -i input/ -o output/ -- ./static_binary @@`

### AFL++ Unicorn Mode (-U flag)
- **How it works**: Uses Unicorn engine (CPU-only emulator). No OS, no syscalls.
- **Requires**: A custom harness (Python, C, or Rust) that:
  1. Loads the binary into Unicorn memory
  2. Sets up CPU registers and memory maps
  3. Defines start/end addresses for fuzzing
  4. Provides input injection point
- **Use case**: When QEMU mode fails (no rootfs, no OS support, bare-metal firmware)
- **Performance**: Slower than QEMU mode due to no block chaining
- **Verdict**: Fallback for binaries that cannot run in QEMU user-mode. Requires significant per-target setup.

### LibAFL QEMU (Rust Framework)
- **URL**: https://github.com/AFLplusplus/LibAFL
- **Key advantage**: More flexible than AFL++ QEMU mode. Supports hooking, snapshot-restore, binary-only ASan.
- **Performance**: Outperforms AFL++ QEMU mode in speed and coverage
- **Complexity**: Requires Rust harness development. More setup than `afl-fuzz -Q`.
- **Verdict**: Future upgrade path. Not practical for automated/zero-config fuzzing.

### Practical AFL++ Strategy for Standalone Binaries

| Binary Type | AFL++ Mode | Sysroot | Setup Complexity |
|---|---|---|---|
| Static ELF | QEMU mode (-Q) | None | Zero config |
| Dynamic ELF (known arch) | QEMU mode (-Q) | Synthesized sysroot | Low (auto-generate) |
| Dynamic ELF (unknown deps) | QEMU mode (-Q) | Debian debootstrap | Medium |
| Raw/flat binary | Unicorn mode (-U) | None (custom harness) | High (manual) |
| PE binary | Not supported | N/A | Would need Wine integration |

### Key Configuration for AFL++ with Sysroot
```bash
# Environment
export QEMU_LD_PREFIX=/path/to/synthesized/sysroot
export AFL_INST_LIBS=1  # Also instrument shared libraries (optional)

# Fuzzing
afl-fuzz -Q -i /path/to/seeds -o /path/to/output -- /path/to/binary @@
# Or for stdin input:
afl-fuzz -Q -i /path/to/seeds -o /path/to/output -- /path/to/binary
```

## Scout 3B: Input Format Detection

### The Problem
To fuzz a standalone binary, we must know:
1. Does it read from stdin, files, or network sockets?
2. If files: what's the expected format? (extension, magic bytes, structure)
3. If network: what protocol? what port?

### Static Analysis Approach (Most Practical)

#### Import/Symbol Analysis
Check the binary's imported functions for I/O patterns:

| Import Pattern | Input Source | AFL++ Approach |
|---|---|---|
| `read`, `fread`, `fgets`, `scanf` (fd=0) | stdin | Direct pipe (no @@) |
| `fopen`, `open` + `read`/`fread` | File input | Use @@ for file path |
| `recv`, `recvfrom`, `recvmsg`, `accept` | Network socket | Need desock library |
| `getenv` | Environment variable | Not directly fuzzable |
| `argv` access patterns | Command-line arguments | Fuzz file, pass via @@ |

#### Implementation Strategy
1. Parse binary with LIEF/pyelftools to get import table
2. Check for presence of socket-related imports (recv, accept, bind, listen)
3. Check for file-related imports (fopen, open with mode analysis)
4. Check for stdin-related imports (read on fd 0, fgets with stdin)
5. If socket imports found: recommend desock library (already in Wairz fuzzing container)
6. If file imports found: recommend @@ mode
7. If only stdin: recommend direct pipe mode
8. If ambiguous: default to file mode (@@ is safest default)

#### Wairz Already Has This Partially
- `backend/app/ai/tools/binary.py` already defines `_DEFAULT_SOURCES` and `_DEFAULT_SINKS`
- The `list_imports` tool already extracts import tables
- The `analyze_fuzzing_target` tool in `tools/fuzzing.py` already does target analysis
- Extending this to detect input method is straightforward

### Dynamic Analysis Approach (Advanced, Phase 2)
1. Run binary under strace/ltrace equivalent in QEMU
2. Observe which syscalls are made (read, open, socket, accept)
3. Determine input source from actual behavior
4. More accurate but requires the binary to actually run

### Automated Fuzzing Frameworks Reference

#### OSS-Fuzz / ClusterFuzz
- Uses LLM-based harness synthesis (as of 2025)
- Four-step process: auto-build, program analysis, harness generation, evaluation
- Generated 88 valid OSS-Fuzz integrations from 225 GitHub repos automatically
- Key insight: LLM-based harness generation works for source-available projects but not binary-only

#### PromeFuzz (ACM CCS 2025)
- Knowledge-driven fuzzing harness generation with LLMs
- Academic research on automating harness creation
- Relevant for future Wairz AI-assisted harness generation

### Seed Corpus Generation for Unknown Binaries
When we don't know the input format:
1. **String analysis**: Extract strings from binary, look for file extension patterns (.xml, .json, .cfg, .bin)
2. **Magic byte analysis**: Check if binary references known magic bytes (e.g., PNG header, ZIP header)
3. **Generic seeds**: Start with small random inputs (1-byte, 4-byte, newline-terminated)
4. **Wairz existing tool**: `generate_seed_corpus` in tools/fuzzing.py already handles this
