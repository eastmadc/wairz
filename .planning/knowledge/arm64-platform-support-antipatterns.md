# Anti-patterns: ARM64 Platform Support

> Extracted: 2026-04-15
> Campaign: .planning/campaigns/completed/arm64-platform-support.md

## Failed Patterns

### 1. Assuming Prebuilt Binaries Exist for All Architectures
- **What was done:** Initial approach assumed Ghidra would have ARM64 decompiler binaries available for download.
- **Failure mode:** Ghidra only ships x86_64 native binaries; ARM64 was not available, requiring a from-source build.
- **Evidence:** Phase 1 decision log — had to pivot to compilation.
- **How to avoid:** Before depending on a tool binary, check the tool's release assets for the target architecture. If ARM64 binaries aren't listed, plan for a from-source build.

### 2. Hardcoded Architecture Strings Without Verification
- **What was done:** QEMU_TRACE_MAP used `x86_64` as a key, but QEMU reports `i386` for x86 targets.
- **Failure mode:** Architecture lookup silently fails — trace analysis returns no results without any error.
- **Evidence:** Phase 2 — fixed by replacing `x86_64` with `i386`.
- **How to avoid:** When mapping architecture strings, verify the actual values reported by the tool at runtime (e.g., `qemu-*-static --help` or test output). Don't assume architecture names match platform conventions.
