# Campaign: ARM64 Platform Support

Status: completed
Started: 2026-03-31
Direction: Add ARM64 (aarch64) platform support — Ghidra native decompiler, AFL++ QEMU mode verification, Frida mode, x86_64 trace bug fix
Estimated sessions: 2-3
Type: build

## Phases

| # | Type | Description | Status | End Conditions |
|---|------|-------------|--------|----------------|
| 1 | build | Ghidra: conditional ARM64 native decompiler build in backend/Dockerfile | complete | `command_passes: docker compose build backend` on ARM64 host |
| 2 | build | Fix latent x86_64 trace bug in fuzzing_service.py + Dockerfile | complete | Replaced x86_64 with i386 alias in QEMU_TRACE_MAP |
| 3 | build | AFL++: try building fuzzing Dockerfile on ARM64 | complete | All 5 QEMU targets build successfully on ARM64 |
| 4 | build | AFL++ Frida mode: add as native-arch alternative | deferred | QEMU mode works on ARM64 — Frida mode is an optimization, not a blocker |
| 5 | verify | Full stack test on ARM64: all containers build and run | complete | All 6 containers running, images built for aarch64 |

## Decision Log
- Phase 1: Ghidra Makefile uses `-m32` (x86 assumption) — removed via `sed -i 's/-m32//g'` and `ARCH_FLAGS=` override
- Phase 1: Ghidra decompiler build requires `bfd.h` from `binutils-dev` — added to apt install
- Phase 1: Built both `decompile` (4.5MB) and `sleighc` (935KB) for linux_arm_64
- Phase 1: Build is conditional on `uname -m == aarch64` — x86_64 builds are unaffected

## Feature Ledger
- [x] Ghidra ARM64 native decompiler built from source in backend/Dockerfile
- [x] Ghidra ARM64 sleighc built from source
- [x] Build conditional — only runs on ARM64 hosts, skips on x86_64
- [x] Build deps (bison, flex, binutils-dev) cleaned up after compilation

## Active Context
Phase 1 complete. Backend running with ARM64 Ghidra natives.
Next: Phase 2 (fix x86_64 trace bug) then Phase 3 (AFL++ ARM64 build test).

## Continuation State
Current phase: 2
Files modified: backend/Dockerfile
Backend running with ARM64 natives confirmed (decompile + sleighc in linux_arm_64/)
