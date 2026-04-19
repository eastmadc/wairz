# Campaign: Standalone Binary Environment Synthesis

Status: complete
Started: 2026-04-04T12:00:00Z
Completed: 2026-04-04
Direction: Add support for emulating and fuzzing standalone binaries (uploaded without rootfs). Auto-detect architecture, resolve dependencies, synthesize sysroot, adapt emulation/fuzzing pipelines.

## Phases
1. [complete] Backend: Binary Analysis Service (LIEF integration + firmware upload pipeline)
2. [complete] Sysroot Management Service + Dockerfile updates
3. [complete] Emulation Service standalone binary mode
4. [complete] Fuzzing Service standalone binary mode
5. [complete] Frontend updates
6. [complete] MCP tool updates

## Feature Ledger
| Feature | Status | Phase |
|---------|--------|-------|
| binary_analysis_service.py | complete | 1 |
| lief dependency | complete | 1 |
| Firmware model binary_info JSONB field | complete | 1 |
| firmware upload arch detection (ELF + PE + fallback) | complete | 1 |
| Alembic migration (merge heads + binary_info) | complete | 1 |
| sysroot_service.py | complete | 2 |
| emulation/scripts/build-sysroots.sh | complete | 2 |
| emulation Dockerfile sysroot stage | complete | 2 |
| emulation standalone mode (container flags, QEMU_LD_PREFIX) | complete | 3 |
| start-user-mode.sh QEMU_LD_PREFIX support | complete | 3 |
| WebSocket terminal standalone mode | complete | 3 |
| exec_command standalone mode | complete | 3 |
| fuzzing QEMU_LD_PREFIX for standalone binaries | complete | 4 |
| fuzzing triage QEMU_LD_PREFIX for standalone binaries | complete | 4 |
| fuzzing Dockerfile sysroot stage | complete | 4 |
| ProjectDetailPage binary info display + standalone badge | complete | 5 |
| EmulationPage standalone binary indicator + pre-fill | complete | 5 |
| Frontend BinaryInfo type | complete | 5 |
| MCP analyze_binary_format tool (LIEF-based) | complete | 6 |
| MCP emulation start standalone mode output | complete | 6 |
| MCP fuzzing analyze_target standalone info | complete | 6 |

## Decision Log
- 2026-04-04: Using LIEF for multi-format binary parsing (ELF+PE+Mach-O unified API). pyelftools as fallback for ELF. LIEF v0.16.1 API verified (ARCH.I386 not i386, Header.ELF_DATA not ELF.ELF_DATA).
- 2026-04-04: Storing binary analysis results as JSONB in firmware.binary_info field -- lightweight, extensible, avoids join overhead. Only set for standalone binaries, never for firmware with rootfs.
- 2026-04-04: Using Debian multiarch packages for sysroot creation -- libc6 + libgcc-s1 per arch. Sysroots at /opt/sysroots/<arch>/lib/ in both emulation and fuzzing containers.
- 2026-04-04: Primary tier: ARM, AArch64, MIPS, MIPSel, x86 (covers 95%+ of firmware binaries). x86_64 supported but conditional on host arch.
- 2026-04-04: Standalone mode detection uses container flag files (/tmp/.standalone_mode, /tmp/.standalone_arch, /tmp/.standalone_static) -- avoids passing state through DB for exec_command and WebSocket.
- 2026-04-04: Static binaries skip sysroot entirely -- run directly with qemu-<arch>-static.
- 2026-04-04: Merged two Alembic migration heads (c4d5e6f7a8b9 + 81f49fd099f5) in the binary_info migration.

## Files Modified
### New files
- backend/app/services/binary_analysis_service.py
- backend/app/services/sysroot_service.py
- emulation/scripts/build-sysroots.sh
- fuzzing/sysroots/build-sysroots.sh
- backend/alembic/versions/g7b8c9d0e1f2_add_binary_info_to_firmware.py

### Modified files
- backend/pyproject.toml (added lief>=0.15.0)
- backend/app/models/firmware.py (added binary_info JSONB column)
- backend/app/schemas/firmware.py (added BinaryInfoResponse, binary_info field)
- backend/app/workers/unpack_common.py (added binary_info to UnpackResult)
- backend/app/workers/unpack.py (LIEF analysis for ELF/PE + fallback paths)
- backend/app/workers/arq_worker.py (store binary_info)
- backend/app/routers/firmware.py (store binary_info)
- backend/app/services/device_service.py (store binary_info)
- backend/app/services/emulation_service.py (standalone mode: container flags, QEMU_LD_PREFIX, build_user_shell_cmd, exec_command)
- backend/app/services/fuzzing_service.py (standalone mode: sysroot QEMU_LD_PREFIX, triage)
- backend/app/routers/emulation.py (WebSocket terminal standalone mode)
- backend/app/ai/tools/binary.py (analyze_binary_format tool)
- backend/app/ai/tools/emulation.py (standalone mode output)
- backend/app/ai/tools/fuzzing.py (standalone binary info in analyze_target)
- emulation/Dockerfile (sysroot builder stage)
- emulation/scripts/start-user-mode.sh (QEMU_LD_PREFIX support)
- fuzzing/Dockerfile (sysroot builder stage)
- frontend/src/types/index.ts (BinaryInfo interface)
- frontend/src/pages/ProjectDetailPage.tsx (binary info display, standalone badge)
- frontend/src/pages/EmulationPage.tsx (standalone indicator, binary path pre-fill)
