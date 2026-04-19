# Campaign: Standalone Binary Support - Phases 2, 3, 4

Status: completed
Started: 2026-04-04T00:00:00Z
Completed: 2026-04-04
Direction: Implement PE static analysis, raw binary architecture detection, and Qiling emulation for PE/Mach-O.

## Phases
1. [completed] PE Static Analysis - pefile integration, PE protection checks, MCP tool updates
2. [completed] Raw Binary Architecture Detection - cpu_rec integration, statistical arch detection
3. [completed] Qiling-Based Emulation - qiling service, PE/Mach-O emulation, frontend updates

## Feature Ledger
| Feature | Status | Phase |
|---------|--------|-------|
| pefile dependency | added | 2 |
| check_pe_protections() | implemented | 2 |
| PE-aware analyze_binary_format | extended | 2 |
| PE-aware check_binary_protections | extended | 2 |
| PE fallback in get_binary_info | implemented | 2 |
| cpu_rec Dockerfile install | added | 3 |
| detect_raw_architecture() | implemented | 3 |
| Unpack pipeline raw binary fallback | extended | 3 |
| analyze_raw_binary MCP tool | added | 3 |
| Architecture selector (frontend) | added | 3 |
| ArchCandidate type (frontend) | added | 3 |
| qiling dependency | added | 4 |
| Qiling rootfs Dockerfile install | added | 4 |
| qiling_service.py | created | 4 |
| Qiling integration in emulation_service | implemented | 4 |
| emulate_with_qiling MCP tool | added | 4 |
| check_qiling_rootfs MCP tool | added | 4 |
| Qiling session mode (frontend) | implemented | 4 |
| Qiling output display (frontend) | implemented | 4 |

## Decision Log
- Used pefile instead of extending LIEF for PE analysis: pefile provides more detailed PE internals (section entropy, authenticode, per-DLL imports) than LIEF
- cpu_rec installed from git (not pip): cpu_rec is not on PyPI, installed to /opt/cpu_rec during Docker build
- Heuristic fallback for arch detection: when cpu_rec unavailable, basic instruction pattern matching provides low-confidence candidates
- Qiling runs in-process: no Docker container needed for PE/Mach-O emulation, runs in thread pool via run_in_executor
- Qiling mode is batch: PE/Mach-O execution is not interactive, output displayed as text log instead of WebSocket terminal
- Mode auto-switching: user sends "user" mode, service auto-detects PE/Mach-O and switches to "qiling" internally
- Windows DLLs not bundled: licensing prevents bundling Windows system DLLs; users mount their own
