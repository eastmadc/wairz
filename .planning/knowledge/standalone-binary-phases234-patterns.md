# Patterns: Standalone Binary Support - Phases 2, 3, 4

> Extracted: 2026-04-06
> Campaign: .planning/campaigns/standalone-binary-phases234.md
> Postmortem: none

## Successful Patterns

### 1. Specialized Library Over Generic Framework
- **Description:** Used pefile (specialized PE library) instead of extending LIEF (generic binary framework) for PE static analysis. Pefile provides section entropy, authenticode verification, per-DLL import lists — deeper than LIEF's generic binary interface.
- **Evidence:** Decision log: "pefile provides more detailed PE internals than LIEF." Phase 2 completed without rework.
- **Applies when:** Choosing between a specialized library (deep coverage of one format) and a generic framework (shallow coverage of many). If the feature requires format-specific details (PE authenticode, ELF RELRO, Mach-O entitlements), use the specialized library.

### 2. In-Process Emulation for Non-Interactive Formats
- **Description:** Ran Qiling (PE/Mach-O emulator) in-process via `run_in_executor()` instead of spinning up a Docker container. PE/Mach-O emulation is batch (not interactive), so no terminal/WebSocket needed.
- **Evidence:** Decision log: "Qiling runs in-process: no Docker container needed." Phase 4 used thread pool execution. Output displayed as text log.
- **Applies when:** Emulation is short-lived and non-interactive. Avoid Docker overhead for batch analysis. Only use Docker containers when: long-running, needs isolation, or requires privileged operations.

### 3. Auto-Detecting Mode from Binary Format
- **Description:** Service auto-detects PE/Mach-O binaries and switches from user-requested "user" mode to "qiling" mode internally, rather than exposing mode complexity to the user.
- **Evidence:** Decision log: "user sends 'user' mode, service auto-detects PE/Mach-O and switches to 'qiling' internally." Transparent UX.
- **Applies when:** Multiple emulation backends serve different binary formats. The user shouldn't need to know which backend handles their binary — auto-detection based on magic bytes or file type is better UX.

### 4. Heuristic Fallback for Unavailable Tools
- **Description:** When cpu_rec (statistical architecture detector) is unavailable, fallback to basic instruction pattern matching that provides low-confidence architecture candidates instead of failing.
- **Evidence:** Decision log: "Heuristic fallback for arch detection." `detect_raw_architecture()` works with or without cpu_rec.
- **Applies when:** An optional tool provides high-quality results but isn't always available. Implement a degraded-but-functional fallback rather than hard-failing when the optimal tool is missing.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| pefile over LIEF for PE analysis | Deeper PE internals (entropy, authenticode, per-DLL imports) | Worked — richer analysis than LIEF alone |
| cpu_rec from git, not pip | Not published to PyPI | Worked — installed to /opt/cpu_rec in Docker |
| Qiling in-process, not Docker | PE/Mach-O emulation is batch, not interactive | Worked — simpler, lower overhead |
| Qiling mode is batch text output | No terminal needed for non-interactive execution | Worked — output displayed as scrollable log |
| Auto-mode switching for PE/Mach-O | Users shouldn't need to pick emulation backend | Worked — transparent to user |
| Windows DLLs not bundled | Licensing prevents bundling Windows system DLLs | Correct — users mount their own rootfs |
