---
name: router
description: Session bootstrap and navigation hub. Read at the start of every session before any task. Contains project state, routing table, and behavioural contract.
edges:
  - target: context/architecture.md
    condition: when working on system design, integrations, or understanding how components connect
  - target: context/stack.md
    condition: when working with specific technologies, libraries, or making tech decisions
  - target: context/conventions.md
    condition: when writing new code, reviewing code, or unsure about project patterns
  - target: context/decisions.md
    condition: when making architectural choices or understanding why something is built a certain way
  - target: context/setup.md
    condition: when setting up the dev environment or running the project for the first time
  - target: context/mcp-tools.md
    condition: when adding, modifying, or debugging MCP tool handlers
  - target: patterns/INDEX.md
    condition: when starting a task — check the pattern index for a matching pattern file
last_updated: 2026-04-17
---

# Session Bootstrap

If you haven't already read `AGENTS.md`, read it now — it contains the project identity, non-negotiables, and commands.

Then read this file fully before doing anything else in this session.

## Current Project State

**Working:**
- MCP server (`wairz-mcp`) with 65+ tools across 19 categories (filesystem, binary, security, sbom, emulation, fuzzing, android, android_bytecode, android_sast, uart, uefi, vulhunt, attack_surface, cwe_checker, comparison, documents, network, reporting, strings).
- Firmware upload + unpacking pipeline (binwalk3 + unblob, multi-partition, SquashFS/JFFS2/UBIFS/CramFS/ext/CPIO/Intel HEX).
- React 19 SPA with pages for Projects, ProjectDetail, Explore (file tree + Monaco viewer), ComponentMap (ReactFlow graph), Emulation, Fuzzing, SBOM, Findings, SecurityScan, SecurityTools, Comparison, DeviceAcquisition, Help.
- Standalone APK upload + classification (recent commit 370b312).
- Docker socket-based sidecar launch for QEMU emulation, AFL++ fuzzing, FirmAE system-mode.
- Host-side UART bridge (port 9999) and device acquisition bridge (port 9998).
- Redis-backed arq job queue + SSE event bus (polling fallback if Redis is down).
- 22 learned rules codified in CLAUDE.md, surfaced in `context/conventions.md` Verify Checklist.
- Backend + frontend host ports bound to 127.0.0.1 by default (LAN-exposure mitigation for the unauthenticated `/ws` WebSocket, session 59045370 commit 10872d6).
- Postgres + FirmAE passwords parameterized via env vars with backward-compatible defaults (session 59045370 commit 906cfe2).
- `analysis_cache.operation` widened to VARCHAR(512) via alembic 1f6c72decc84 (session 59045370 commit e3053b6).
- Binwalk3 escape-symlink artifact cleanup in the unpack fallback chain (session 59045370 commit 90ed79c) — prevents the "extraction succeeded but only a symlink exists" bug that surfaced on the PowerPack firmware.

**Not yet built (per intake queue):**
- Android hardware firmware detection (modem/TEE/Wi-Fi/GPU/DSP/drivers) — campaign planned.
- APK deep-linking scan.
- Backend decomposition of god-class services, shared cache module extraction, circular-import break-up.
- Schema drift fixes (findings/firmware/CRA), CHECK/UNIQUE constraints, pagination on unbounded list endpoints.
- Frontend code splitting + list virtualisation, `useFirmwareList` hook dedup, store isolation + project-id guards.
- Docker socket proxy, volume quotas + postgres backup.

**Known issues:**
- `cwe_checker` tool shares an AsyncSession across `asyncio.gather` (fix queued as `backend-cwe-checker-session-fix`).
- Double-shell injection risk in fuzzing service at `fuzzing_service.py:532` and `:827` (queued as `security-fuzzing-shell-injection`).
- Android OTA/ZIP extraction needs hardening — per-entry realpath + symlink-escape checks missing (queued as `security-android-unpack-hardening`).
- WebSocket endpoints bypass `BaseHTTPMiddleware`-based auth; `/ws` is unauthenticated (queued as `security-auth-hardening`). A.1 loopback bind is a network-layer mitigation; pure-ASGI middleware is the real fix.
- Raw bare-metal firmware >10 MB (medical/automotive) with no recognisable container falls outside the standalone-binary copy path (`_STANDALONE_BINARY_MAX` in `unpack.py:771`). User may want to analyse a 268 MB raw blob; current code refuses past the limit.

## Routing Table

Load the relevant file based on the current task. Always load `context/architecture.md` first if not already in context this session.

| Task type | Load |
|-----------|------|
| Understanding how the system works | `context/architecture.md` |
| Working with a specific technology | `context/stack.md` |
| Writing or reviewing code | `context/conventions.md` |
| Making a design decision | `context/decisions.md` |
| Setting up or running the project | `context/setup.md` |
| Adding or debugging an MCP tool | `context/mcp-tools.md` |
| Any specific task | Check `patterns/INDEX.md` for a matching pattern |

## Behavioural Contract

For every task, follow this loop:

1. **CONTEXT** — Load the relevant context file(s) from the routing table above. Check `patterns/INDEX.md` for a matching pattern. If one exists, follow it. Narrate what you load: "Loading architecture context..."
2. **BUILD** — Do the work. If a pattern exists, follow its Steps. If you are about to deviate from an established pattern, say so before writing any code — state the deviation and why.
3. **VERIFY** — Load `context/conventions.md` and run the Verify Checklist item by item. State each item and whether the output passes. Do not summarise — enumerate explicitly.
4. **DEBUG** — If verification fails or something breaks, check `patterns/INDEX.md` for a debug pattern. Follow it. Fix the issue and re-run VERIFY.
5. **GROW** — After completing the task:
   - If no pattern exists for this task type, create one in `patterns/` using the format in `patterns/README.md`. Add it to `patterns/INDEX.md`. Flag it: "Created `patterns/<name>.md` from this session."
   - If a pattern exists but you deviated from it or discovered a new gotcha, update it with what you learned.
   - If any `context/` file is now out of date because of this work, update it surgically — do not rewrite entire files.
   - Update the "Current Project State" section above if the work was significant.
