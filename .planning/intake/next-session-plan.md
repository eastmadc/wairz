# Wairz Master Plan

> Created: 2026-04-01
> Updated: 2026-04-13 (session 34 — upload fix, YARA verified, deep research)
> Resume with: /do continue

---

## Session 34 Handoff (2026-04-13)

**What was done:**
1. Committed S33 deployment changes (`10a191d`) — binwalk3 source build, parameterized ports, learned rules 7-10
2. Verified YARA scanning fully operational — 4,990 rules loaded (YARA Forge + 4 built-in), `scan_with_yara` MCP tool works end-to-end
3. Fixed firmware upload 413 error — `MAX_UPLOAD_SIZE_MB` raised from 500→2048 across config.py, frontend/Dockerfile, .env.example, .env. Nginx now allows 2GB uploads. Root cause: 1.14GB Android tablet image exceeded 500MB limit.
4. Extracted session 34 knowledge files

**Uncommitted S34 changes:**
- backend/app/config.py — max_upload_size_mb default 500→2048
- frontend/Dockerfile — ENV MAX_UPLOAD_SIZE_MB 500→2048
- .env.example — MAX_UPLOAD_SIZE_MB=2048
- CLAUDE.md — updated max upload size docs
- .planning/knowledge/session34-upload-413-{patterns,antipatterns}.md (new)

**Discoveries during S34 research:**
- Binary diff enhancement campaign code is ALREADY FULLY IMPLEMENTED (LIEF function hashing, Capstone instruction diffs, frontend diff viewer with 5 diff types). Campaign file outdated — mark as completed.
- Security Hardening Phase 1 (YARA) is DONE — yara-python installed, 4990 rules, scan_with_yara works. Mark campaign as fully completed.
- No comparison service unit tests exist (gap).
- Frontend container has no healthcheck in docker-compose.yml.
- No log rotation configured for any container.
- No resource limits on backend/worker containers.

---

## Priority Work for S35

### 1. Commit S34 changes (5 min)
Stage and commit the upload limit fix and knowledge files.

### 2. Production Hardening (1-2 hours) — HIGH IMPACT
The stack is deployed and being used by real users. These are the gaps:

**A. Docker log rotation (all containers)**
Add `logging` driver with `max-size`/`max-file` to prevent disk fill.

**B. Frontend healthcheck**
Add nginx healthcheck to docker-compose.yml (all other services have one).

**C. Backend/worker resource limits**
Add memory limits to prevent OOM from large firmware processing.

**D. Redis sysctl tuning**
Add `vm.overcommit_memory=1` sysctl or Redis config to prevent background save failures.

### 3. Comparison Service Unit Tests (1 hour) — COVERAGE GAP
No unit tests for `comparison_service.py` — the most complex service with LIEF, Capstone, and Ghidra integration. Write tests for:
- `diff_filesystems()` — added/removed/modified detection
- `diff_binary()` — LIEF function hashing, section fallback for stripped binaries
- `diff_function_instructions()` — Capstone disassembly diff
- `diff_text_file()` — unified diff output

### 4. Campaign Housekeeping (15 min)
- Mark binary-diff-enhancement campaign as completed (code already exists)
- Mark security-hardening Phase 1 as completed (YARA verified)
- Update campaign completion count: 14/15 → only Device Acquisition v2 Phase 10 blocked

### 5. CI/CD Pipeline (Phase 5.2) — if time permits
- SARIF output from vulnerability scans
- Configurable severity thresholds
- Docker image size optimization

---

## Blocked
- Device Acquisition v2 Phase 10 — needs physical MediaTek device in BROM mode

## Project Status After S34
- Campaigns: ~14/15 completed (93%+), only Device Acquisition v2 Phase 10 hardware-blocked
- MCP tools: 160+
- Stack: deployed and operational on x86_64 Ubuntu 22.04
- Upload limit: 2GB (was 500MB)
- YARA scanning: verified working
