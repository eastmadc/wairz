# Plan: Attack Surface Map + Script SAST

> Created: 2026-04-08
> Priority: Critical (force multiplier for all downstream tools)
> Effort: 2 sessions
> Source: Ouroboros interview (10 rounds) + Citadel research fleet (4 scouts)
> Dependencies: None (standalone)

---

## Strategic Context

Deep research (Ouroboros strategic interview + Citadel competitive analysis + 4 parallel
technical research agents) identified the **attack surface map** as the highest-leverage
feature for Wairz. It's a force multiplier: every downstream tool (cwe_checker, ShellCheck,
fuzzing, threat intel) becomes more effective when it knows which binaries to prioritize.

Competitive gap analysis found that EMBA has cwe_checker (S17) and script SAST (S20-S22)
that Wairz lacks. FACT has input vector detection. No tool has a persistent, scored attack
surface map with auto-finding generation.

## Session 1: Fleet Wave (Two Parallel Tracks)

### Track A: Attack Surface Map

**Goal:** Persistent attack surface map that runs in the analysis pipeline (after SBOM
generation), scores every ELF binary by attack surface, auto-generates findings for
dangerous signal combinations, and provides an MCP tool facade for Claude to query.

**V1 Signals (scored 0-100):**

| Signal | Detection Method | Weight |
|--------|-----------------|--------|
| Network listener | ELF imports: socket, bind, listen, accept, select, poll, epoll_create | 5x |
| CGI/HTTP handler | Path patterns: /www/cgi-bin/*, /tmp/www/* + QUERY_STRING env check | 4x |
| Setuid/setgid | File permission bits (st_mode) | 3x |
| Dangerous imports | system, popen, strcpy, sprintf, gets, execve, dlopen | 2x |
| Custom/proprietary | NOT in SBOM component list = likely vendor-specific | 2x bonus |
| Known daemon name | uhttpd, lighttpd, nginx, dropbear, telnetd, dnsmasq, mosquitto, etc. | Auto-classify as network-facing |

**Scoring formula:** `sum(signal_weight * signal_matches) * privilege_multiplier`
- privilege_multiplier: 3x for setuid, 2x for init-script-launched, 1x otherwise
- Normalize to 0-100 range

**Severity thresholds (frontend badge colors):**
- 75-100: Critical (red)
- 50-74: High (orange)
- 25-49: Medium (yellow)
- 0-24: Low (gray)

**Auto-finding rules:**

| Signal Combination | Severity | CWE | Finding Title |
|---|---|---|---|
| Network listener + no ASLR + no stack canary | High | CWE-119 | Network-exposed binary lacks memory protections |
| Setuid + imports system()/popen() | High | CWE-78 | Privileged binary uses dangerous exec functions |
| CGI handler + no input validation imports | Medium | CWE-20 | CGI binary has no visible input sanitization |
| Network listener + setuid + imports strcpy() | Critical | CWE-120 | Privileged network service uses unsafe string functions |
| Debug symbols in production binary | Low | CWE-215 | Debug information exposed in production binary |

**Architecture:** Persistent table (like SBOM). MCP tool `detect_input_vectors` queries stored data.
Frontend "Attack Surface" tab with sortable table showing score, badge, binary name, signal breakdown.

**Database schema:**
```sql
CREATE TABLE attack_surface_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    firmware_id UUID NOT NULL REFERENCES firmware(id) ON DELETE CASCADE,
    binary_path TEXT NOT NULL,
    binary_name TEXT NOT NULL,
    architecture TEXT,
    attack_surface_score INTEGER NOT NULL DEFAULT 0,
    score_breakdown JSONB NOT NULL DEFAULT '{}',
    is_setuid BOOLEAN NOT NULL DEFAULT FALSE,
    is_network_listener BOOLEAN NOT NULL DEFAULT FALSE,
    is_cgi_handler BOOLEAN NOT NULL DEFAULT FALSE,
    has_dangerous_imports BOOLEAN NOT NULL DEFAULT FALSE,
    dangerous_imports JSONB DEFAULT '[]',
    input_categories JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX ix_attack_surface_project_firmware_score
    ON attack_surface_entries (project_id, firmware_id, attack_surface_score DESC);
```

**MCP tools:**

1. `detect_input_vectors` — Bulk scan firmware, store results, return ranked table
2. `analyze_binary_attack_surface` — Single binary deep dive (categorized imports, device paths, init script refs, setuid status, score + breakdown)

**Files to create/modify:**

| File | Change |
|------|--------|
| `backend/app/models/attack_surface.py` | New: SQLAlchemy model |
| `backend/app/schemas/attack_surface.py` | New: Pydantic schemas |
| `backend/app/services/attack_surface_service.py` | New: scanning logic (~300 lines) |
| `backend/app/ai/tools/attack_surface.py` | New: MCP tool handlers + registration |
| `backend/app/ai/__init__.py` | Register attack_surface tools |
| `backend/app/routers/attack_surface.py` | New: REST endpoints (GET list, POST scan) |
| `backend/app/main.py` | Register router |
| `alembic/versions/xxx_add_attack_surface.py` | Migration |
| `frontend/src/api/attackSurface.ts` | New: API client |
| `frontend/src/components/security/AttackSurfaceTab.tsx` | New: ranked table with badges |
| `frontend/src/pages/SecurityScanPage.tsx` | Add Attack Surface tab |

### Track B: ShellCheck + Bandit SAST

**Goal:** Two new static analysis tools for shell and Python scripts, integrated into the
findings system and automated assessment pipeline.

**ShellCheck:**
- Install: static binary from GitHub releases into backend Docker image (~2MB, zero deps)
- Discovery: shebang detection (#!/bin/sh, #!/bin/bash, #!/bin/ash) + .sh/.ash extension + extensionless files in /etc/init.d/, /www/cgi-bin/ with shell shebangs
- Invocation: `shellcheck -f json1 -S warning -s sh` per-file via asyncio.create_subprocess_exec
- Output: parsed JSON, security-relevant SC codes (SC2086, SC2091, SC2046, SC2059) mapped to CWE-78
- Auto-findings: written via add_finding, source="shellcheck"
- Integration: added to run_full_assessment pipeline alongside Semgrep

**Bandit:**
- Install: `pip install bandit` in backend container
- Discovery: shebang detection (#!/usr/bin/python*) + .py extension
- Invocation: `bandit -r {dir} -f json -ll` (medium+ severity)
- Output: parsed JSON, CWE mappings preserved from Bandit's native output
- Auto-findings: written via add_finding, source="bandit"
- Integration: same as ShellCheck

**MCP tools:**
1. `shellcheck_scan` — Run ShellCheck on shell scripts, return classified findings
2. `bandit_scan` — Run Bandit on Python scripts, return classified findings

**Files to create/modify:**

| File | Change |
|------|--------|
| `backend/app/ai/tools/security.py` | Add shellcheck_scan + bandit_scan handlers |
| `backend/app/services/security_audit_service.py` | Add ShellCheck + Bandit to audit pipeline |
| `backend/app/routers/tools.py` | Whitelist shellcheck_scan, bandit_scan |
| `backend/Dockerfile` | Install shellcheck binary + bandit pip package |

## Session 2: cwe_checker Integration

**Goal:** Static binary CWE detection via cwe_checker Docker sidecar, auto-fed from
attack surface map (top-N binaries).

**Key details from research:**
- 18 CWE checks (buffer overflow, format string, UAF, null deref, dangerous functions, etc.)
- Requires its own Ghidra (bundles v11.2 with p_code_extractor plugin)
- Docker sidecar pattern (like VulHunt, emulation containers)
- ARM64 blocker: upstream image is amd64-only, need native build on RPi
- Performance: 2-15 min per binary, cache by SHA-256 in analysis_cache
- "Fast mode": lightweight heuristic checks only (CWE-676, CWE-215, CWE-332, CWE-560) — seconds

**MCP tools:**
1. `cwe_check_binary` — Single binary analysis (with check selection + timeout)
2. `cwe_check_firmware` — Batch: top-N binaries from attack surface map
3. `cwe_check_status` — Docker image availability check

**Auto-feed wiring:** `cwe_check_firmware` reads attack surface map, runs cwe_checker
on top-20 binaries sorted by attack_surface_score DESC.

## Quick Wins (Anytime, Independent)

### YARA Forge Community Rules (~1 hour)
- Download yara-forge-rules-core.yar from GitHub releases
- Modify yara_service.py to load alongside custom rules
- 26 rules → thousands, zero cost, zero privacy risk

### DTB Parser (~2-3 hours)
- New file: backend/app/ai/tools/devicetree.py
- Two tools: find_device_trees (magic 0xD00DFEED scan), parse_device_tree (dtc -I dtb -O dts)
- dtc already installed, zero new deps
- Reveals UART pins, JTAG, TrustZone config, peripheral bus topology

## Deferred (Documented for Future)

- UI-level priority override for attack surface entries
- Config cross-reference detection (Path 2: parse init scripts for port bindings)
- Emulation-assisted detection (Path 3: netstat after boot)
- Automated cascade pipeline (Option C: attack surface → auto-trigger all downstream)
- set_binary_priority MCP tool
- Threat intelligence campaign (ClamAV, VT, abuse.ch, CIRCL) — separate 2-3 session Archon campaign

## Acceptance Criteria

### Session 1 Track A
1. `detect_input_vectors` returns scored, ranked table for a real firmware image
2. Scores range from 0-100 with correct badge thresholds
3. Network listeners (uhttpd, dnsmasq) rank highest
4. Auto-findings generated for dangerous signal combinations
5. Frontend Attack Surface tab displays sortable table with colored badges
6. Data persists in database, survives page reload

### Session 1 Track B
1. `shellcheck_scan` detects unquoted variable injection (SC2086) in real firmware scripts
2. `bandit_scan` detects subprocess shell=True in Python scripts
3. Findings written to findings table with correct CWE mappings
4. Both tools integrated into run_full_assessment pipeline
5. Results visible in SecurityScanPage

### Session 2
1. cwe_checker Docker image built and running on ARM64
2. `cwe_check_binary` returns CWE warnings for a real ELF binary
3. `cwe_check_firmware` auto-selects top binaries from attack surface map
4. Results cached by binary hash in analysis_cache
5. Findings written with source="cwe_checker"
