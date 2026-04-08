# Plan: Firmware Update Mechanism Static Detection

> Created: 2026-04-08
> Priority: High (CRA Annex I prerequisite)
> Effort: Medium (1 session)
> Dependencies: None (standalone, feeds into CRA compliance report)
> Session: S22

---

## Goal

Add a `detect_update_mechanisms` MCP tool that scans firmware filesystems for update mechanisms, catalogs them, and reports their presence/absence. Static detection and cataloging only — security property analysis (signature verification, encryption, rollback protection) deferred to a follow-up session.

## Strategic Context

EU CRA Annex I Part 1 requires products to have secure update mechanisms. Before we can assess update security (S23+ CRA compliance), we need to know *what* update mechanisms exist. EMBA's S09 module is version-centric (what version is installed), not mechanism-centric (how updates work). This is a differentiated capability.

Existing YARA rule `Suspicious_Firmware_Modification` in `suspicious_patterns.yar` already catches `--no-check` and `--force` flags on update commands. The new service builds on this but goes much deeper.

## Current State

- YARA rule detects insecure update patterns (`fwupgrade`, `firmware_update`, `sysupgrade`, `flashcp`, `dd /dev/mtd` with dangerous flags)
- `check_secure_boot` analyzes boot chain integrity (U-Boot FIT, dm-verity, UEFI Secure Boot)
- `analyze_init_scripts` parses init scripts but doesn't extract update mechanisms
- SBOM generation detects package managers (opkg, dpkg) via `sbom_service.py`
- No dedicated update mechanism detection or cataloging

## Implementation Plan

### Step 1: Create `update_mechanism_service.py`

New service: `backend/app/services/update_mechanism_service.py` (~300-400 lines)

**Detection targets:**

| Update System | Detection Method | Config Paths |
|---|---|---|
| **SWUpdate** | Binary `swupdate` in PATH, `/etc/swupdate.cfg`, `.swu` files | `/etc/swupdate.cfg`, `/etc/swupdate/` |
| **RAUC** | Binary `rauc` in PATH, `/etc/rauc/system.conf`, bundle files | `/etc/rauc/system.conf` |
| **Mender** | Binary `mender` or `mender-client`, config file | `/etc/mender/mender.conf`, `/var/lib/mender/` |
| **opkg** | Binary `opkg`, `sysupgrade` script | `/etc/opkg.conf`, `/etc/opkg/`, `/sbin/sysupgrade` |
| **U-Boot env** | `fw_setenv`/`fw_printenv` binaries, env vars with update commands | Parse `fw_printenv` output or `/etc/fw_env.config` |
| **Android OTA** | `/system/bin/update_engine`, recovery partition, `update.zip` patterns | `/cache/recovery/`, `META-INF/com/google/android/` |
| **Custom OTA** | Scripts containing wget/curl + flash/mtd/dd patterns | Init scripts, cron jobs |
| **Package manager** | dpkg, apt, yum, rpm binaries | `/etc/apt/sources.list`, `/etc/yum.repos.d/` |

**Implementation approach:**

1. **Binary scan:** Walk firmware filesystem, check for known update tool binaries
2. **Config parse:** For each detected system, read its config file and extract:
   - Update server URL(s)
   - Update channel (HTTP vs HTTPS)
   - Any certificate/key references
   - Partition layout (A/B scheme detection)
3. **Init script scan:** Grep init scripts and crontabs for update-related commands
4. **U-Boot env scan:** Parse fw_env.config or bootloader env for update commands (`bootcmd`, `altbootcmd`, `upgrade_available`)
5. **Classify each finding:**

| Finding | Severity | CWE | Note |
|---|---|---|---|
| No update mechanism found | High | CWE-1277 | CRA requires update capability |
| HTTP-only update URL | High | CWE-319 | Plaintext firmware download |
| Update URL present (HTTPS) | Info | — | Expected, good practice |
| A/B partition scheme detected | Info | — | Supports rollback |
| No A/B or rollback mechanism | Medium | CWE-1277 | CRA prefers rollback |
| Update cron job found | Info | — | Automatic updates |
| Custom OTA script (wget+flash) | Medium | CWE-494 | Often lacks integrity checks |

6. **Return structured result** grouped by update system, with URLs, config paths, and classification.

### Step 2: Create MCP tools

Register in `backend/app/ai/tools/security.py`:

1. `detect_update_mechanisms` — Full firmware scan, returns cataloged update systems with config details
2. `analyze_update_config` — Deep dive on a specific update system's config (e.g., parse SWUpdate .cfg)

### Step 3: Add REST endpoint

- `GET /api/v1/projects/{pid}/firmware/{fid}/update-mechanisms` — returns detected update mechanisms
- Integrate into SecurityScanPage (new tab or section within existing Security tab)

### Step 4: Add to automated security audit

Add `_scan_update_mechanisms()` to `security_audit_service.py`:
- Flag "no update mechanism" as High severity
- Flag HTTP-only update URLs as High severity
- Flag custom wget+flash scripts as Medium severity

### Step 5: Whitelist tools

Add `detect_update_mechanisms` and `analyze_update_config` to `ALLOWED_TOOLS` in `routers/tools.py`.

## Files to Create/Modify

| File | Change |
|------|--------|
| `backend/app/services/update_mechanism_service.py` | **New:** ~300-400 lines, detection logic |
| `backend/app/ai/tools/security.py` | Add 2 tool handlers + registration |
| `backend/app/routers/security_audit.py` | Add REST endpoint for update mechanisms |
| `backend/app/services/security_audit_service.py` | Add `_scan_update_mechanisms()` to audit |
| `backend/app/routers/tools.py` | Whitelist new tools |

## What NOT to Do

- Do NOT analyze security properties of update mechanisms (signature verification, encryption) — that's a follow-up session
- Do NOT attempt to trigger or test update mechanisms
- Do NOT parse binary-level update logic — stick to filesystem heuristics and config parsing
- Do NOT create a separate router — use existing security_audit router
- Do NOT duplicate YARA rule detection — reference YARA findings, don't re-detect

## Acceptance Criteria

1. `detect_update_mechanisms` correctly identifies opkg/sysupgrade on OpenWrt firmware
2. SWUpdate, RAUC, and Mender configs parsed when present
3. HTTP-only update URLs flagged as High severity
4. "No update mechanism found" flagged for bare-metal/RTOS firmware
5. U-Boot environment parsed for update-related variables
6. Results appear in automated security audit output
7. Tools whitelisted for REST access
