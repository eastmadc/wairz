# Plan: Network Dependency Mapping

> Created: 2026-04-08
> Priority: High
> Effort: Medium (1 session)
> Dependencies: None (standalone, complements hardcoded IP detection)

---

## Goal

Add a `detect_network_dependencies` MCP tool that produces a structured map of all network mounts, remote filesystems, cloud storage endpoints, database connections, MQTT brokers, and remote service references found in firmware. This reveals the firmware's external dependencies and attack surface.

## Current State

- `analyze_config_security` analyzes single config files but doesn't scan for network mounts
- `find_hardcoded_credentials` detects credentials in connection strings but not connectionless network references
- `credential_patterns.py` has `database_connection_string` pattern (with creds) but misses credential-less connections, cloud URLs, MQTT endpoints
- `analyze_init_scripts` checks init scripts but doesn't extract network dependencies
- YARA rule `IoT_Insecure_Update_Mechanism` partially overlaps with HTTP firmware URLs
- No tool produces a unified "network dependency map" of the firmware
- Gap exists in all major tools (EMBA, firmwalker, FACT) — none provide structured categorized analysis

## Implementation Plan

### Step 1: Create `detect_network_dependencies` tool in `security.py`

**Tool schema:**
```
Name: detect_network_dependencies
Input: { path?: string }  # optional subdirectory filter
Output: Categorized report of all network dependencies
```

**Detection categories and patterns:**

#### A. NFS Mounts
```python
# fstab syntax
r"[\w.\-]+:/[\w/.\-]+\s+/[\w/.\-]+\s+nfs[4]?"
# mount commands in scripts
r"mount\s+(?:-t\s+nfs[4]?\s+)?[\w.\-]+:/[\w/.\-]+"
# NFS exports (device sharing data)
r"^/[\w/.\-]+\s+[\w.*]+\("
# URL scheme
r"nfs://[\w.\-:]+/"
```
Key files: `/etc/fstab`, `/etc/exports`, `/etc/auto.*`, init scripts

#### B. SMB/CIFS Mounts
```python
# Unix style
r"//[\w.\-]+/[\w.\-$]+"
# Windows style in configs
r"\\\\[\w.\-]+\\[\w.\-$]+"
# Credential exposure in mount options (CRITICAL)
r"(?:username|user|password|pass|credentials)=\S+"
# mount commands
r"mount\s+(?:-t\s+cifs\s+)?//[\w.\-]+/"
```
**Critical:** CIFS mount options in `/etc/fstab` frequently contain `username=` and `password=` inline in world-readable files (CWE-256, CWE-798).

#### C. Cloud Storage Endpoints
```python
# AWS S3
r"s3://[\w.\-]+/?"
r"[\w.\-]+\.s3[\.\-][\w.\-]*amazonaws\.com"
# Azure Blob
r"[\w.\-]+\.blob\.core\.windows\.net"
# Google Cloud Storage
r"gs://[\w.\-]+/?"
r"storage\.googleapis\.com/[\w.\-]+"
```

#### D. Database Connection Strings
```python
# URI-style connections (without embedded credentials — those are caught by credential_patterns.py)
r"(?:mongodb|mysql|postgres|redis|amqp|influxdb)://[\w.\-]+(?::\d+)?(?:/\w+)?"
# CLI patterns
r"(?:mysql|psql|redis-cli|mongo)\s+(?:-h|--host)\s+[\w.\-]+"
# Well-known ports
r"[\w.\-]+:(?:3306|5432|6379|27017|5672|1883|8883|9092|2181)\b"
```

#### E. MQTT/AMQP Brokers
```python
# URL schemes
r"mqtt[s]?://[\w.\-]+(?::\d+)?"
r"amqp[s]?://[\w.\-]+(?::\d+)?"
# mosquitto config
r"(?:address|host|connection)\s+[\w.\-]+"
# CLI commands
r"mosquitto_(?:pub|sub)\s+.*-h\s+[\w.\-]+"
```

#### F. FTP/TFTP (Firmware Updates)
```python
r"[ts]?ftp://[\w.\-]+(?::\d+)?/[\w/.\-]+"
r"(?:tftp|ftpget|ftpput|wget|curl)\s+.*[ts]?ftp://"
# Busybox
r"ftp(?:get|put)\s+(?:-v\s+)?[\w.\-]+"
```

#### G. Remote Syslog
```python
# rsyslog remote destinations (@ = UDP, @@ = TCP)
r"@+[\w.\-]+(?::\d+)?"
# syslog-ng
r'destination\s+.*host\s*\(\s*"[\w.\-]+"'
```

#### H. iSCSI Targets
```python
r"iqn\.\d{4}-\d{2}\.[\w.\-:]+"
```

### Step 2: Implementation approach

The tool should:

1. **Scan specific config files first** (high-confidence parsing):
   - Parse `/etc/fstab` line-by-line: extract filesystem type, server, mount options
   - Parse `/etc/exports`: extract NFS shares and allowed networks
   - Parse `/etc/samba/smb.conf`: extract share definitions
   - Parse `/etc/auto.master`, `/etc/auto.*`: autofs configurations
   - Check for `*.mount` systemd units

2. **Scan init scripts and crontabs** (medium-confidence):
   - Grep `/etc/init.d/*`, `/etc/rc.local`, crontab files for mount/wget/curl/rsync/scp/tftp commands
   - Extract remote hosts from command arguments

3. **Grep all text files** (broad sweep):
   - Apply URL scheme patterns across all text files
   - Apply cloud storage patterns
   - Apply database connection patterns

4. **Classify each finding:**

| Finding Type | Severity | CWE |
|---|---|---|
| CIFS mount with inline `password=` | Critical | CWE-256, CWE-798 |
| NFS export with `no_root_squash` | High | CWE-269 |
| Database connection with credentials | Critical | CWE-798 |
| Cloud storage endpoint (S3/Azure/GCS) | High | CWE-200 |
| MQTT broker on plaintext port 1883 | High | CWE-319 |
| FTP/TFTP firmware update URL | High | CWE-494 |
| iSCSI target IQN | High | CWE-200 |
| NFS/CIFS mount (no credentials) | Medium | CWE-1051 |
| Remote syslog (UDP) | Medium | CWE-319 |
| MQTT broker on TLS port 8883 | Medium | CWE-200 |
| HTTPS update URL | Low | CWE-200 |
| NTP/DNS references | Info | — |

5. **Format output** grouped by category, then severity, with file paths and line numbers.

### Step 3: Add to automated security audit

Add `_scan_network_dependencies()` to `security_audit_service.py` focusing on:
- Fstab credential exposure (Critical)
- NFS `no_root_squash` (High)
- Cloud storage endpoints (High)
- Plaintext protocol usage (High)

### Step 4: Whitelist and register

- Register in `security.py`'s `register_security_tools()` function
- Add to `ALLOWED_TOOLS` in `routers/tools.py`

## Files to Modify

| File | Change |
|------|--------|
| `backend/app/ai/tools/security.py` | Add `detect_network_dependencies` handler + registration (~200 lines) |
| `backend/app/services/security_audit_service.py` | Add `_scan_network_dependencies()` to audit pipeline |
| `backend/app/routers/tools.py` | Whitelist `detect_network_dependencies` |

## What NOT to Do

- Do NOT extend `analyze_config_security` — it analyzes single files, this needs full filesystem scan
- Do NOT make this purely YARA-based — YARA can't parse fstab columns or mount options
- Do NOT add to `find_hardcoded_credentials` — that tool focuses on secrets, this includes non-credential findings
- Do NOT attempt to connect to or validate discovered endpoints

## Acceptance Criteria

1. Tool correctly parses NFS/CIFS entries from `/etc/fstab` with credential detection
2. Cloud storage endpoints (S3, Azure, GCS) detected across text files
3. MQTT broker addresses detected in configs and scripts
4. FTP/TFTP firmware update URLs flagged
5. Findings have correct CWE tags and severity levels
6. Automated security audit includes network dependency results
7. Tool whitelisted for REST access
