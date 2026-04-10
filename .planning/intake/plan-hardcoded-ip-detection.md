# Plan: Hardcoded IP Address Detection

> Created: 2026-04-08
> Priority: High | **Status:** completed (2026-04-08, S20)
> Effort: Medium (1 session)
> Dependencies: None (standalone)
>
> **Completed S20:** `find_hardcoded_ips` MCP tool with validated IP regex, classification (public/private/well-known/loopback), false positive filtering, context-based severity, symlink dedup.

---

## Goal

Add a dedicated `find_hardcoded_ips` MCP tool that scans firmware filesystems for hardcoded IP addresses, classifies them (private/public/well-known), filters false positives, assigns severity by context, and integrates into the automated security audit.

## Current State

- `_IP_RE` in `strings.py:~line 20` is the weakest possible pattern: `r"\b(?:\d{1,3}\.){3}\d{1,3}\b"` — matches `999.999.999.999`, version strings, OIDs
- `extract_strings` categorizes strings including IPs but only for single files, no classification
- YARA rule `Suspicious_Hardcoded_IP_With_Download` only fires when IP + wget/curl appear together
- No dedicated IP scanning tool, no classification, no false positive filtering
- EMBA has S75 (network config analysis), firmwalker has validated regex, FACT has `ip_and_uri_finder` plugin — Wairz has none of this

## Implementation Plan

### Step 1: Upgrade `_IP_RE` regex in `strings.py`

Replace weak pattern with firmwalker-derived validated regex (each octet 0-255):

```python
_IP_RE = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
```

This immediately benefits `extract_strings` and `_categorize_strings`.

### Step 2: Create `find_hardcoded_ips` tool handler in `strings.py`

**Tool schema:**
```
Name: find_hardcoded_ips
Input: { path?: string, include_private?: bool, include_binaries?: bool, max_results?: int }
Output: Categorized report of all hardcoded IPs found
```

**Implementation:**
1. Walk firmware filesystem via `safe_walk` (same pattern as `find_hardcoded_credentials`)
2. For text files: read content, regex-match IPs with line numbers and surrounding context
3. For binary files (ELF, PE): run `strings -n 6`, regex-match output
4. Validate each match with `ipaddress.ip_address()` (Python stdlib)
5. Apply false positive filters:
   - Exclude subnet masks (`255.255.255.0`, `255.255.0.0`, etc.)
   - Exclude `0.0.0.0`, `255.255.255.255`
   - Exclude documentation ranges (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
   - Check for version-string context (look back 20 chars for `version`, `ver`, `v`, `release`, `build`, `fw`)
   - Exclude ASN.1 OID patterns (`2.5.x.x`, `1.3.6.x.x`)
6. Classify each IP:
   - **Private/RFC1918**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` → severity: Low
   - **Loopback**: `127.0.0.0/8` → severity: Info
   - **Link-local**: `169.254.0.0/16` → severity: Info
   - **Well-known service**: match against `WELL_KNOWN_IPS` dict → severity: Info
   - **Multicast/Broadcast**: `224.0.0.0/4` → severity: Info (exclude by default)
   - **Unknown public**: everything else → severity: Medium-High
7. Apply context-based severity modifiers:
   - Found in ELF binary `.rodata`: +1 severity
   - Found alongside wget/curl/nc: +1 severity
   - Found in init script/crontab: +1 severity
   - Found in resolv.conf/DNS config: -1 severity (expected)
   - Found in NTP config: -1 severity
8. Return results grouped by severity, then by category

**Well-known IP database:**
```python
WELL_KNOWN_IPS = {
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS (secondary)",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS (secondary)",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS (secondary)",
    "9.9.9.9": "Quad9 DNS",
    "149.112.112.112": "Quad9 DNS (secondary)",
    "129.6.15.28": "NIST NTP",
    "132.163.97.1": "NIST NTP",
    "128.105.39.11": "Netgear hardcoded NTP (known bug)",
    "77.88.8.8": "Yandex DNS",
    "94.140.14.14": "AdGuard DNS",
    "76.76.2.0": "Control D DNS",
}
```

### Step 3: Add YARA rule for public IPs in binaries

New rule in `suspicious_patterns.yar`:

```yara
rule Suspicious_Hardcoded_Public_IP
{
    meta:
        description = "Public IP address in binary near socket/connect calls"
        severity = "medium"
        category = "suspicious"
        cwe = "CWE-1051"
    strings:
        $ip = /[^0-9.](([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])[^0-9.]/ ascii
        $connect = "connect" ascii
        $socket = "socket" ascii
        $inet = "inet_addr" ascii
        $inet_pton = "inet_pton" ascii
    condition:
        $ip and any of ($connect, $socket, $inet, $inet_pton)
}
```

### Step 4: Integrate into automated security audit

Add `_scan_hardcoded_ips()` check to `security_audit_service.py` so findings appear in the SecurityScanPage without MCP conversation. Simplified version focusing on:
- Unknown public IPs (always flag)
- Private IPs in binaries (flag as info)
- IPs in init scripts near wget/curl (flag as high)

### Step 5: Whitelist tool in `routers/tools.py`

Add `find_hardcoded_ips` to `ALLOWED_TOOLS` set.

## CWE Mappings

- **CWE-1051**: Initialization with Hard-Coded Network Resource Configuration Data
- **CWE-798**: Use of Hard-coded Credentials (when IP is part of auth string)
- **CWE-547**: Use of Hard-coded, Security-relevant Constants

## Files to Modify

| File | Change |
|------|--------|
| `backend/app/ai/tools/strings.py` | Upgrade `_IP_RE`, add `find_hardcoded_ips` handler + registration |
| `backend/app/yara_rules/suspicious_patterns.yar` | Add `Suspicious_Hardcoded_Public_IP` rule |
| `backend/app/services/security_audit_service.py` | Add `_scan_hardcoded_ips()` to audit pipeline |
| `backend/app/routers/tools.py` | Whitelist `find_hardcoded_ips` |

## What NOT to Do

- Do NOT scan for packed 4-byte network-order IPs — false positive rate is unmanageable
- Do NOT create a separate tool category file — this belongs in `strings.py`
- Do NOT rely solely on YARA — YARA can't classify IPs or filter FPs
- Do NOT resolve/ping found IPs — no network access from analysis container

## Acceptance Criteria

1. `find_hardcoded_ips` returns classified results from a real firmware image
2. Known IPs (Google DNS, Cloudflare) are labeled correctly
3. Version strings (`1.2.3.4`) and subnet masks are filtered out
4. Unknown public IPs get Medium+ severity
5. Automated security audit includes IP scan results
6. Tool whitelisted for REST access
