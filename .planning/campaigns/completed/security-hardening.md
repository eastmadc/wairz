# Campaign: Security Hardening

Status: completed
Created: 2026-04-02
Direction: Add YARA malware detection, expanded credential patterns (AWS/Azure/GCP/GitHub), kernel sysctl hardening checks, and firewall policy analysis
Estimated sessions: 2-3
Type: build

## Background

Research fleet (session 3) identified security assessment as the biggest competitive gap vs
EMBA/ByteSweep. Current security tools: 6 checks (CVEs, config, setuid, init, perms, certs).
Missing: malware/backdoor detection (YARA), cloud API key patterns, kernel hardening, firewall analysis.

## Phases

| # | Type | Description | Deps | End Conditions | Status |
|---|------|-------------|------|----------------|--------|
| 1 | build | YARA scanning tool + YARA-Forge rules | none | `scan_with_yara` MCP tool works, 4990 YARA-Forge rules loaded, yara-python installed | done (verified S34: 4990 rules, scan_with_yara working) |
| 2 | build | Expanded credential detection patterns | none | 18 new API key patterns (AWS, Azure, GCP, GitHub, Stripe, Slack, JWT, Twilio) in find_hardcoded_credentials | done |
| 3 | build | Kernel sysctl hardening checker | none | `check_kernel_hardening` MCP tool, 18 sysctl parameters checked, router-aware severity adjustment | done |
| 4 | verify | Tests + integration | 1-3 | Unit tests for all new patterns, YARA rules compile, sysctl parser works | done (24 tests + YARA verified S34) |

## Decision Log

- YARA tools added to security.py (not a separate category) — fits naturally with existing security tools
- yara-python (Python bindings) preferred over CLI wrapping — faster for batch scanning, no subprocess overhead
- Built-in rules embedded in code (not external files) — simpler deployment, no file management
- API key patterns added to existing _CREDENTIAL_PATTERNS — extends current tool rather than new one
- Sysctl checker as new tool — distinct enough from config_security to warrant separate registration
