# Plan: Threat Intelligence Integration

> Created: 2026-04-08
> Priority: High
> Effort: Large (2-3 sessions as Archon campaign)
> Dependencies: Hardcoded IP detection (for IOC enrichment feeds)

---

## Goal

Add malware scanning and threat intelligence lookups to Wairz via a privacy-first approach: local analysis first (YARA Forge, ClamAV), hash-only external lookups second (VT, abuse.ch, CIRCL), explicit opt-in upload last. Never auto-send firmware to external services.

## Current State

- **YARA**: 4 custom rule files (26 rules) in `backend/app/yara_rules/`. `yara_service.py` supports `extra_rules_dir` parameter for loading additional rules
- **Grype**: Local vuln scanner against CycloneDX SBOM, DB cached at `/data/grype-db`
- **Config pattern**: API keys via `.env` — existing: `nvd_api_key`, `dependency_track_api_key`, `dependency_track_url`
- **No external threat intel**: No VT, no abuse.ch, no ClamAV, no CIRCL integration
- **No community YARA rules**: Only 26 hand-written rules, no YARA Forge or community packs

## Phases

### Phase 1: YARA Forge Community Rules (zero cost, zero risk)

**What:** Download YARA Forge "core" rule package and load via existing `extra_rules_dir` infrastructure.

**Implementation:**
1. Add a script `scripts/update-yara-rules.sh` that downloads the latest YARA Forge core package:
   ```bash
   curl -L -o /data/yara-forge/yara-forge-rules-core.yar \
     https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.yar
   ```
2. Add `YARA_FORGE_DIR` to `config.py`: `yara_forge_dir: str = "/data/yara-forge"`
3. Modify `yara_service.py` to auto-load YARA Forge rules alongside custom rules
4. Add the download to Dockerfile build or entrypoint (with offline fallback — don't fail if GitHub unreachable)
5. Add a `update_yara_rules` MCP tool that triggers a re-download

**End condition:** `scan_with_yara` uses thousands of community rules instead of just 26.

### Phase 2: ClamAV Sidecar (self-hosted, no data leaks)

**What:** Add ClamAV as a Docker sidecar service for AV scanning of extracted firmware files.

**Implementation:**
1. Add `clamav` service to `docker-compose.yml`:
   ```yaml
   clamav:
     image: clamav/clamav:latest
     restart: unless-stopped
     volumes:
       - clamav-db:/var/lib/clamav
       - firmware-data:/data/firmware:ro
     mem_limit: 4g
   ```
   Note: ~3-4 GB RAM for signature DB. Shares the firmware storage volume read-only.

2. Create `backend/app/services/clamav_service.py`:
   - Connect to clamd via Unix socket or TCP
   - `scan_file(path) -> ClamScanResult` — scan single file
   - `scan_directory(path) -> list[ClamScanResult]` — scan extracted filesystem
   - Use `clamd` Python client library (add `clamd>=1.0.2` to pyproject.toml)

3. Create MCP tools in `backend/app/ai/tools/security.py`:
   - `scan_with_clamav` — scan a specific file or directory with ClamAV
   - `scan_firmware_clamav` — batch scan all extracted firmware files, return findings

4. Add REST endpoint for the UI:
   - `POST /api/v1/projects/{pid}/security/clamav-scan` — trigger ClamAV scan
   - Integrate results into SecurityScanPage (new "Malware Scan" tab or section)

5. Add to automated security audit in `security_audit_service.py`

**Config:**
```python
clamav_host: str = "clamav"        # Docker service name
clamav_port: int = 3310            # clamd TCP port
clamav_enabled: bool = True        # Disable if container not running
```

**End condition:** ClamAV scans extracted firmware files, findings appear in SecurityScanPage.

### Phase 3: VirusTotal Hash Lookup (privacy-safe, user-provided key)

**What:** Hash-only VT lookups — compute SHA-256 of extracted binaries, check VT without uploading.

**Implementation:**
1. Add config: `virustotal_api_key: str = ""` in `config.py` (`VT_API_KEY` in `.env`)
2. Create `backend/app/services/virustotal_service.py`:
   - `check_hash(sha256: str) -> VTResult | None` — single hash lookup
   - `batch_check_hashes(hashes: list[str]) -> list[VTResult]` — batch with rate limiting (4 req/min)
   - Rate limiter: simple token bucket respecting VT free tier (4/min, 500/day)
   - `VTResult` dataclass: `sha256, detection_count, total_engines, permalink, detections: list[Detection]`
3. MCP tools:
   - `check_virustotal` — check a single file's hash against VT
   - `scan_firmware_virustotal` — batch hash-check all ELF binaries, prioritized by: shared libs > executables > scripts
4. REST endpoint: `POST /api/v1/projects/{pid}/security/vt-scan` — trigger batch VT scan
5. Store results as findings (severity based on detection ratio: >10/72 = Critical, >5 = High, >1 = Medium)
6. Frontend: Add VT detection badges to SecurityScanPage results

**API usage:**
```python
# Hash-only lookup — zero privacy risk
import httpx
async def check_hash(sha256: str) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": settings.virustotal_api_key},
        )
        if resp.status_code == 404:
            return None  # Not in VT corpus
        return resp.json()["data"]["attributes"]["last_analysis_stats"]
```

**End condition:** VT hash lookups return detection counts for extracted binaries.

### Phase 4: abuse.ch Suite (MalwareBazaar + ThreatFox + URLhaus + YARAify)

**What:** Free threat intel from abuse.ch's four services via a single Auth-Key.

**Implementation:**
1. Add config: `abusech_auth_key: str = ""` in `config.py` (`ABUSECH_AUTH_KEY` in `.env`)
2. Create `backend/app/services/abusech_service.py`:

   **MalwareBazaar** (hash → known malware?):
   ```python
   async def check_malwarebazaar(sha256: str) -> MBResult | None:
       resp = await client.post("https://mb-api.abuse.ch/api/v1/", data={
           "query": "get_info", "hash": sha256
       })
   ```

   **ThreatFox** (IP/domain/hash → known C2?):
   ```python
   async def check_threatfox(ioc: str, ioc_type: str) -> list[TFResult]:
       resp = await client.post("https://threatfox-api.abuse.ch/api/v1/", json={
           "query": "search_ioc", "search_term": ioc
       })
   ```

   **URLhaus** (URL → malicious?):
   ```python
   async def check_urlhaus(url: str) -> UHResult | None:
       resp = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={
           "url": url
       })
   ```

   **YARAify** (hash → community YARA matches?):
   ```python
   async def check_yaraify(sha256: str) -> list[YARAifyResult]:
       resp = await client.get(
           f"https://yaraify-api.abuse.ch/api/v2/query/hash/sha256/{sha256}/"
       )
   ```

3. MCP tools:
   - `check_malwarebazaar_hash` — is this binary a known malware sample?
   - `check_threatfox_ioc` — check IP/domain/hash against IOC database
   - `check_urlhaus_url` — check extracted URLs against malicious URL database
   - `enrich_firmware_threat_intel` — batch: run all abuse.ch checks on extracted IOCs (hashes + IPs + URLs)

4. Integration: Feed extracted IPs from `find_hardcoded_ips` and URLs from `extract_strings` into ThreatFox/URLhaus checks.

**End condition:** abuse.ch lookups return threat intel for extracted hashes, IPs, and URLs.

### Phase 5: CIRCL Hashlookup (known-good filtering, no key needed)

**What:** Identify known-good files via NSRL database to reduce analyst workload.

**Implementation:**
1. Create `backend/app/services/hashlookup_service.py`:
   ```python
   async def check_known_good(sha256: str) -> HashlookupResult | None:
       resp = await client.get(
           f"https://hashlookup.circl.lu/lookup/sha256/{sha256}"
       )
       if resp.status_code == 200:
           data = resp.json()
           return HashlookupResult(
               known=True,
               source=data.get("source", "NSRL"),
               product=data.get("ProductName"),
               vendor=data.get("MfgName"),
           )
       return None  # Not in known-good DB
   ```
2. MCP tool: `check_known_good_hash` — identifies known legitimate files
3. Integration into VT/abuse.ch batch scans: skip known-good files to save API quota

**End condition:** Known-good files identified and labeled, reducing false positive workload.

## Architecture

```
Extracted Firmware Filesystem
        │
        ▼
┌───────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Local Analysis    │     │ Hash-Only Lookup  │     │ Self-Hosted AV   │
│ (no network)      │     │ (privacy-safe)    │     │ (no data leaves) │
│                   │     │                   │     │                  │
│ • YARA custom +   │     │ • VirusTotal      │     │ • ClamAV clamd   │
│   YARA Forge      │     │ • MalwareBazaar   │     │   Docker sidecar │
│ • Grype (SBOM)    │     │ • ThreatFox       │     │   ~3-4 GB RAM    │
│                   │     │ • URLhaus         │     │                  │
│                   │     │ • YARAify         │     │                  │
│                   │     │ • CIRCL Hashlookup│     │                  │
└───────────────────┘     └──────────────────┘     └──────────────────┘
                                   │
                     Only hashes/IOCs sent
                     (never full files)
```

## Config Additions (all in `config.py`)

```python
# Threat Intelligence
virustotal_api_key: str = ""        # VT_API_KEY — hash-only lookups
abusech_auth_key: str = ""          # ABUSECH_AUTH_KEY — abuse.ch suite
yara_forge_dir: str = "/data/yara-forge"  # YARA_FORGE_DIR
clamav_host: str = "clamav"         # CLAMAV_HOST — Docker service name
clamav_port: int = 3310             # CLAMAV_PORT
clamav_enabled: bool = True         # CLAMAV_ENABLED
```

## New Files

| File | Purpose | Phase |
|------|---------|-------|
| `scripts/update-yara-rules.sh` | Download YARA Forge core package | 1 |
| `backend/app/services/clamav_service.py` | ClamAV clamd client | 2 |
| `backend/app/services/virustotal_service.py` | VT API v3 hash-only client | 3 |
| `backend/app/services/abusech_service.py` | abuse.ch suite client | 4 |
| `backend/app/services/hashlookup_service.py` | CIRCL hashlookup client | 5 |

## Files to Modify

| File | Change | Phase |
|------|--------|-------|
| `backend/app/config.py` | Add threat intel config fields | 1 |
| `backend/app/services/yara_service.py` | Load YARA Forge rules | 1 |
| `docker-compose.yml` | Add ClamAV service | 2 |
| `backend/pyproject.toml` | Add `clamd>=1.0.2`, `httpx>=0.27` | 2-3 |
| `backend/app/ai/tools/security.py` | Register threat intel MCP tools | 2-5 |
| `backend/app/routers/security_audit.py` | Add threat intel REST endpoints | 2-5 |
| `backend/app/routers/tools.py` | Whitelist new tools | 2-5 |
| `backend/app/services/security_audit_service.py` | Integrate into auto audit | 2-5 |
| `frontend/src/pages/SecurityScanPage.tsx` | Add threat intel results display | 3-5 |

## What NOT to Do

- **Never auto-upload firmware files** to VT or any external service
- **Never make IntelOwl/OpenCTI/MISP a dependency** — too heavy, different purpose
- **Never integrate CAPE Sandbox** — Windows-focused, Wairz has QEMU for embedded
- **Never hardcode API keys** — always user-provided via `.env`
- **Graceful degradation** — every service must work when its API key is absent (return "not configured")

## Phase End Conditions

| Phase | Condition |
|-------|-----------|
| 1 | `scan_with_yara` returns matches from YARA Forge community rules |
| 2 | `scan_with_clamav` returns ClamAV detection results for extracted files |
| 3 | `check_virustotal` returns detection count for a known malware hash |
| 4 | `check_malwarebazaar_hash` + `check_threatfox_ioc` return results |
| 5 | `check_known_good_hash` identifies a BusyBox binary as known-good |

## Acceptance Criteria

1. YARA Forge rules loaded alongside custom rules — thousands of detections
2. ClamAV sidecar scans firmware files, results in SecurityScanPage
3. VT hash lookups work with free tier, respect rate limits (4/min, 500/day)
4. abuse.ch suite checks hashes, IPs, and URLs with single Auth-Key
5. CIRCL identifies known-good files, reduces analyst workload
6. All services gracefully degrade when API keys not configured
7. No firmware data ever sent to external services without explicit user opt-in
