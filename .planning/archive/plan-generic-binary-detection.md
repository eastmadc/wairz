# Plan: Generic Binary Version Detection (SBOM Gap Closer)

> Created: 2026-04-10
> Priority: High (security-critical detection gap validated by testing 5 tools) | **Status:** completed (2026-04-10, S27)
> Effort: Medium (1 session)
> Dependencies: None (standalone, builds on existing sbom_service.py)
> Evidence: rssh 2.3.4 missed by Syft, Trivy, Grype, cve-bin-tool, Wairz — 0/5 tools detect it
>
> **Completed S27:** Generic filename-anchored fallback detector in `_scan_binary_version_strings()`. rssh 2.3.4 now detected with CPE `cpe:2.3:a:pizzashack:rssh:2.3.4` (NVD exact match, confidence 1.0). 15 generic detections total, 3 CPE-validated. `MAX_BINARIES_SCAN` raised from 200→500. 8 niche services added to `KNOWN_SERVICE_RISKS`.

---

## Problem

Firmware binaries that self-identify with `{name} {version}` strings (e.g., `rssh 2.3.4`) are invisible to every open-source SBOM tool. Wairz has 58 curated `VERSION_PATTERNS` covering major software (OpenSSH, BusyBox, nginx, etc.) but misses hundreds of niche/vendor tools that embed version strings in the same way.

**Empirical proof:** Tested the actual firmware (Yocto ARM, project `98180e8b`) against 5 tools:

| Tool | rssh Detected? | Method |
|---|---|---|
| Syft (binary-classifier) | NO | Curated list of ~60 binaries |
| Trivy (fs scan) | NO | Package DB only (no dpkg/opkg in Yocto) |
| Grype (dir scan) | NO | Consumes Syft SBOM — same blind spot |
| cve-bin-tool (366 checkers) | NO | No rssh checker (has openssh, libssh) |
| Wairz (58 VERSION_PATTERNS) | NO | No rssh regex pattern |

The binary clearly embeds `rssh 2.3.4` in its strings output. rssh has known critical CVEs (CVE-2019-3463 command injection, CVE-2019-1000018 arbitrary command execution). These vulns are invisible because no tool detects the component.

## Current Architecture

**Detection pipeline** (`sbom_service.py`):
1. Syft → package ecosystems (dpkg, apk, Python, Go, etc.)
2. Package managers → opkg/dpkg status files
3. Binary version strings → 58 curated regexes in `VERSION_PATTERNS` (lines 185-242)
4. Library SONAME → ELF dynamic symbols
5. Service risk annotation → 33 known daemons in `KNOWN_SERVICE_RISKS`

**Enrichment pipeline** (after detection):
1. `CPE_VENDOR_MAP` exact match (158 entries, confidence 0.95)
2. Local fuzzy match (normalize names, confidence 0.85)
3. NVD CPE dictionary fuzzy match via `cpe_dictionary_service.py` (1M+ products, confidence 0.70-1.0)
4. Kernel module inheritance
5. Android SDK version

**The gap lives between steps 3 and 4 of detection:** binary strings scanning only matches curated patterns. If a binary isn't in the list, its version is never extracted, so the enrichment pipeline never fires.

## Solution: Generic Binary Self-Identification Fallback

Add a **fallback detector** that runs after all curated VERSION_PATTERNS fail. It looks for the pattern where a binary's own filename appears alongside a semver string in its extracted strings.

### Why This Works

Binaries frequently self-identify for `--version` output, logging, and error messages:
- `rssh 2.3.4` (rssh)
- `procps-ng 3.3.10` (procps utilities)
- `util-linux 2.25.2` (coreutils)
- `avahi-daemon 0.6.31` (avahi)

### False Positive Analysis (from actual firmware strings)

**True positives found:**

| Binary | String | Detection |
|---|---|---|
| `/usr/bin/rssh` | `rssh 2.3.4` | filename matches product name |
| `busybox.nosuid` | `BusyBox v1.23.1` | already caught by curated pattern |
| `pwdx.procps` | `procps-ng 3.3.10` | suffix `.procps` maps to product |
| `hexdump.util-linux` | `util-linux 2.25.2` | suffix `.util-linux` maps to product |

**False positives identified and how to filter:**

| String (in sshd) | Why False | Filter Rule |
|---|---|---|
| `libcrypto 1.0.0` | Library dependency, not sshd's version | Exclude `lib*` prefixes |
| `OPENSSL_1.0.1` | Symbol version requirement | Exclude `_` joined name+ver |
| `GLIBC_2.4` | C library symbol version | Exclude known symbol prefixes |
| `OpenSSH_6.7p1*` | Protocol compat string (has `*` wildcard) | Exclude strings with `*` |

### Implementation Plan

#### Step 1: Generic Fallback Pattern in `_scan_binary_version_strings()`

After the curated VERSION_PATTERNS loop (line ~1806), add a fallback:

```python
# Fallback: check if binary filename appears alongside semver in strings
if not matched:
    binary_base = os.path.basename(binary_path).split('.')[0].lower()
    # Also try Yocto-style suffixed names: hexdump.util-linux → util-linux
    suffix_name = os.path.basename(binary_path).rsplit('.', 1)[-1].lower() if '.' in os.path.basename(binary_path) else None
    
    GENERIC_VERSION_RE = re.compile(
        rb"(?:^|\s)(" + re.escape(binary_base.encode()) + rb")[\s/v_-]+(\d+\.\d+(?:\.\d+)?(?:[a-z]?\d*)?)\b",
        re.IGNORECASE
    )
    # Also try suffix name if different
    patterns_to_try = [GENERIC_VERSION_RE]
    if suffix_name and suffix_name != binary_base:
        patterns_to_try.append(re.compile(
            rb"(?:^|\s)(" + re.escape(suffix_name.encode()) + rb")[\s/v_-]+(\d+\.\d+(?:\.\d+)?(?:[a-z]?\d*)?)\b",
            re.IGNORECASE
        ))
    
    for pat in patterns_to_try:
        m = pat.search(joined_strings)
        if m:
            detected_name = m.group(1).decode('ascii', errors='ignore').lower()
            detected_version = m.group(2).decode('ascii', errors='ignore')
            # Apply false positive filters (Step 2)
            if _is_valid_generic_detection(detected_name, detected_version, binary_base):
                component = IdentifiedComponent(
                    name=detected_name,
                    version=detected_version,
                    type="application",
                    detection_source="binary_strings",
                    detection_confidence="low",  # Lower than curated patterns
                    file_paths=[rel_path],
                )
                self._add_component(component)
                break
```

#### Step 2: False Positive Filter Function

```python
# Known false positive prefixes (library symbol versions, not products)
_GENERIC_EXCLUDE_PREFIXES = frozenset([
    "glibc", "openssl", "libcrypto", "libssl", "libpthread",
    "gcc", "musl", "uclibc", "linux",
])

def _is_valid_generic_detection(name: str, version: str, binary_base: str) -> bool:
    """Filter false positives from generic binary version detection."""
    # Rule 1: Exclude known library/symbol version prefixes
    if name.lower() in _GENERIC_EXCLUDE_PREFIXES:
        return False
    if name.startswith("lib") and len(name) > 3:
        return False  # Library references (libfoo), not the binary itself
    
    # Rule 2: Version must be clean semver (no wildcards, no trailing *)
    if "*" in version or "?" in version:
        return False
    
    # Rule 3: Name must loosely match binary filename
    # (already enforced by regex construction — binary_base is in the pattern)
    
    return True
```

#### Step 3: CPE Validation via NVD Dictionary (confidence boost)

After generic detection, the existing enrichment pipeline handles CPE assignment:
1. `_enrich_cpes()` checks `CPE_VENDOR_MAP` → miss (rssh not in map)
2. Falls through to NVD CPE dictionary fuzzy match → **hit** (`rssh_project:rssh`)
3. Assigns CPE with confidence based on NVD match quality

For high-value detections, add CPE validation as a confidence booster:

```python
# In _enrich_cpes(), after generic detection:
if comp.detection_confidence == "low" and comp.enrichment_source in ("nvd_exact", "nvd_fuzzy"):
    # Generic detection + NVD CPE match = promote to medium confidence
    comp.detection_confidence = "medium"
    comp.metadata["generic_detection_validated"] = True
```

#### Step 4: Expand KNOWN_SERVICE_RISKS

Add niche but security-relevant services:

```python
# Add to KNOWN_SERVICE_RISKS:
"rssh": "medium",      # Restricted shell — CVE-2019-3463
"rsh": "critical",     # Remote shell — unencrypted
"rexec": "critical",   # Remote exec — unencrypted
"stunnel": "medium",   # TLS wrapper — attack surface
"socat": "medium",     # Socket relay — attack surface
"ncat": "medium",      # Nmap netcat — attack surface
"xinetd": "medium",    # Super-server — attack surface
"inetd": "high",       # Legacy super-server
```

### Quality Gates

- [ ] rssh 2.3.4 detected in SBOM for project 98180e8b
- [ ] rssh gets CPE assigned via NVD dictionary fuzzy match
- [ ] CVE-2019-3463 appears in vulnerability scan results
- [ ] No false positive components from sshd's embedded library strings
- [ ] No false positive from GLIBC/OPENSSL symbol versions in any binary
- [ ] Generic detections marked as `detection_confidence: "low"` (promoted to "medium" if CPE validates)
- [ ] TypeScript clean, Docker rebuilt, API smoke test

### Risks

1. **False positive rate** — mitigated by filename matching + library exclusion + CPE validation
2. **Performance** — regex compilation per binary is O(1); no significant overhead on 200 binary limit
3. **Confidence calibration** — generic detections start at "low" to avoid displacing higher-quality detections

### Competitive Advantage

**No open-source firmware SBOM tool does this.** Tested Syft, Trivy, Grype, cve-bin-tool — all miss rssh. EMBA's S09 module is the closest (brute-force string matching) but uses a curated list too. A generic fallback with CPE validation is a novel approach that closes a real gap across the entire ecosystem.
