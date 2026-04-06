# Patterns: Session 11 (Autopilot + Live Testing + Binary Diff Enhancement)

> Extracted: 2026-04-06
> Session scope: Autopilot items, firmware unpack debugging, binary diff rebuild, SBOM fixes

## Successful Patterns

### 1. Live-Test-Driven Bug Discovery
- **Description:** Rather than relying on unit tests alone, uploading real firmware (MediaTek DPCS10 1.1GB) revealed 4 critical bugs that no test would have caught: arq timeout mismatch, stuck firmware state, EROFS permission denials, and Grype CycloneDX version incompatibility.
- **Evidence:** Session went from "3 autopilot items complete" to discovering and fixing 8+ bugs by actually using the tool.
- **Applies when:** After any session that changes extraction, SBOM, or scan pipelines — always test with a real firmware image.

### 2. Timeout Hierarchy Must Be Outer > Inner
- **Description:** When a background job system (arq) wraps a subprocess (unblob), the outer timeout must exceed the inner timeout. arq was 600s, unblob was 1200s — arq killed the job before unblob could complete.
- **Evidence:** DPCS10 firmware extraction failed at exactly 600s (arq timeout) while unblob needed 20 min.
- **Applies when:** Any arq job that runs extraction tools, Ghidra, or other subprocess-based analysis.

### 3. MediaTek Scatter Format Detection
- **Description:** Android firmware from MediaTek uses `*_scatter.txt` + nested partition files in a zip. The classifier didn't recognize this format, causing fallthrough to unblob (20 min failure) instead of the Android pipeline (44 seconds).
- **Evidence:** Adding `android_scatter` classification dropped extraction from 20+ min timeout to 44 seconds.
- **Applies when:** Adding support for new firmware formats — always check the classifier first.

### 4. LIEF API Version Portability
- **Description:** LIEF's Python API differs across versions. `binary.static_symbols` doesn't exist (use `binary.symbols`), `lief.ELF.ELF_DATA` should be `lief.ELF.Header.ELF_DATA`, `lief.ELF.ELF_CLASS` should be `lief.ELF.Header.CLASS`. Use `sym.is_function` instead of `sym.type == lief.ELF.Symbol.TYPE.FUNC` for maximum portability.
- **Evidence:** Fleet agent wrote code using `binary.static_symbols` which crashed silently (caught by `except Exception: return None`), causing function hashing to fall back to "stripped binary" mode.
- **Applies when:** Any code using LIEF — always test against the Docker container's LIEF version, not the local one.

### 5. Parallel Fleet Agents With Worktrees
- **Description:** Launching 3 agents in parallel worktrees (backend Tier 1, backend Tier 2, frontend) cut build time by ~60%. Each agent worked independently, changes merged cleanly.
- **Evidence:** All 3 agents completed successfully, merged without conflicts, 379 tests + typecheck passed.
- **Applies when:** When work decomposes into 3+ independent file scopes.

### 6. chmod +r After EROFS/ext4 Extraction
- **Description:** EROFS and ext4 extraction preserves original Android permissions (600, 640). This makes files unreadable by analysis tools (SBOM scanner, string extraction). Adding `chmod -R +r` after extraction fixes it.
- **Evidence:** `build.prop` was 600-permissions, causing `_parse_build_prop` to fail with PermissionError, resulting in no Android OS component in SBOM.
- **Applies when:** Any extraction of Android partitions — always normalize permissions after.

### 7. Grype Input SBOM Version Independence
- **Description:** The SBOM version exported to users (CycloneDX 1.7) must be independent of the version fed to Grype for scanning. Grype 0.87 doesn't support CycloneDX 1.7. The internal Grype input SBOM should use the highest version the installed Grype supports.
- **Evidence:** Upgrading specVersion to 1.7 in grype_service.py broke all vulnerability scanning — "sbom format not recognized".
- **Applies when:** Any CycloneDX version upgrade — never change grype_service's input format without testing Grype compatibility.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| LIEF over pyelftools for binary diff | LIEF reads function body bytes, pyelftools only reads symbol metadata | 10 modified functions detected that pyelftools missed entirely |
| .symtab → .dynsym → section fallback | Maximum coverage across stripped and non-stripped binaries | Works for all tested firmware binaries |
| Deferred radiff2 Tier 3 | Tier 1+2 deliver core value; radiff2 takes 3-60s per binary | Correct — Tier 1+2 already solved the user's problem |
| capstone as Python dependency | Needed for instruction-level disassembly in REST API | Added to pyproject.toml, builds cleanly on ARM64 |
| Kernel version from vermagic strings | Android puts modules in vendor partition, not /lib/modules/ | Found kernel 6.6.102 which produced 2,891 CVEs |
| EROFS chmod +r post-extraction | Android file permissions (600) break analysis tools | Root cause of SBOM missing Android OS component |
| Grype input stays at CycloneDX 1.5 | Grype 0.87 doesn't parse 1.7 | Fixed vuln scanning; user exports still use 1.7 |
