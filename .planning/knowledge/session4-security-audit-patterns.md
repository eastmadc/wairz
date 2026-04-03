# Patterns: Session 4 — Security Audit, SquashFS Fix, Zip Bomb Prevention

> Extracted: 2026-04-03
> Commit: f2b11f8
> Campaigns: security-hardening (completed), device-acquisition-v2 (blocked)

## Successful Patterns

### 1. User-Driven Bug Discovery via SBOM Comparison
- **Description:** User asked to compare SBOMs between two projects with the same device firmware. The 9-vs-319 component discrepancy led directly to discovering the SquashFS extraction failure, which led to the sasquatch dependency fix, which led to discovering 5 more missing unblob deps.
- **Evidence:** SBOM comparison → SquashFS not extracted → sasquatch wrong fork → liblz4-dev missing → 5 more deps missing
- **Applies when:** Any time scan/analysis results seem incomplete, compare against a known-good reference. The delta reveals infrastructure bugs.

### 2. `unblob --show-external-dependencies` for Dependency Auditing
- **Description:** Unblob has a built-in dependency checker that shows checkmarks for all 15 external tools it needs. Running this after installing sasquatch revealed 5 additional missing deps we didn't know about.
- **Evidence:** Command output showed 10/15 → 15/15 after fixes
- **Applies when:** After any Dockerfile change affecting extraction tools, run this command to verify completeness.

### 3. Shared Pattern Module for Credential Detection
- **Description:** Credential patterns were duplicated between the MCP tool (strings.py) and the security audit service. Consolidating into `app/utils/credential_patterns.py` ensures both paths stay in sync and makes pattern additions a single-file change.
- **Evidence:** `credential_patterns.py` with 65+ patterns imported by both consumers
- **Applies when:** Any detection logic used by both MCP tools and automated services. Extract to a shared utils module.

### 4. Optional External Tool Wrappers (TruffleHog/Nosey Parker)
- **Description:** External scanners integrated as optional enhancements that silently skip if the binary isn't installed. Uses `shutil.which()` check + subprocess with timeout. Results merged into the same findings table with tool-name prefixes.
- **Evidence:** TruffleHog found 1 additional finding (Privacy detector) that 65+ custom patterns missed. Zero failures when tools aren't installed.
- **Applies when:** Integrating any external analysis tool. Make it optional, fail silently, merge results into existing data model.

### 5. Backend Path Resolution over Frontend Workarounds
- **Description:** Finding file paths (`/etc/main.conf`) didn't match explorer tree IDs (`/rootfs/etc/main.conf`). Instead of hacking the frontend, fixed `FileService._resolve()` to accept rootfs-relative paths when virtual root is active. Frontend fallback kept as defense-in-depth.
- **Evidence:** Backend now resolves both `/etc/main.conf` and `/rootfs/etc/main.conf` to the same file
- **Applies when:** Path format mismatches between data producers and UI consumers. Fix at the resolution layer, not the display layer.

### 6. Pre-extraction + Post-extraction Defense for Zip Bombs
- **Description:** For archives we control (ZIP, tar), inspect declared sizes before extracting. For subprocess extractors (binwalk, unblob), validate after extraction. Both layers needed since subprocesses can't be intercepted.
- **Evidence:** `check_tar_bomb()` (pre) + `check_extraction_limits()` (post) at all 5 extraction points
- **Applies when:** Any multi-tool extraction pipeline. Pre-check where possible, post-check everywhere.

### 7. Naming Matters — "Security Audit" over "Security Scan"
- **Description:** Initial naming was "security_scan" which conflicted with the existing vulnerability scan (Grype CVE matching). Renamed to "security_audit" to clearly distinguish configuration/secrets checking from CVE scanning.
- **Evidence:** User questioned the naming, leading to rename across backend source, API endpoint, DB records, frontend types, and UI labels
- **Applies when:** Any new feature that could be confused with existing features. The name should immediately convey what makes it different.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| onekey-sec sasquatch over devttys0 fork | Maintained by unblob team, builds cleanly on ARM64, no -Werror patching needed | SquashFS extraction works, 13K+ inodes extracted |
| Custom regex over external tool for core audit | Firmware-specific checks (shadow, setuid, init scripts) can't come from generic tools; EMBA/FACT validate this approach | 6 built-in checks + external tools as optional enhancement |
| Source build for sasquatch, binary download for TruffleHog/NP | sasquatch needs compilation with system libs; TH/NP are single static Go/Rust binaries | Both approaches reliable in Docker build |
| CA cert bundle filtering | `/etc/ssl/certs/` contains 130+ system CA certificates that are not security findings | Reduced noise from 192 to 52 findings |
| Generous extraction limits (10GB, 500K files, 200:1) | Firmware legitimately decompresses to large sizes; limits catch obvious bombs without blocking real firmware | No false positives on test firmware |
| Store findings with `source='security_audit'` | Allows filtering in existing FindingsPage UI; distinct from `sbom_scan` and `ai_discovered` | Full filter/sort support in UI |
| `pendingLine` in explorer store | Line number jump needs to survive the async file load; stored in Zustand and consumed by Monaco's `onMount` | Finding → file → exact line navigation works |
