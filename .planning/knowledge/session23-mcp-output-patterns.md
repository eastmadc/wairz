# Patterns: Session 23 — MCP Output Quality & UI Polish

> Extracted: 2026-04-09
> Commit: cd8cb43 on clean-history
> Postmortem: none (single-session fix batch)

## Successful Patterns

### 1. Symlink Deduplication Before Scanning
- **Description:** Resolved `os.path.realpath()` before scanning binary content in `find_hardcoded_ips`. Busybox firmwares have 300+ symlinks to the same binary — scanning each one produced 2000 identical findings.
- **Evidence:** Output dropped from 64KB / 2000 lines to 2KB / 77 lines on the same firmware.
- **Applies when:** Any tool that runs `strings` or content analysis on firmware binaries. Check for hardlinks/symlinks first.

### 2. Group-by-Finding Instead of Group-by-File
- **Description:** Restructured MCP output to group by the interesting thing (IP address, CVE) rather than listing each file occurrence. Shows file list under each finding, capped at 5.
- **Evidence:** `find_hardcoded_ips` went from listing `192.168.0.20 in /bin/mv`, `192.168.0.20 in /bin/cp`, ... (400 lines) to `192.168.0.20 — found in 1 file(s)` with the resolved binary path.
- **Applies when:** Any tool where the same finding appears across many files (especially busybox symlinks, shared libraries).

### 3. MCP Summary + REST Full Document
- **Description:** For export tools (VEX), MCP returns a structured summary (severity counts, top N items) while REST returns the full document. Added a Download button to bridge the gap.
- **Evidence:** VEX export was 6.8MB JSON, truncated to 30KB of component data with zero vulnerabilities visible. Now MCP shows severity breakdown + top 50 vulns in 18KB. Browser download gets the full 6.8MB.
- **Applies when:** Any MCP tool that produces document-sized output (SBOM, reports, exports). Always provide a REST download path.

### 4. Global CSS Fix Over Per-Component Fixes
- **Description:** Instead of adding `text-foreground` / `bg-background` to each `<select>`/`<option>` across 12+ files, added a single global rule in `index.css` base layer.
- **Evidence:** Fixed all 12 select elements across ComparisonPage, EmulationPage, KernelManager, CraChecklistTab, etc. with 4 lines of CSS.
- **Applies when:** A styling bug appears in one component but the same pattern exists in many others. Fix at the lowest common layer.

### 5. Display Caps With "... and N more"
- **Description:** Added display limits (30-50 items) to all verbose tool outputs with a count of remaining items. User knows the full scope without drowning in data.
- **Evidence:** Applied to `check_all_binary_protections` (50 binaries), `find_crypto_material` (30 per category), `find_hardcoded_credentials` (30 high-entropy, 20 low-entropy).
- **Applies when:** Any tool that iterates over filesystem scan results. Always cap display, always show the total.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| MCP VEX returns summary, not full doc | Full VEX (6.8MB) is useless when truncated to 30KB — vulnerabilities never visible | Works — 18KB output with all severity data, top 50 vulns |
| Added Download button to ToolOutput | Users expect browser download for export tools, not just JSON display | Clean UX — summary for review, Download for the file |
| Resolve symlinks in IP scanner | Busybox has 300+ symlinks to same binary, each producing identical results | 28 findings instead of 2000, scan time also reduced |
| Global CSS for select/option dark mode | 12+ select elements across codebase, each would need individual fix | 4 lines in index.css fixed all current and future selects |
