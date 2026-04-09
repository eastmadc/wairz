# Anti-patterns: Session 23 — MCP Output Quality

> Extracted: 2026-04-09
> Commit: cd8cb43 on clean-history

## Failed Patterns

### 1. Raw JSON Dump With [:30000] Truncation
- **What was done:** MCP tool built the full JSON document (components + vulnerabilities), serialized it, then sliced the string at 30,000 characters.
- **Failure mode:** JSON components section (300 entries) consumed the entire 30KB budget. The vulnerabilities array (5062 entries — the actual value of VEX) was never visible. Output was also invalid JSON (cut mid-string).
- **Evidence:** `export_sbom` with `cyclonedx-vex-json` — user saw 303 component objects, zero vulnerabilities.
- **How to avoid:** Never truncate serialized JSON with `[:30000]`. Instead, build a purpose-fit MCP summary: counts, top-N, and a pointer to the REST endpoint for the full document. The MCP output format should be designed for AI consumption, not be a raw dump.

### 2. Scanning Symlinks as Unique Files
- **What was done:** `find_hardcoded_ips` walked the filesystem and ran `strings` on every file, including all busybox symlinks.
- **Failure mode:** 300+ busybox symlinks → 300 identical `strings` runs → identical IPs "found" 300 times each → 2000 findings for 14 unique IPs.
- **Evidence:** User saw `192.168.0.20 in /bin/ls (binary)`, `192.168.0.20 in /bin/cat (binary)`, repeated for every busybox applet.
- **How to avoid:** Always `os.path.realpath()` binary files and track scanned real paths in a set. Skip if already scanned. This is a common pattern in embedded firmware where busybox, toybox, and similar multi-call binaries dominate.

### 3. Per-Occurrence Output Instead of Grouped
- **What was done:** Tool output listed each (IP, file) pair as a separate line, even when the same IP appeared across hundreds of files.
- **Failure mode:** Output was 99% redundant — same IP, different file path, no new information. Buried the actually interesting findings (hardcoded public IPs, IPs near wget/curl).
- **Evidence:** 792 LOW lines for 2 private IPs vs. 4 MEDIUM lines for interesting findings.
- **How to avoid:** Group output by the primary finding (IP, CVE, rule), list affected files as a sub-list with a cap (5 shown, rest summarized). This is more useful for both humans and AI.

### 4. Native Select/Option Without Explicit Colors
- **What was done:** `<select>` used `bg-transparent` with no `text-foreground` class. `<option>` elements had no styling at all.
- **Failure mode:** In dark mode, native browser rendering of `<option>` dropdowns doesn't inherit CSS custom properties from Tailwind's theme system. Result: white text on white background.
- **Evidence:** User reported "white text on white background" on Security Tools page dropdown. Same issue present in 12+ other selects.
- **How to avoid:** Always add explicit text/background colors to native `<select>` and `<option>` elements — don't rely on inheritance. Better yet, add a global rule in the CSS base layer so all selects are covered.
