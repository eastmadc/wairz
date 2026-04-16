# Patterns: Session 39 — Standalone APK Upload + Project Maturity

> Extracted: 2026-04-16
> Source: Session 39 work (APK deep-linking, fleet wave, standalone APK classifier, branding research)
> Postmortem: none

## Successful Patterns

### 1. Classifier-First Architecture for New Upload Types
- **Description:** Adding support for a new upload type (standalone APK) required only two changes: (a) add detection logic to `classify_firmware()` in `unpack_common.py`, and (b) add a fast-path handler in `unpack.py`. No router, schema, or frontend changes needed.
- **Evidence:** 4 lines in classifier + 15 lines in unpack pipeline = complete feature. APK preserved as-is, scanner finds it immediately.
- **Applies when:** Adding support for new firmware/file types. The classify → fast-path architecture handles it cleanly every time.

### 2. Preserve-Don't-Unpack for Single-File Analysis
- **Description:** For standalone APK files, the right approach is to copy the file as-is into the extraction directory rather than running it through binwalk/unblob. The APK scanner needs the intact `.apk` file, not its extracted contents.
- **Evidence:** First upload attempt without the classifier resulted in `linux_blob` classification and unblob extracting 798 files — none useful for APK scanning. After the fix, the APK is preserved intact and scannable in <1 second.
- **Applies when:** Any file type where the analysis tools need the original file, not extracted contents (APKs, IPA files, Windows executables with embedded resources).

### 3. Rebuild-First Debugging for "Code Doesn't Work"
- **Description:** When testing the APK classifier, the upload still classified as `linux_blob`. Root cause: the Docker container was running the old image. `docker compose up -d --build backend worker` fixed it instantly.
- **Evidence:** CLAUDE.md learned rule #1 triggered again — this is the single most common failure mode in this project.
- **Applies when:** Every time code changes don't seem to take effect. Always rebuild containers first, debug second.

### 4. Deep-Link Params as Props Through Component Tree
- **Description:** APK scan deep-linking was fixed by extracting URL params (`?finding=<title>`) at the page level and threading them as props through SecurityScanPage → ApkScanTab → SecurityScanResults. Each component handles its own piece: page extracts params, tab selects APK, results expand/scroll to finding.
- **Evidence:** 4 files changed, single coordinated flow replaced 8+ incremental patches. Typecheck clean.
- **Applies when:** Deep-linking to specific UI state — parse at the page, thread via props, handle at each level.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Detect APK by `AndroidManifest.xml` + `*.dex` in ZIP | Every valid APK has both; OTA ZIPs have neither pattern in isolation | Correct — no false positives against OTA, scatter, or rootfs ZIPs |
| Place APK check after Android OTA/scatter checks | OTA ZIPs also contain AndroidManifest.xml (inside system.img), but classifier checks OTA markers first | Correct ordering — OTA detection is more specific and takes priority |
| Copy APK as-is, don't extract | APK scanner needs the intact file; extraction destroys the structure | Confirmed by first failed attempt (unblob extracted 798 useless files) |
| Use finding title (not rule_id) for deep-link matching | The `Finding` DB model doesn't have a `rule_id` field; title is the most reliable match key available on both sides | Works — titles are unique per APK scan |
