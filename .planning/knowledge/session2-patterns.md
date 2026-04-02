# Patterns: Session 2 — Vuln UI, Android Pipeline, Test Fixes, Quality

> Extracted: 2026-04-02
> Campaigns: android-sbom (completed), android-firmware-support (active, 9/11)
> Source: 8 commits, 219 tests passing, 3 research fleets

## Successful Patterns

### 1. Research fleet before implementation avoids wasted work
- **Description:** Launched 4 parallel research scouts before writing any code. Each scout explored a different domain (vuln UI, SBOM detection, ZIP extraction, test suite). Implementation was targeted and avoided dead ends.
- **Evidence:** Zero reverts, zero wasted implementations. All 5 P-items completed in single passes. Research took ~70s each while running in parallel; implementation was precise because the code was already understood.
- **Applies when:** Starting a session with 3+ independent work items. The research cost (~$2-3 in tokens) pays for itself by preventing misdirected implementation.

### 2. Verify end conditions before implementing
- **Description:** Checked SBOM component count (418 total, 128 Android-specific) via API before writing any SBOM code. Phase 1 end condition (>100 components) was already met by prior session's work.
- **Evidence:** Saved an entire implementation cycle. The SBOM campaign was marked complete without writing new code — only verification.
- **Applies when:** Resuming a campaign with measurable end conditions. Always check first.

### 3. Worktree agents need write permissions granted upfront
- **Description:** Three worktree agents (P1, P2, P4) were blocked on Edit/Write/Bash permissions. They produced excellent plans but couldn't execute. Main thread had to implement based on their research.
- **Evidence:** P1 agent produced exact code snippets and line numbers but couldn't write. P4 agent designed 25 tests with fixture layouts but couldn't create files.
- **Applies when:** Using isolation: "worktree" agents. The user must pre-approve write tools or the agents become read-only researchers. Consider using foreground agents instead if writes are needed.

### 4. Fix pre-existing test failures before adding new tests
- **Description:** The 10 pre-existing test failures masked the health of new changes. Fixing them (outdated counts, sandbox behavior change) gave a clean 219/219 baseline.
- **Evidence:** After fixing, the test suite became a reliable signal. The unpack.py refactor (1,022→4 files) was validated by running 219 tests — confidence was high because the baseline was clean.
- **Applies when:** Any session where tests are failing before you start. Green baseline first, then new work.

### 5. Content-based identification is more robust than metadata parsing
- **Description:** Partitions from super.img were identified by directory contents (system has init+bin, vendor has build.prop+lib) rather than LP metadata headers.
- **Evidence:** Works even when partition order is unknown and LP metadata is complex. Successfully identified system, vendor, product partitions on MediaTek firmware.
- **Applies when:** Any extraction where container metadata is unavailable or unreliable. Check contents post-extraction.

### 6. Preserve original archives when downstream tools already handle them
- **Description:** Android ZIP detection preserves the ZIP intact (skip extraction) because classify_firmware() + _extract_android_ota() already handle ZIP input correctly.
- **Evidence:** Simpler than extracting all .img files at upload time. One `pass` statement + `else` indentation vs. new extraction function.
- **Applies when:** Adding early detection for a format that the downstream pipeline already processes. Don't duplicate work.

## Anti-patterns

### 1. CPE vendor mismatch filtering doesn't catch NVD cross-references
- **What was done:** Added vendor extraction from Grype CPE matches to filter false positives (e.g., Adobe Flash CVEs on Android)
- **Failure mode:** NVD tags Flash CVEs with `cpe:2.3:o:google:android:*` because Flash *did* affect Android. Both sides have vendor=google, so the filter doesn't trigger.
- **Evidence:** Re-scan still showed 26 Flash/Adobe CVEs. The found.cpes in Grype output contained google:android, not adobe:flash.
- **How to avoid:** For this specific case, version-range filtering or description-based heuristics would be needed. The vendor filter is still useful for genuinely mismatched vendors but won't catch cross-referenced CVEs in the NVD.

### 2. _resolve_within_root() silently clamping '..' was a security regression
- **What was done:** Original implementation clamped '..' traversals to root instead of raising PathTraversalError
- **Failure mode:** Allowed prefix collision attacks (../firmware_evil/secret.txt resolved to root/firmware_evil/secret.txt) and silently swallowed escape attempts
- **Evidence:** 5 sandbox tests failed. Adding one `raise` statement fixed all 5.
- **How to avoid:** Path resolution functions must REJECT escape attempts, not silently clamp them. Defense-in-depth: even if the result is "safe" (stays in root), the intent was malicious and should be reported.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Keep ZIP intact for Android upload (not extract all .img) | Downstream pipeline already handles ZIP input | Correct — simpler, no new extraction logic needed |
| Split unpack.py into 4 files | 1,022 lines with clear Linux/Android/common boundaries | Correct — each file <300 lines, 11 cross-imports |
| Remove CFS cpus limits from docker-compose | Breaks on Raspberry Pi / non-CFS kernels | Correct — memory + PID limits remain, CPU limits were non-essential |
| Update sandbox tests for chroot model (not revert resolver) | _resolve_within_root() is architecturally correct for firmware | Correct — absolute symlinks must rewrite to root, not reject |
| Use Load More button (not infinite scroll) for vuln pagination | Simpler, explicit user control, no scroll listener complexity | Correct — adequate for the use case |
| Directory-name APK detection (not AndroidManifest.xml parsing) | Sufficient for inventory, manifest parsing needs androguard | Correct — 62 APKs detected without any dependency |
