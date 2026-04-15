# Patterns: APK Security Scanning (Ouroboros-driven)

> Extracted: 2026-04-15
> Source: Ouroboros interview (interview_20260414_231546), seed execution (seed_9f99b1d82824), Citadel review + research fleet
> Postmortem: none (Ouroboros-driven, not campaign-based)

## Successful Patterns

### 1. Ouroboros interview for deep research before implementation
- **Description:** Used Ouroboros Socratic interview to systematically research MobSF, mobsfscan, semgrep, Androguard capabilities before writing any code. The interview forced decisions on scope (firmware APKs vs standalone), phasing (manifest first, then bytecode, then SAST), output integration (dual: MCP + findings DB), and severity model (static base + context bump).
- **Evidence:** 8 interview rounds with 4-path routing (code, user, research, judgment). Ambiguity reduced from unscoped "should we add MobSF?" to 0.195 with 16 concrete acceptance criteria.
- **Applies when:** Any feature that spans multiple tools, has unclear scope, or requires architecture decisions before implementation. Especially valuable when the user says "deep research" — the interview prevents premature implementation.

### 2. Research-first discovery prevents wrong tool choices
- **Description:** Web research during the interview discovered that mobsfscan works ONLY on source code (not compiled APKs), and that Androguard can detect ~60% of insecure API patterns at bytecode level WITHOUT decompilation. This pivoted the architecture from "integrate MobSF" to a 3-tier hybrid approach.
- **Evidence:** Original question was "should we integrate MobSF?" — answer was "no, extract specific capabilities (manifest checks via Androguard, code SAST via mobsfscan on jadx output, bytecode patterns via Androguard analysis API)."
- **Applies when:** Evaluating external tool integration. Always research the tool's actual capabilities and constraints before committing to an integration approach.

### 3. Ouroboros seed execution for multi-phase implementation
- **Description:** The seed with 16 ACs was executed via `ooo run`, producing 6,838 lines across 22 files in ~85 minutes. The AC tree tracked progress through 5 levels with parallel execution. 14/16 ACs completed quickly; the remaining 2 (validation against test APKs) took longer because they couldn't be fully automated without the actual APKs.
- **Evidence:** AC tree progressed: 0/16 → 3/16 (Level 1) → 9/16 (Level 2) → 11/16 (Level 3) → 14/16 (Level 4) → 16/16 (Level 5). Code growth tracked via git diff showed steady progress (2,719 → 3,191 → 4,177 → 6,838 insertions).
- **Applies when:** Large multi-file features (10+ files, 3+ phases) where acceptance criteria can be clearly defined. The seed format forces explicit success criteria.

### 4. Citadel 5-pass review catches architecture bugs that linters miss
- **Description:** After Ouroboros execution, Citadel review found 5 warnings including a platform-signing false equivalence (equating "not debug-signed AND in priv-app" with "platform-signed"), priv-app path detection too broad, and code duplication across 3 files.
- **Evidence:** Warning #3 (platform signing) was a genuine security logic bug — third-party APKs placed in priv-app by OEMs would incorrectly get severity bumps AND reductions. The service already had the correct 3-tier heuristic (`_has_signature_or_system_protection`) but the tool handler wasn't using it.
- **Applies when:** After any AI-generated code, especially security-sensitive logic. Ouroboros produces functional code but may take shortcuts on architecture patterns that only a targeted review catches.

### 5. Research fleet for targeted fix validation before implementation
- **Description:** Before fixing the 5 warnings, deployed 3 scout agents in parallel to research: (a) correct Android priv-app/platform-signing detection in firmware analysis tools, (b) code organization patterns in the Wairz codebase, (c) Pydantic model conventions in Wairz routers. Each scout produced independent findings that converged on clear recommendations.
- **Evidence:** All 3 scouts agreed. Scout 1 confirmed the 3-tier heuristic was correct. Scout 2 found androguard_service.py was 2.6x the next largest service. Scout 3 found 9/10 routers use schemas/ for models.
- **Applies when:** Code review warnings that have multiple valid fix approaches. Research fleet prevents guessing and ensures fixes align with project conventions.

### 6. Mixin pattern for splitting large service files
- **Description:** Split 3,375-line androguard_service.py into 855-line core + 2,584-line ManifestChecksMixin. The mixin contains all `_check_*` methods and is inherited by AndroguardService. Public API unchanged — all existing imports still work via re-export.
- **Evidence:** `ManifestFinding` moved to manifest_checks.py as canonical definition, re-exported from androguard_service.py. All `self._check_*` calls in `scan_manifest_security()` work via inheritance.
- **Applies when:** Service files exceeding ~1,500 lines with a natural split boundary (e.g., "orchestration" vs "individual checks"). Mixin inheritance preserves the public API without refactoring imports.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Don't integrate full MobSF | MobSF is a 1.5GB+ Django app — too heavy for a firmware RE platform | Correct — extracted specific capabilities instead |
| Phase manifest checks independently | Manifest checks need no new deps (Androguard already parses manifests), code SAST needs jadx+mobsfscan | Correct — Phase 1 shipped in the same session |
| On-demand, not auto during extraction | Auto-scanning all APKs during firmware unpack would slow extraction and generate noise | Correct — matches existing Wairz patterns (Ghidra, YARA, etc.) |
| Static severity + context bump/reduction | Firmware system apps need different FP handling — flag everything but adjust severity based on priv-app and platform signing | Correct — review confirmed the model but caught a bug in the detection logic |
| Use APK() not AnalyzeAPK() for manifest checks | AnalyzeAPK() parses DEX (slow); APK() only parses manifest (fast, <500ms) | Correct — review confirmed this as a good optimization |
| Mixin pattern over module-level functions | Individual check methods use `self._get_manifest_attr()` and share state — methods, not functions | Correct — clean inheritance, no API changes |
| Create _android_helpers.py for shared APK code | 3 tool files had byte-for-byte identical `_APK_DIRS` and `_find_apk()` | Correct — first shared helper in ai/tools/ but well-motivated |
| Move Pydantic models to schemas/apk_scan.py | 9/10 existing routers import from schemas/ — apk_scan.py was the outlier | Correct — fixes forward reference and follows convention |

### 7. Smoke test with real firmware APKs validates the full stack
- **Description:** After deploying, ran manifest scan against 3 APKs from the Horizon Tablet Android firmware: BasicDreams (clean, 0 findings), framework-res.apk (18 findings, platform-signed), Traceur (3 findings, platform-signed). This caught the SDK threshold constant bug that syntax checking and import tests missed.
- **Evidence:** HTTP 500 on first API call (`NameError`), fixed within minutes, then 200 OK with correct findings. framework-res.apk scanned in 1.4s (acceptable for the largest Android APK). Regular APKs in 18-81ms (well under 500ms target).
- **Applies when:** After any file split or refactoring. `py_compile` and import checks are necessary but not sufficient — they don't catch runtime `NameError` in methods that haven't been called. Always run an actual API call or integration test against a real data sample.
