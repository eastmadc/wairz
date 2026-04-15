# Anti-patterns: APK Security Scanning (Ouroboros-driven)

> Extracted: 2026-04-15 (updated after deployment)
> Source: Citadel 5-pass code review, research fleet findings, deployment smoke test

## Failed Patterns

### 1. Negating debug signing as a proxy for platform signing
- **What was done:** The Ouroboros-generated code used `if not is_debug and is_priv_app: is_platform_signed = True` to detect platform-signed APKs.
- **Failure mode:** False equivalence — a third-party APK could be release-signed (not debug) but not platform-signed, yet land in priv-app through OEM bundling. This would incorrectly trigger severity bumps AND severity reductions (for "expected system behaviour" checks).
- **Evidence:** Citadel review Warning #3. The service already had the correct 3-tier heuristic (`_has_signature_or_system_protection()` — declared permissions, requested platform permissions, shared UIDs) but the tool handler and router independently implemented the wrong shortcut.
- **How to avoid:** When detecting platform signing in firmware analysis, always use manifest-based heuristics (declared signatureOrSystem permissions, requested platform-only permissions, system shared UIDs). Never rely on certificate signing alone without the actual platform certificate.

### 2. Path component matching without partition context
- **What was done:** `_is_priv_app_path()` used `"priv-app" in rel.split(os.sep)` to detect privileged app directories.
- **Failure mode:** Any path component named "priv-app" would match, including paths like `data/priv-app-backup/foo.apk` or firmware with nested directories containing "priv-app" in a non-partition context.
- **Evidence:** Citadel review Warning #2. Android firmware has a specific partition/priv-app structure (system/priv-app, product/priv-app, vendor/priv-app, system_ext/priv-app).
- **How to avoid:** When matching firmware paths, always check the partition prefix paired with the directory name, not just the directory name alone. Use `parts[i] in ("system", "product", "vendor", "system_ext") and parts[i+1] == "priv-app"`.

### 3. Duplicating helper code across tool files
- **What was done:** Ouroboros execution copy-pasted `_APK_DIRS`, `_find_apk()`, and `_check_androguard()` identically across android.py, android_bytecode.py, and android_sast.py (3x duplication, ~50 lines each).
- **Failure mode:** If a new APK directory is added (e.g., `odm/app`), only one file might be updated. The duplication was acknowledged in comments ("shared with android_bytecode.py") but never refactored.
- **Evidence:** Citadel review Warning #1, confirmed by Scout 2 (byte-for-byte identical across all 3 files). No existing shared helper pattern existed in ai/tools/ to guide the generator.
- **How to avoid:** After AI-generated multi-file features, check for duplicated helper functions. Extract to a shared module (like `_android_helpers.py`) before merging.

### 4. Ouroboros seed execution stuck on verification-only ACs
- **What was done:** ACs 12 and 13 ("findings are superset of MobSF" and "FP rate under 20%") were included as acceptance criteria in the seed.
- **Failure mode:** The executor spent ~40 minutes trying to satisfy these ACs but couldn't fully verify them without downloading and running actual test APKs (DIVA, InsecureBankv2, OVAA). It eventually completed by building test infrastructure and synthetic validation, but the context cost was high.
- **Evidence:** AC tree showed 14/16 complete for ~40 minutes while ACs 12/13 looped. Code growth slowed from ~200 lines/poll to ~50 lines/poll during this period.
- **How to avoid:** Validation criteria that require external resources (downloading test files, running external tools, network access) should be separated from implementation ACs. Use implementation ACs for the seed, and define validation ACs as manual post-execution steps. Alternatively, phrase validation ACs as "validation infrastructure is built" rather than "validation passes."

### 5. Inline Pydantic models in routers
- **What was done:** Ouroboros-generated code defined all response models inline in apk_scan.py (~130 lines of models) instead of in schemas/apk_scan.py.
- **Failure mode:** Forward reference — helper functions referenced `ManifestFindingResponse` before its definition. Works at runtime due to Python's late binding but violates the project convention (9/10 routers import from schemas/).
- **Evidence:** Citadel review Warning #5, confirmed by Scout 3. Python allows forward references in function bodies but it's confusing and fragile.
- **How to avoid:** When generating new routers, check the project convention for model placement. In Wairz, models always go in `schemas/`.

### 6. Module-level constants missed during file split
- **What was done:** When splitting androguard_service.py into core + manifest_checks.py mixin, the `_MIN_SDK_SECURE_THRESHOLD` and `_MIN_SDK_CRITICAL_THRESHOLD` constants were left in the core file while the `_check_min_sdk()` method that references them was moved to the mixin.
- **Failure mode:** Runtime `NameError: name '_MIN_SDK_CRITICAL_THRESHOLD' is not defined` on the first API call to the manifest scan endpoint. Caught during smoke test, not during syntax checking (`py_compile` and `python -c "import ..."` passed because the error only surfaces when the method is actually called).
- **Evidence:** HTTP 500 from `POST /apk-scan/manifest` with `detail: "Manifest scan failed: name '_MIN_SDK_CRITICAL_THRESHOLD' is not defined"`. Fixed by moving constants to manifest_checks.py.
- **How to avoid:** After any file split, grep both files for all module-level names (`_UPPER_CASE` constants, helper functions) used by the extracted code. `py_compile` and import checks are insufficient — they only catch syntax errors and import-time failures, not runtime reference errors in methods that haven't been called yet. Run an actual integration test (API call or unit test) on the split code before deploying.

### 7. Docker container name conflict from background builds
- **What was done:** Started `docker compose up -d --build` in the background, then ran it again in the foreground when the first attempt appeared stalled.
- **Failure mode:** `Error response from daemon: Conflict. The container name "/e2298b1f4883_wairz-backend-1" is already in use`. The background build had created a container but the foreground build couldn't reuse the name.
- **Evidence:** Needed `docker rm -f` on the stale container before `up -d` would succeed.
- **How to avoid:** Don't run `docker compose up -d --build` concurrently for the same service. If a background build is running, wait for it to complete or cancel it before starting another. Use `docker compose ps` to check for orphaned containers before rebuilding.

### 8. semgrep requires pkg_resources from setuptools<70 in uv venvs
- **What was done:** Added `semgrep>=1.80.0` to pyproject.toml. mobsfscan depends on semgrep as a subprocess CLI tool. uv installed semgrep into the venv.
- **Failure mode:** `ModuleNotFoundError: No module named 'pkg_resources'`. semgrep's opentelemetry dependency chain imports `pkg_resources` from setuptools. uv venvs don't include setuptools by default, and setuptools 70+ removed `pkg_resources` as a bundled module.
- **Evidence:** `semgrep --version` crashed with the import error. Fixed by adding `setuptools<70` install step in Dockerfile after `uv sync`.
- **How to avoid:** When adding CLI tools that depend on `pkg_resources` (common in older Python packages with opentelemetry/instrumentation), install `setuptools<70` explicitly in uv venvs. Standard venvs include setuptools by default but uv does not.

### 9. analysis_cache operation column too narrow for Java class name cache keys
- **What was done:** JADX decompilation results were cached with operation keys like `jadx_source:com/android/server/telecom/CallDiagnosticServiceController$$ExternalSyntheticLambda0.java`.
- **Failure mode:** `StringDataRightTruncationError: value too long for type character varying(100)`. Java class names with inner classes and synthetic lambdas easily exceed 100 characters.
- **Evidence:** SAST scan on MtkTelecom.apk returned HTTP 500 with the truncation error. Fixed by widening `operation` column from VARCHAR(100) to VARCHAR(512).
- **How to avoid:** When reusing existing DB columns for new data types (Java class paths vs short operation names like "decompile:main"), verify the new values fit the column constraints. Java fully-qualified class names with `$$` synthetic suffixes commonly reach 150+ characters.
