# Anti-patterns: Session 11

> Extracted: 2026-04-06

## Failed Patterns

### 1. Broad except Exception Swallowing Real Errors
- **What was done:** `_extract_function_hashes()` used `except Exception: return None` which silently caught `AttributeError: no attribute 'static_symbols'`, making every binary appear stripped.
- **Failure mode:** LIEF API incompatibility was invisible — the function returned None, triggering the "stripped binary" fallback, and the user saw "no symbol-level diff available" for a binary with 101 functions.
- **Evidence:** Debug testing showed `binary.static_symbols` doesn't exist in LIEF 0.16.
- **How to avoid:** When `except Exception` catches and returns a fallback value, log the exception at DEBUG level. Or narrow the exception type.

### 2. Changing Grype Input Format With User-Facing Export Format
- **What was done:** When upgrading CycloneDX export from 1.5 to 1.7, the grype_service.py input SBOM was also changed to 1.7 in a batch replace.
- **Failure mode:** Grype 0.87 can't parse CycloneDX 1.7 → all vulnerability scans returned 0 results with "sbom format not recognized" error swallowed.
- **Evidence:** `grype sbom:test.cdx.json` with specVersion 1.7 returned exit code 1 with "sbom format not recognized".
- **How to avoid:** Internal tool input formats (Grype, Syft) must be tested separately from user-facing exports. Never batch-replace version strings across the entire codebase.

### 3. EROFS Permission Preservation Breaking Analysis
- **What was done:** `fsck.erofs --extract` preserves original filesystem permissions. Android system files have 600 (owner-only) permissions.
- **Failure mode:** Python `open()` in the SBOM scanner got PermissionError on `build.prop` (600 perms), silently skipping Android OS detection. SBOM showed 418 components but no android version.
- **Evidence:** `os.path.isfile()` returned True but `open()` raised PermissionError in the thread executor context.
- **How to avoid:** Always `chmod -R +r` after extracting Android EROFS/ext4 partitions.

### 4. Finally Block Not Cleaning Up All State
- **What was done:** arq worker's `finally` block only reset `project.status` but left `firmware.unpack_stage` and `firmware.unpack_progress` set. Also didn't save an error log.
- **Failure mode:** After timeout, firmware appeared stuck at "Running unblob extraction / 30%" indefinitely. User saw no error message. Retry button was hidden because `unpack_stage` was still set.
- **Evidence:** DB query showed `unpack_stage: Running unblob extraction, unpack_progress: 30, unpack_log: None`.
- **How to avoid:** Every `finally` block that resets state must reset ALL related fields, not just the parent entity. Write a descriptive error log.

### 5. Fleet Agent Using Wrong LIEF API Constants
- **What was done:** Parallel agent wrote code using `binary.static_symbols`, `lief.ELF.ELF_DATA`, and `lief.ELF.ELF_CLASS` based on LIEF documentation, not the actual installed version.
- **Failure mode:** All three constants don't exist in the Docker image's LIEF version. Code compiled but failed at runtime.
- **Evidence:** Post-merge testing showed AttributeError on `static_symbols`, and Bash testing showed `ELF_DATA` and `ELF_CLASS` need `Header.` prefix.
- **How to avoid:** Agent prompts for LIEF code should include "test against the Docker container LIEF version" and reference `binary_analysis_service.py` which has working LIEF patterns.

### 6. Missing Python Dependency in Docker Image
- **What was done:** `capstone` was used in comparison_service.py but not listed in `pyproject.toml` dependencies.
- **Failure mode:** Code passed local tests (capstone installed locally) but 500 error in Docker: `ModuleNotFoundError: No module named 'capstone'`.
- **Evidence:** Instruction diff endpoint returned 500 immediately after deployment.
- **How to avoid:** After adding any new import, check `pyproject.toml` dependencies. Run `docker compose exec backend python -c "import <module>"` to verify.
