# Anti-patterns: Session 28 — Security Audit Fix

> Extracted: 2026-04-10
> Campaign: none (ad-hoc bug fix)

## Failed Patterns

### 1. Router Function Name Shadows Service Import
- **What was done:** REST endpoint function `run_clamav_scan` in `routers/security_audit.py` was given the same name as the imported service function `run_clamav_scan` from `services/security_audit_service.py`. The endpoint definition (lower in the file) silently replaced the import in module scope.
- **Failure mode:** When `run_audit()` called `run_clamav_scan(firmware.extracted_path)`, Python resolved to the endpoint function (not the service). The endpoint function's first parameter is `project_id: uuid.UUID` but received a string path. When ClamAV was unavailable, it returned a `ClamScanResponse` Pydantic model *before* touching the database. Iterating a Pydantic model yields `(field_name, value)` tuples, which were added to `all_findings` as if they were `SecurityFinding` objects. Persistence then crashed with `AttributeError: 'tuple' object has no attribute 'title'`.
- **Evidence:** Debug injection revealed 6 bad entries: `('status', 'unavailable'), ('files_scanned', 0), ('infected_count', 0), ('infected_files', []), ('findings_created', 0), ('errors', [...])` — the fields of `ClamScanResponse`.
- **How to avoid:** Always use distinct names for router endpoint functions vs. imported service functions. Convention: append `_endpoint` suffix to router functions that share a conceptual name with a service function. The other threat intel endpoints (`run_abusech_scan_endpoint`, `run_known_good_scan_endpoint`) already followed this convention — `run_clamav_scan` was the exception.

### 2. Pydantic Model Iteration Surprise
- **What was done:** Code assumed iterating over a return value would yield domain objects, but Pydantic v2 models are iterable — they yield `(field_name, value)` tuples (like `dict.items()`).
- **Failure mode:** `for sf in clamav_findings:` silently iterated over the Pydantic model fields instead of raising a TypeError. No type error at the iteration site — the crash happened later at persistence.
- **Evidence:** The `extend((sf, firmware.id) for sf in clamav_findings)` line created `(('status', 'unavailable'), firmware.id)` tuples instead of `(SecurityFinding, UUID)` tuples.
- **How to avoid:** When a function is expected to return `list[T]`, verify the return type matches, especially when the function could be shadowed. Static type checkers (mypy, pyright) would catch this if the codebase uses strict mode.
