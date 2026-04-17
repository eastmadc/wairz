---
title: "Backend: Promote Private APIs + Break Circular Imports"
status: pending
priority: high
target: backend/app/services/
---

## Problem

### P1. `assessment_service` calls private `_scan_*` helpers from `security_audit_service`

`backend/app/services/assessment_service.py:197-202, 290` imports:
- `_scan_credentials`
- `_scan_crypto_material`
- `_scan_shadow`

All prefixed with `_` signaling "private, do not use outside module." This is a leaky abstraction:
- If `security_audit_service` renames or changes these signatures, `assessment_service` silently breaks at runtime
- IDE / static analysis tools flag this pattern
- Future refactoring tools (e.g., rename-symbol) may miss the cross-module callers

### P2. Circular lazy import between `emulation_service` and `kernel_service`

Two modules lazy-import each other at function level to dodge module-level cycles:

**`backend/app/services/emulation_service.py:26-34`**:
```python
from app.services.emulation_constants import _validate_kernel_file  # top-level
# ...
# emulation_service.py:696
from app.services.kernel_service import KernelService  # function-local
# emulation_service.py:1187
from app.services.kernel_service import KernelService  # function-local again
```

**`backend/app/services/kernel_service.py:322-323`**:
```python
def some_method(self):
    # avoid circular dependency at module level
    from app.services.emulation_service import _validate_kernel_file
```

But `_validate_kernel_file` actually lives in `emulation_constants.py` (where `emulation_service` imports it from). `kernel_service` should bypass `emulation_service` and import from the constants module directly — breaking the cycle cleanly.

### P3. Systemic function-local imports hide cycles

10+ services use function-local imports to dodge cycles:
- `assessment_service.py`: 9 function-local imports (lines 60, 197, 239, 240, 290, 335, 530, 584, 645)
- `security_audit_service.py`: 5 (lines 901, 991, 1029, 1082, 1147)
- `emulation_service.py`: 6 (lines 250, 696, 956, 1187, 1251, 1367)
- `fuzzing_service.py`: 4 (lines 96, 404, 482, 778)

This pattern hides cycles from static analysis. The true problem: services at the top of the dependency graph (`assessment_service`, `security_audit_service`) depend on many peers. There's no orchestration layer distinct from domain services.

## Approach

### Phase 1 — Fix P2 (circular import — 10 minutes)

In `backend/app/services/kernel_service.py:322-323`:

```python
# Before
def some_method(self):
    from app.services.emulation_service import _validate_kernel_file  # avoid cycle
    _validate_kernel_file(...)

# After (top-level import)
from app.services.emulation_constants import _validate_kernel_file
# ...
class KernelService:
    def some_method(self):
        _validate_kernel_file(...)  # top-level now, no function-local import
```

This eliminates the lazy-import that existed only because `kernel_service` imported from `emulation_service` unnecessarily.

### Phase 2 — Fix P1 (promote private APIs)

Rename the three helpers in `security_audit_service.py` (dropping leading underscore):
- `_scan_credentials` → `scan_credentials`
- `_scan_crypto_material` → `scan_crypto_material`
- `_scan_shadow` → `scan_shadow`

Keep the old names as deprecated aliases temporarily:
```python
# Deprecated alias for backward compatibility. Remove after 2 releases.
_scan_credentials = scan_credentials
```

Update `assessment_service.py` to use the new names. Document in the docstring of each that these are public and consumable by other services.

**Better alternative (preferred):** Add a `run_scan_subset(scanners=["credentials", "crypto_material", "shadow"])` method to `security_audit_service` that internally dispatches. Then `assessment_service` calls the public method with a list.

```python
# backend/app/services/security_audit_service.py
SCANNERS = {
    "credentials": scan_credentials,
    "crypto_material": scan_crypto_material,
    "shadow": scan_shadow,
    "filesystem_permissions": scan_filesystem_permissions,
    # ...
}

async def run_scan_subset(scanner_names: list[str], firmware_id: UUID, ...) -> list[Finding]:
    findings = []
    for name in scanner_names:
        scanner = SCANNERS.get(name)
        if not scanner:
            raise ValueError(f"Unknown scanner: {name}")
        findings.extend(await run_in_executor(None, scanner, ...))
    return findings
```

### Phase 3 — Audit remaining function-local imports

Produce a dependency graph of inter-service imports:

```bash
# One-shot script to emit DOT graph
cd backend/app/services
grep -r "from app.services\." --include="*.py" -h | \
    sed -E 's/.*from app\.services\.([^ ]+) import.*/\1/' | \
    sort | uniq -c
```

Identify cycle pairs. For each cycle, choose one side to move to a shared `_base.py` or `constants.py` module. Track the list of function-local imports — every time one is removed, the static analysis improves.

**Long-term target:** No function-local imports in `backend/app/services/*.py`. All dependencies declared at module level; cycles broken via shared constants or extracted interfaces.

## Files

### Phase 1
- `backend/app/services/kernel_service.py:322-323` (move import to top)

### Phase 2
- `backend/app/services/security_audit_service.py` (rename 3 helpers + add alias)
- `backend/app/services/assessment_service.py` (update 3 import sites — lines 197-202, 290)
- **OR** add `run_scan_subset` to `security_audit_service` and update `assessment_service` to call it

### Phase 3 (follow-up PR)
- Dependency-graph script + list of function-local imports
- Per-cycle: identify shared extract point, do the extract
- Convert function-local imports to top-level one service at a time

## Acceptance Criteria

- [ ] Phase 1: `grep -n 'from app.services.emulation_service import _validate_kernel_file' backend/app/services/kernel_service.py` returns nothing
- [ ] Phase 1: `kernel_service.py` and `emulation_service.py` both top-level import from `emulation_constants`, neither imports the other
- [ ] Phase 2: `grep -rn '_scan_credentials\b\|_scan_crypto_material\b\|_scan_shadow\b' backend/app/services/assessment_service.py` returns zero hits — all callers use public names
- [ ] Phase 2 (if using run_scan_subset): `assessment_service` has no direct function references to `security_audit_service` internals
- [ ] All existing tests pass

## Risks

- MCP tools may call the `_scan_*` names directly — grep `backend/app/ai/tools` and update if so
- Frontend has no exposure to Python naming, no risk there
- Phase 3 is open-ended and can grow — cap the scope to specific service pairs per PR, not "all of them"

## References

- Backend review C3, H4, H5
