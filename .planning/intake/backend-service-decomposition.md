---
title: "Backend: Decompose God-Class Services"
status: pending
priority: high
target: backend/app/services/
---

> **Status note (2026-04-20):** unchanged — no part shipped yet.
> Attempted in session 2026-04-20 but deferred: `manifest_checks.py`
> has grown to **2589 LOC** (from the 2263 measured at intake time),
> and the full 8-file split requires a dedicated focused session.
> See `.planning/campaigns/wairz-intake-sweep-2026-04-19.md` § Session
> 2026-04-20 summary for the next-session pickup prompt. Table in
> "Problem" below still reflects the intake-time measurements; see
> campaign file for current numbers.

## Problem

Five services are oversized and mix multiple responsibilities:

| File | Lines | Concern |
|---|---|---|
| `backend/app/services/manifest_checks.py` | 2263 | A 2263-line **mixin** (`ManifestChecksMixin`, line 59) attached to `AndroguardService` |
| `backend/app/services/sbom_service.py` | 2073 | Syft, LIEF, kernel-module parsing, SO-name parsing, PURL construction all in one class |
| `backend/app/services/emulation_service.py` | 1454 | Combines Docker orchestration, user-mode workflow, system-mode workflow, kernel selection, sysroot mounting |
| `backend/app/services/mobsfscan_service.py` | 1328 | Parsing, normalization, pipeline orchestration (line 970), persistence |
| `backend/app/services/security_audit_service.py` | 1036 | 15 `_scan_*` free functions + four async scanners |

## Approach

This is **campaign-sized work** — one service per PR, done sequentially. Do NOT do all five at once.

### Priority Order

1. **`manifest_checks.py`** — worst offender architecturally (mixin hack). Easiest to split.
2. **`security_audit_service.py`** — clean natural seams (credentials, permissions, external scanners, hash lookups). Related intake: `backend-private-api-and-circular-imports.md` (which makes the private helpers public first).
3. **`sbom_service.py`** — strategy pattern fits naturally.
4. **`mobsfscan_service.py`** — can wait, lowest call-site count.
5. **`emulation_service.py`** — most complex, touches system-emulation; do last.

### Phase 1 — Convert `ManifestChecksMixin` to Composition

`backend/app/services/manifest_checks.py:59` declares a mixin class with 2263 lines. `AndroguardService` inherits from it (`androguard_service.py:17`). This is not a mixin — it's "I didn't want to split the file."

**New structure:**

```
backend/app/services/
├── androguard_service.py       (unchanged public API)
├── manifest_checks/
│   ├── __init__.py             (re-exports ManifestChecker)
│   ├── checker.py              (the public interface — thin)
│   ├── permissions.py          (~300 lines of permission-related checks)
│   ├── components.py           (~500 lines: activities, services, providers, receivers)
│   ├── network_security.py     (~200 lines: NSC, cleartext, cert pinning)
│   ├── backup_and_debug.py     (~200 lines: allowBackup, debuggable, test-only)
│   ├── signing.py              (~300 lines: platform signing, sharedUid, signatureOrSystem perms)
│   ├── exported_checks.py      (~400 lines: exported analysis)
│   └── misc.py                 (~300 lines: remaining checks)
```

`AndroguardService`:
```python
# Before
class AndroguardService(ManifestChecksMixin):
    ...

# After
class AndroguardService:
    def __init__(self, ...):
        self.manifest_checker = ManifestChecker(self)  # back-reference if needed
        ...
    
    def run_manifest_checks(self, *args, **kwargs):
        return self.manifest_checker.run_all(*args, **kwargs)
```

**Migration is mechanical.** For each method in the mixin, cut it into the appropriate topic file as a method of `ManifestChecker`. Update any `self.XXX` accesses that referred to `AndroguardService` fields — inject them via `__init__`.

### Phase 2 — Split `security_audit_service.py` into a subpackage

```
backend/app/services/security_audit/
├── __init__.py                 (re-exports run_security_audit)
├── credentials.py              (scan_credentials, scan_crypto_material, scan_shadow, scan_hardcoded_ips)
├── permissions.py              (scan_filesystem_permissions, scan_setuid)
├── binaries.py                 (scan_binary_protections)
├── external_scanners.py        (trufflehog, noseyparker, shellcheck, bandit)
├── hash_lookups.py             (virustotal, abusech, clamav, hashlookup)
└── orchestrator.py             (run_security_audit — orchestrates all above)
```

**Important:** Promote `_scan_credentials`, `_scan_crypto_material`, `_scan_shadow` to public (`scan_credentials`, etc.) since `assessment_service.py` already calls them cross-module. See `backend-private-api-and-circular-imports.md` — do that intake FIRST so this split doesn't break imports.

### Phase 3 — Split `sbom_service.py` with Strategy Pattern

```
backend/app/services/sbom/
├── __init__.py                 (re-exports SbomService)
├── service.py                  (SbomService — orchestration only, ~200 lines)
├── strategies/
│   ├── base.py                 (SbomStrategy protocol)
│   ├── syft_strategy.py        (scan_syft)
│   ├── dpkg_strategy.py        (scan_dpkg)
│   ├── rpm_strategy.py         (scan_rpm)
│   ├── opkg_strategy.py        (scan_opkg)
│   ├── lief_strategy.py        (scan_lief_metadata)
│   ├── kernel_modules_strategy.py
│   └── so_files_strategy.py
├── purl.py                     (_build_purl — pure function, easier to test)
└── normalization.py            (component dedup, version normalization)
```

`SbomService` becomes a coordinator: runs all strategies, merges results. Each strategy is independently testable.

### Phase 4 — Split `mobsfscan_service.py`

```
backend/app/services/mobsfscan/
├── __init__.py
├── service.py                  (public API — run_scan, get_cached)
├── pipeline.py                 (MobsfScanPipeline — just the orchestration)
├── parser.py                   (parse mobsfscan JSON output)
└── normalization.py            (finding dedup, severity normalization)
```

### Phase 5 — Split `emulation_service.py`

```
backend/app/services/emulation/
├── __init__.py
├── service.py                  (EmulationService public API — ~200 lines)
├── user_mode.py                (user-mode QEMU workflow)
├── system_mode.py              (system-mode QEMU workflow)
├── docker_ops.py               (Docker container lifecycle — wraps docker_safety)
├── kernel_selection.py         (KernelSelector — matches arch to kernel)
└── sysroot_mount.py            (sysroot bind-mount logic)
```

### General Rules for Splits

- Preserve public API — no renames, no signature changes
- Use `__init__.py` to re-export the old names so `from app.services.X import Y` keeps working
- Add new tests in per-topic test files rather than one giant test file
- Run typecheck and existing tests after each split

## Files

Per phase, listed above. Net effect: 5 files → 5 subpackages with ~6 modules each. Line counts drop from 7000+ → distributed across ~30 files.

## Acceptance Criteria

- [ ] Phase 1: `manifest_checks/` subpackage, `AndroguardService` uses composition, no mixin inheritance
- [ ] Phase 2: `security_audit/` subpackage, `assessment_service` imports public names (not `_scan_*`)
- [ ] Phase 3: `sbom/` subpackage with strategy pattern
- [ ] Phase 4: `mobsfscan/` subpackage
- [ ] Phase 5: `emulation/` subpackage
- [ ] All existing tests pass after each phase
- [ ] `wc -l backend/app/services/*.py | sort -rn | head -3` shows no service > 1000 lines after completion

## Risks

- **This is the largest single structural change** — do phases independently, each in its own PR, each with full test runs
- Import sprawl during transition — prefer re-exporting from `__init__.py` over rewriting every caller
- Circular imports may become visible when splitting; if so, follow up with `backend-private-api-and-circular-imports.md`
- Git blame becomes harder to follow — each phase should use `git mv` where possible

## References

- Backend review H7 (god objects), M (refactoring opportunities)
- Related intake: `backend-private-api-and-circular-imports.md` (must precede Phase 2)
