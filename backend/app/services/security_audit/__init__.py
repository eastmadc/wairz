"""Security audit scanning — split into a subpackage for maintainability.

Public API re-exports (preserved across the Phase 5 part 2 split):

- ``SecurityFinding``, ``ScanResult`` — dataclasses (in ``_base``).
- ``SCANNERS``, ``run_scan_subset`` — scanner registry + by-name dispatch.
- ``run_security_audit``, ``run_security_audit_multi`` — sync orchestrators.
- ``run_clamav_scan``, ``run_virustotal_scan``, ``run_abusech_scan``,
  ``run_known_good_scan`` — async threat-intel scanners.

Callers should import from ``app.services.security_audit`` directly; the
legacy ``app.services.security_audit_service`` module is a temporary
compatibility shim that re-exports these same names and will be removed
once in-tree callers are migrated.
"""

from app.services.security_audit._base import (
    MAX_FINDINGS_PER_CHECK,
    ScanResult,
    SecurityFinding,
)
from app.services.security_audit.hash_lookups import (
    run_abusech_scan,
    run_clamav_scan,
    run_known_good_scan,
    run_virustotal_scan,
)
from app.services.security_audit.orchestrator import (
    SCANNERS,
    ScannerFn,
    run_scan_subset,
    run_security_audit,
    run_security_audit_multi,
)

__all__ = [
    "MAX_FINDINGS_PER_CHECK",
    "SCANNERS",
    "ScanResult",
    "ScannerFn",
    "SecurityFinding",
    "run_abusech_scan",
    "run_clamav_scan",
    "run_known_good_scan",
    "run_scan_subset",
    "run_security_audit",
    "run_security_audit_multi",
    "run_virustotal_scan",
]
