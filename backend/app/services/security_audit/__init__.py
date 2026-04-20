"""Security audit scanning — split into a subpackage for maintainability.

Public API re-exports (preserved across the Phase 5 part 2 split):

- ``SecurityFinding``, ``ScanResult`` — dataclasses (in ``_base``)
- ``SCANNERS``, ``run_scan_subset`` — scanner registry + dispatch
- ``run_security_audit``, ``run_security_audit_multi`` — sync orchestrators
- ``run_clamav_scan``, ``run_virustotal_scan``, ``run_abusech_scan``,
  ``run_known_good_scan`` — async threat-intel scanners

Callers may import from ``app.services.security_audit`` directly; the
legacy ``app.services.security_audit_service`` module is a temporary
compatibility shim that will be removed at the end of the Phase 5 split.
"""

from app.services.security_audit._base import (
    MAX_FINDINGS_PER_CHECK,
    ScanResult,
    SecurityFinding,
)

__all__ = [
    "MAX_FINDINGS_PER_CHECK",
    "ScanResult",
    "SecurityFinding",
]
