"""Legacy compatibility shim for the security_audit subpackage.

As of the Phase 5 part 2 split, all implementation lives under
``app.services.security_audit``. This module re-exports the same public
surface that existed before the split so pre-split imports keep working.

New callers SHOULD import from ``app.services.security_audit`` directly.
This shim will be removed once all in-tree callers have migrated (the
step-8 cut-over commit updates them in place).
"""

from app.services.security_audit._base import (
    MAX_FINDINGS_PER_CHECK,
    ScanResult,
    SecurityFinding,
    _is_text_file,
    _rel,
    _shannon_entropy,
)
from app.services.security_audit.credentials import (
    _scan_credentials,
    _scan_crypto_material,
    _scan_shadow,
)
from app.services.security_audit.external_scanners import (
    _scan_bandit,
    _scan_noseyparker,
    _scan_shellcheck,
    _scan_trufflehog,
)
from app.services.security_audit.hash_lookups import (
    run_abusech_scan,
    run_clamav_scan,
    run_known_good_scan,
    run_virustotal_scan,
)
from app.services.security_audit.network import (
    _scan_network_dependencies,
    _scan_update_mechanisms,
)
from app.services.security_audit.orchestrator import (
    SCANNERS,
    ScannerFn,
    _run_checks_against_root,
    _SECURITY_CHECKS,
    run_scan_subset,
    run_security_audit,
    run_security_audit_multi,
)
from app.services.security_audit.permissions import (
    _scan_init_services,
    _scan_setuid,
    _scan_world_writable,
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
    # Legacy private-symbol re-exports (removed in step 8 cut-over):
    "_run_checks_against_root",
    "_SECURITY_CHECKS",
    "_is_text_file",
    "_rel",
    "_scan_bandit",
    "_scan_credentials",
    "_scan_crypto_material",
    "_scan_init_services",
    "_scan_network_dependencies",
    "_scan_noseyparker",
    "_scan_setuid",
    "_scan_shadow",
    "_scan_shellcheck",
    "_scan_trufflehog",
    "_scan_update_mechanisms",
    "_scan_world_writable",
    "_shannon_entropy",
]
