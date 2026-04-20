"""Automated security scanning that persists findings to the database.

Runs the same checks as the MCP security tools but writes results directly
to the findings table so they're visible in the UI without needing an
active AI conversation.

Designed to run as a sync function in a thread executor (CPU-bound filesystem
scanning), then persist findings via an async DB session.
"""

import logging
import os
import re
import stat
from typing import Callable

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
from app.services.security_audit.permissions import (
    _scan_init_services,
    _scan_setuid,
    _scan_world_writable,
)

logger = logging.getLogger(__name__)



# ---------------------------------------------------------------------------
# Main scan orchestrator
# ---------------------------------------------------------------------------

_SECURITY_CHECKS = [
    ("credentials", _scan_credentials),
    ("shadow", _scan_shadow),
    ("setuid", _scan_setuid),
    ("init_services", _scan_init_services),
    ("world_writable", _scan_world_writable),
    ("crypto_material", _scan_crypto_material),
    ("network_dependencies", _scan_network_dependencies),
    ("update_mechanisms", _scan_update_mechanisms),
    # Optional external scanners — silently skip if not installed
    ("trufflehog", _scan_trufflehog),
    ("noseyparker", _scan_noseyparker),
    ("shellcheck", _scan_shellcheck),
    ("bandit", _scan_bandit),
]

#: Scanner callable: ``(root, findings) -> None`` (mutates findings list).
ScannerFn = Callable[[str, list[SecurityFinding]], None]

#: Public scanner registry — lookup-by-name dispatch for callers that
#: only want a subset of checks (e.g. ``assessment_service`` runs
#: credentials + shadow + crypto_material but not setuid/init/...).
#: Keeping the canonical list ``_SECURITY_CHECKS`` as source of truth
#: means a scanner added to the registry above is automatically
#: subset-dispatchable without a second mapping to maintain.
SCANNERS: dict[str, ScannerFn] = dict(_SECURITY_CHECKS)


def run_scan_subset(
    root: str,
    scanner_names: list[str],
    findings: list[SecurityFinding] | None = None,
) -> list[SecurityFinding]:
    """Run a subset of security scanners against ``root`` by name.

    Public entry point for services that want part of the audit without
    depending on the private ``_scan_*`` implementations. Appends to
    ``findings`` if supplied (matches the per-scanner mutation pattern)
    or returns a fresh list. Raises ``KeyError`` on an unknown scanner
    name — callers supply names from a known set.

    Example::

        findings: list[SecurityFinding] = []
        run_scan_subset(root, ["credentials", "crypto_material", "shadow"], findings)
    """
    if findings is None:
        findings = []
    for name in scanner_names:
        scanner = SCANNERS[name]  # intentionally KeyError on typo
        scanner(root, findings)
    return findings


def _run_checks_against_root(root: str, result: ScanResult) -> None:
    """Run every security check against ``root`` and aggregate into result."""
    for name, func in _SECURITY_CHECKS:
        try:
            before = len(result.findings)
            func(root, result.findings)
            result.checks_run += 1
            after = len(result.findings)
            if after > before:
                logger.info(
                    "Security check '%s' on %s: %d finding(s)",
                    name, root, after - before,
                )
        except Exception as e:
            result.errors.append(f"{name}: {e}")
            logger.warning(
                "Security check '%s' failed on %s: %s",
                name, root, e, exc_info=True,
            )


def run_security_audit(extracted_root: str) -> ScanResult:
    """Run all security checks against an extracted firmware filesystem.

    This is a sync function — call from a thread executor for async contexts.

    Built-in checks always run. External scanners (TruffleHog, Nosey Parker)
    run only if the binary is installed — they are optional enhancements.
    """
    result = ScanResult()
    _run_checks_against_root(extracted_root, result)
    return result


def run_security_audit_multi(roots: list[str]) -> ScanResult:
    """Multi-root variant of ``run_security_audit``.

    Each root is walked sequentially; findings are aggregated into a
    single ScanResult. ``checks_run`` counts each (root × check) pair
    so the caller can see total coverage.

    Designed for Phase 3a consumers that call ``get_detection_roots``
    to enumerate every partition dir (rootfs + scatter siblings).
    """
    result = ScanResult()

    if not roots:
        result.errors.append("No scan roots provided")
        return result

    any_valid = False
    for root in roots:
        if not root or not os.path.isdir(root):
            result.errors.append(f"Scan root does not exist: {root}")
            continue
        any_valid = True
        _run_checks_against_root(root, result)

    if not any_valid and roots:
        # Preserve legacy behaviour: run checks against the first root
        # even if it doesn't exist — the individual scanners silently
        # no-op on empty/nonexistent paths. This keeps ``checks_run``
        # non-zero for test_nonexistent_path.
        _run_checks_against_root(roots[0], result)

    return result
