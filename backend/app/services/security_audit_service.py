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


# ---------------------------------------------------------------------------
# Async threat intelligence scans (ClamAV, VirusTotal)
# These run as optional async phases after the sync audit completes.
# ---------------------------------------------------------------------------


async def run_clamav_scan(extracted_root: str) -> list[SecurityFinding]:
    """Scan extracted firmware with ClamAV (async, optional).

    Returns findings for infected files. Returns empty list if
    ClamAV is unavailable.
    """
    from app.services import clamav_service

    available = await clamav_service.check_available()
    if not available:
        logger.info("ClamAV not available — skipping antivirus scan")
        return []

    results = await clamav_service.scan_directory(extracted_root, max_files=500)
    findings: list[SecurityFinding] = []

    for sr in results:
        if sr.infected:
            rel = "/" + os.path.relpath(sr.file_path, extracted_root)
            findings.append(SecurityFinding(
                title=f"Malware detected: {sr.signature}",
                severity="critical",
                description=(
                    f"ClamAV detected malware signature '{sr.signature}' "
                    f"in file {rel}. This file should be quarantined and "
                    f"analyzed further."
                ),
                evidence=f"ClamAV signature: {sr.signature}",
                file_path=rel,
                cwe_ids=["CWE-506"],
            ))

    logger.info("ClamAV scan: %d findings from %d files", len(findings), len(results))
    return findings


async def run_virustotal_scan(extracted_root: str) -> list[SecurityFinding]:
    """Hash-check firmware binaries against VirusTotal (async, optional).

    Returns findings for detected files. Returns empty list if
    VT API key is not configured.
    """
    import asyncio
    from app.config import get_settings
    from app.services import virustotal_service

    settings = get_settings()
    if not settings.virustotal_api_key:
        logger.info("VT API key not configured — skipping VirusTotal scan")
        return []

    loop = asyncio.get_running_loop()
    hashes = await loop.run_in_executor(
        None, virustotal_service.collect_binary_hashes,
        extracted_root, 50,
    )
    if not hashes:
        return []

    vt_results = await virustotal_service.batch_check_hashes(hashes)
    findings: list[SecurityFinding] = []

    for vr in vt_results:
        if vr.found and vr.detection_count > 0:
            if vr.detection_count > 10:
                severity = "critical"
            elif vr.detection_count > 5:
                severity = "high"
            elif vr.detection_count > 1:
                severity = "medium"
            else:
                severity = "low"

            top_detections = ", ".join(vr.detections[:5])
            findings.append(SecurityFinding(
                title=f"VirusTotal detection: {vr.file_path} ({vr.detection_count}/{vr.total_engines})",
                severity=severity,
                description=(
                    f"VirusTotal reports {vr.detection_count}/{vr.total_engines} "
                    f"engines flagging this binary. Top detections: {top_detections}"
                ),
                evidence=f"SHA-256: {vr.sha256}\nPermalink: {vr.permalink}",
                file_path=vr.file_path,
                cwe_ids=["CWE-506"],
            ))

    logger.info("VirusTotal scan: %d findings from %d hashes", len(findings), len(hashes))
    return findings


async def run_abusech_scan(extracted_root: str) -> list[SecurityFinding]:
    """Check firmware hashes against abuse.ch services (async, optional).

    Returns findings for known malware (MalwareBazaar), IOC matches
    (ThreatFox), and community YARA matches (YARAify).
    """
    import asyncio
    from app.services import abusech_service, virustotal_service

    loop = asyncio.get_running_loop()
    hashes = await loop.run_in_executor(
        None, virustotal_service.collect_binary_hashes,
        extracted_root, 30,
    )
    if not hashes:
        return []

    summary = await abusech_service.enrich_iocs(hashes=hashes, max_hashes=30)
    findings: list[SecurityFinding] = []

    for mb in summary.get("malwarebazaar", []):
        findings.append(SecurityFinding(
            title=f"MalwareBazaar: known malware — {mb.signature or 'unknown'}",
            severity="critical",
            description=(
                f"MalwareBazaar identifies this binary as a known malware sample. "
                f"Signature: {mb.signature or 'N/A'}. "
                f"Tags: {', '.join(mb.tags[:5]) if mb.tags else 'none'}. "
                f"First seen: {mb.first_seen or 'unknown'}."
            ),
            evidence=f"SHA-256: {mb.sha256}",
            file_path=mb.file_path,
            cwe_ids=["CWE-506"],
        ))

    for tf in summary.get("threatfox", []):
        findings.append(SecurityFinding(
            title=f"ThreatFox IOC: {tf.malware} ({tf.threat_type})",
            severity="high" if tf.confidence_level >= 75 else "medium",
            description=(
                f"ThreatFox links this IOC to {tf.malware} ({tf.threat_type}). "
                f"Confidence: {tf.confidence_level}%."
            ),
            evidence=f"IOC: {tf.ioc}\nType: {tf.ioc_type}",
            cwe_ids=["CWE-506"],
        ))

    for yf in summary.get("yaraify", []):
        rules = ", ".join(yf.rule_matches[:5])
        findings.append(SecurityFinding(
            title=f"YARAify: community YARA match — {rules}",
            severity="medium",
            description=(
                f"YARAify reports {len(yf.rule_matches)} community YARA rule "
                f"matches for this binary: {rules}."
            ),
            evidence=f"SHA-256: {yf.sha256}",
            file_path=yf.file_path,
            cwe_ids=["CWE-506"],
        ))

    logger.info("abuse.ch scan: %d findings from %d hashes", len(findings), len(hashes))
    return findings


async def run_known_good_scan(extracted_root: str) -> list[SecurityFinding]:
    """Identify known-good files via CIRCL hashlookup (informational).

    Returns informational findings for files identified as known-good.
    These are useful for reducing false positives in other scans.
    """
    import asyncio
    from app.services import hashlookup_service, virustotal_service

    loop = asyncio.get_running_loop()
    hashes = await loop.run_in_executor(
        None, virustotal_service.collect_binary_hashes,
        extracted_root, 100,
    )
    if not hashes:
        return []

    results = await hashlookup_service.batch_check_known_good(hashes)
    findings: list[SecurityFinding] = []

    known = [r for r in results if r.known]
    if known:
        # Single summary finding rather than one per file
        file_list = ", ".join(r.file_path for r in known[:20])
        findings.append(SecurityFinding(
            title=f"CIRCL Hashlookup: {len(known)}/{len(results)} binaries are known-good",
            severity="info",
            description=(
                f"{len(known)} of {len(results)} checked binaries are recognized in "
                f"the NSRL known-good database. These can be deprioritized during "
                f"manual analysis. Files: {file_list}"
            ),
            evidence=f"Checked {len(results)} binaries against CIRCL hashlookup.circl.lu",
        ))

    logger.info("CIRCL hashlookup: %d known-good from %d checked", len(known), len(results))
    return findings
