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

logger = logging.getLogger(__name__)

_KNOWN_SERVICES = {
    "telnetd": ("high", "Telnet daemon — plaintext credential transmission"),
    "ftpd": ("high", "FTP daemon — plaintext credential transmission"),
    "tftpd": ("high", "TFTP daemon — unauthenticated file access"),
    "miniupnpd": ("medium", "UPnP daemon — may expose internal services"),
    "snmpd": ("medium", "SNMP daemon — check community strings"),
}



def _scan_setuid(root: str, findings: list[SecurityFinding]) -> None:
    """Find setuid-root binaries."""
    count = 0
    for dirpath, _dirs, files in os.walk(root):
        if count >= MAX_FINDINGS_PER_CHECK:
            break
        for name in files:
            abs_path = os.path.join(dirpath, name)
            try:
                st = os.lstat(abs_path)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_mode & stat.S_ISUID and st.st_uid == 0:
                rel = _rel(abs_path, root)
                findings.append(SecurityFinding(
                    title=f"Setuid-root binary: {name}",
                    severity="medium",
                    description=f"Binary {rel} is setuid-root (mode {oct(st.st_mode)[-4:]}). "
                                "Setuid-root binaries are common privilege escalation targets.",
                    file_path=rel,
                    cwe_ids=["CWE-250"],
                ))
                count += 1


def _scan_init_services(root: str, findings: list[SecurityFinding]) -> None:
    """Check init scripts for insecure services started at boot."""
    init_dirs = [
        os.path.join(root, "etc", "init.d"),
        os.path.join(root, "etc", "rc.d"),
    ]
    inittab = os.path.join(root, "etc", "inittab")

    scripts_to_scan: list[str] = []
    for d in init_dirs:
        if os.path.isdir(d):
            try:
                scripts_to_scan.extend(
                    os.path.join(d, f) for f in os.listdir(d)
                    if os.path.isfile(os.path.join(d, f))
                )
            except OSError:
                continue
    if os.path.isfile(inittab):
        scripts_to_scan.append(inittab)

    for script_path in scripts_to_scan:
        try:
            with open(script_path, "r", errors="replace") as f:
                content = f.read(64_000)
        except OSError:
            continue
        rel = _rel(script_path, root)
        for service, (severity, desc) in _KNOWN_SERVICES.items():
            if re.search(rf"\b{re.escape(service)}\b", content):
                findings.append(SecurityFinding(
                    title=f"Insecure service at boot: {service}",
                    severity=severity,
                    description=f"{desc}. Started from {rel}.",
                    file_path=rel,
                    cwe_ids=["CWE-319"] if "plaintext" in desc.lower() else None,
                ))


def _scan_world_writable(root: str, findings: list[SecurityFinding]) -> None:
    """Find world-writable files in sensitive directories."""
    sensitive_dirs = ["etc", "bin", "sbin", "usr/bin", "usr/sbin", "lib"]
    count = 0
    for d in sensitive_dirs:
        dir_path = os.path.join(root, d)
        if not os.path.isdir(dir_path):
            continue
        for dirpath, _dirs, files in os.walk(dir_path):
            if count >= MAX_FINDINGS_PER_CHECK:
                break
            for name in files:
                abs_path = os.path.join(dirpath, name)
                try:
                    st = os.lstat(abs_path)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if st.st_mode & stat.S_IWOTH:
                    rel = _rel(abs_path, root)
                    findings.append(SecurityFinding(
                        title=f"World-writable file: {name}",
                        severity="medium",
                        description=f"{rel} is world-writable (mode {oct(st.st_mode)[-4:]}). "
                                    "Any process can modify this file.",
                        file_path=rel,
                        cwe_ids=["CWE-732"],
                    ))
                    count += 1



# ---------------------------------------------------------------------------
# Network dependency scanning
# ---------------------------------------------------------------------------

_NET_DEP_CIFS_CRED_RE = re.compile(r"\bpassword=\S+", re.IGNORECASE)
_NET_DEP_NO_ROOT_SQUASH_RE = re.compile(r"no_root_squash", re.IGNORECASE)
_NET_DEP_CLOUD_RE = re.compile(
    r"(?:\bs3://[\w./-]+|[\w.-]+\.s3\.amazonaws\.com|"
    r"[\w.-]+\.blob\.core\.windows\.net|"
    r"\bgs://[\w./-]+|storage\.googleapis\.com)",
    re.IGNORECASE,
)
_NET_DEP_PLAINTEXT_RE = re.compile(
    r"(?:\bftps?://\S+|\btftp://\S+|\bmqtts?://\S+|"
    r"\b(?:ftpget|ftpput|wget|curl)\b.*\bftp://)",
    re.IGNORECASE,
)
_NET_DEP_DB_CRED_RE = re.compile(
    r"\b(?:mongodb|mysql|postgres(?:ql)?|redis|amqps?|influxdb)://[^/]*:[^@/]+@",
    re.IGNORECASE,
)


def _scan_network_dependencies(root: str, findings: list[SecurityFinding]) -> None:
    """Scan for network mounts, cloud endpoints, and plaintext protocols."""
    count = 0

    # 1. Scan /etc/fstab for CIFS credential exposure
    fstab_path = os.path.join(root, "etc", "fstab")
    if os.path.isfile(fstab_path):
        try:
            with open(fstab_path, "r", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    if count >= MAX_FINDINGS_PER_CHECK:
                        break
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if _NET_DEP_CIFS_CRED_RE.search(stripped) and "cifs" in stripped.lower():
                        findings.append(SecurityFinding(
                            title="CIFS mount with inline credentials in /etc/fstab",
                            severity="critical",
                            description="CIFS mount options contain plaintext password. "
                                        "Credentials should use a credentials file instead.",
                            evidence=stripped[:200],
                            file_path="/etc/fstab",
                            line_number=line_num,
                            cwe_ids=["CWE-798"],
                        ))
                        count += 1
        except OSError:
            pass

    # 2. Scan /etc/exports for no_root_squash
    exports_path = os.path.join(root, "etc", "exports")
    if os.path.isfile(exports_path):
        try:
            with open(exports_path, "r", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    if count >= MAX_FINDINGS_PER_CHECK:
                        break
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if _NET_DEP_NO_ROOT_SQUASH_RE.search(stripped):
                        findings.append(SecurityFinding(
                            title="NFS export with no_root_squash",
                            severity="high",
                            description="NFS export uses no_root_squash, allowing remote root "
                                        "to have root privileges on the exported filesystem.",
                            evidence=stripped[:200],
                            file_path="/etc/exports",
                            line_number=line_num,
                            cwe_ids=["CWE-269"],
                        ))
                        count += 1
        except OSError:
            pass

    # 3. Broad sweep: cloud storage, plaintext protocols, DB credentials
    for dirpath, _dirs, files in os.walk(root):
        if count >= MAX_FINDINGS_PER_CHECK:
            break
        for name in files:
            if count >= MAX_FINDINGS_PER_CHECK:
                break
            abs_path = os.path.join(dirpath, name)
            if not os.path.isfile(abs_path):
                continue
            try:
                if os.path.getsize(abs_path) > 1_000_000:
                    continue
            except OSError:
                continue
            if not _is_text_file(abs_path):
                continue
            rel_path = _rel(abs_path, root)
            try:
                with open(abs_path, "r", errors="replace") as f:
                    for line_num, line in enumerate(f, 1):
                        if count >= MAX_FINDINGS_PER_CHECK:
                            break
                        stripped = line.strip()
                        if not stripped or stripped.startswith("#"):
                            continue

                        # Cloud storage endpoints
                        m = _NET_DEP_CLOUD_RE.search(stripped)
                        if m:
                            findings.append(SecurityFinding(
                                title=f"Cloud storage endpoint in {rel_path}",
                                severity="high",
                                description=f"Firmware references cloud storage: {m.group(0)[:80]}",
                                evidence=stripped[:200],
                                file_path=rel_path,
                                line_number=line_num,
                                cwe_ids=["CWE-200"],
                            ))
                            count += 1
                            continue

                        # DB connection strings with embedded credentials
                        m = _NET_DEP_DB_CRED_RE.search(stripped)
                        if m:
                            findings.append(SecurityFinding(
                                title=f"Database connection with credentials in {rel_path}",
                                severity="critical",
                                description="Database connection string contains embedded credentials.",
                                evidence=stripped[:200],
                                file_path=rel_path,
                                line_number=line_num,
                                cwe_ids=["CWE-798"],
                            ))
                            count += 1
                            continue

                        # Plaintext FTP/TFTP/MQTT URLs
                        m = _NET_DEP_PLAINTEXT_RE.search(stripped)
                        if m:
                            match_text = m.group(0).lower()
                            if "tftp" in match_text:
                                title = f"TFTP URL in {rel_path}"
                            elif "ftp" in match_text:
                                title = f"FTP URL in {rel_path}"
                            else:
                                title = f"MQTT broker reference in {rel_path}"
                            findings.append(SecurityFinding(
                                title=title,
                                severity="high",
                                description="Plaintext protocol used for file transfer or messaging. "
                                            "Data transmitted without encryption.",
                                evidence=stripped[:200],
                                file_path=rel_path,
                                line_number=line_num,
                                cwe_ids=["CWE-319"],
                            ))
                            count += 1
                            continue
            except (OSError, PermissionError):
                continue


# ---------------------------------------------------------------------------
# Optional external scanner wrappers (TruffleHog, Nosey Parker)
# ---------------------------------------------------------------------------

def _run_external_scanner(
    cmd: list[str],
    scanner_name: str,
    root: str,
    findings: list[SecurityFinding],
) -> None:
    """Run an external secrets scanner and merge JSON results into findings."""
    import json
    import subprocess
    from shutil import which

    binary = cmd[0]
    if not which(binary):
        logger.debug("%s not installed — skipping", scanner_name)
        return

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=300,
            text=True,
        )
    except subprocess.TimeoutExpired:
        logger.warning("%s timed out after 300s on %s", scanner_name, root)
        return
    except OSError as e:
        logger.warning("%s execution failed: %s", scanner_name, e)
        return

    if not proc.stdout.strip():
        return

    # Parse JSON output (each tool has different format)
    for line in proc.stdout.strip().splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        finding = _parse_external_finding(obj, scanner_name, root)
        if finding:
            findings.append(finding)
            if len(findings) >= MAX_FINDINGS_PER_CHECK:
                break


def _parse_external_finding(
    obj: dict, scanner_name: str, root: str
) -> SecurityFinding | None:
    """Parse a single JSON result from TruffleHog or Nosey Parker."""
    if scanner_name == "trufflehog":
        detector = obj.get("DetectorName", obj.get("detectorName", "unknown"))
        verified = obj.get("Verified", obj.get("verified", False))
        raw = obj.get("Raw", obj.get("raw", ""))
        source_meta = obj.get("SourceMetadata", obj.get("sourceMetadata", {}))
        file_path = None
        line_number = None
        if source_meta:
            data = source_meta.get("Data", source_meta.get("data", {}))
            fs = data.get("Filesystem", data.get("filesystem", {}))
            file_path = fs.get("file", None)
            line_number = fs.get("line", None)
            if file_path and root:
                file_path = "/" + os.path.relpath(file_path, root) if file_path.startswith(root) else file_path
        severity = "critical" if verified else "high"
        return SecurityFinding(
            title=f"[TruffleHog] {detector}" + (" (verified)" if verified else ""),
            severity=severity,
            description=f"Detected by TruffleHog detector: {detector}. "
                        + ("Credential verified as active." if verified else "Unverified match."),
            evidence=raw[:200] if raw else None,
            file_path=file_path,
            line_number=int(line_number) if line_number else None,
            cwe_ids=["CWE-798"],
        )
    elif scanner_name == "noseyparker":
        rule = obj.get("rule_name", "unknown")
        matches = obj.get("matches", [])
        if not matches:
            return None
        match = matches[0]
        snippet = match.get("snippet", {})
        matching = snippet.get("matching", "")
        provenance = match.get("provenance", [{}])
        file_path = provenance[0].get("path") if provenance else None
        if file_path and root:
            file_path = "/" + os.path.relpath(file_path, root) if file_path.startswith(root) else file_path
        location = match.get("location", {}).get("source_span", {})
        line_num = location.get("start", {}).get("line")
        return SecurityFinding(
            title=f"[NoseyParker] {rule}",
            severity="high",
            description=f"Detected by Nosey Parker rule: {rule}",
            evidence=matching[:200] if matching else None,
            file_path=file_path,
            line_number=line_num,
            cwe_ids=["CWE-798"],
        )
    return None


def _scan_trufflehog(root: str, findings: list[SecurityFinding]) -> None:
    """Run TruffleHog filesystem scan if installed."""
    _run_external_scanner(
        ["trufflehog", "filesystem", root, "--json", "--no-update",
         "--force-skip-binaries", "--force-skip-archives"],
        "trufflehog", root, findings,
    )


def _scan_noseyparker(root: str, findings: list[SecurityFinding]) -> None:
    """Run Nosey Parker filesystem scan if installed.

    NP requires two steps: scan (writes to datastore) then report (reads findings).
    """
    import json
    import subprocess
    import tempfile
    from shutil import which, rmtree

    if not which("noseyparker"):
        logger.debug("noseyparker not installed — skipping")
        return

    datastore = tempfile.mkdtemp(prefix="np-")
    try:
        # Step 1: Scan into datastore
        try:
            subprocess.run(
                ["noseyparker", "scan", "--datastore", datastore, root],
                capture_output=True, timeout=300, text=True,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.warning("noseyparker scan failed: %s", e)
            return

        # Step 2: Report as JSONL
        try:
            proc = subprocess.run(
                ["noseyparker", "report", "--datastore", datastore,
                 "--format", "jsonl"],
                capture_output=True, timeout=60, text=True,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.warning("noseyparker report failed: %s", e)
            return

        if not proc.stdout.strip():
            return

        for line in proc.stdout.strip().splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            finding = _parse_external_finding(obj, "noseyparker", root)
            if finding:
                findings.append(finding)
                if len(findings) >= MAX_FINDINGS_PER_CHECK:
                    break
    finally:
        rmtree(datastore, ignore_errors=True)


# ---------------------------------------------------------------------------
# ShellCheck scanner (optional — runs if shellcheck binary is installed)
# ---------------------------------------------------------------------------

def _scan_shellcheck(root: str, findings: list[SecurityFinding]) -> None:
    """Run ShellCheck on shell scripts found in the firmware."""
    import json
    import subprocess
    from shutil import which

    if not which("shellcheck"):
        logger.debug("shellcheck not installed — skipping")
        return

    # Discover shell scripts
    shell_extensions = {".sh", ".ash"}
    shebang_patterns = {b"/bin/sh", b"/bin/bash", b"/bin/ash", b"/usr/bin/env sh", b"/usr/bin/env bash"}
    script_dirs = {"etc/init.d", "www/cgi-bin"}

    scripts: list[str] = []
    for dirpath, _dirs, files in os.walk(root):
        if len(scripts) >= 100:
            break
        rel_dir = os.path.relpath(dirpath, root)
        in_script_dir = any(
            rel_dir == sd or rel_dir.startswith(sd + os.sep) for sd in script_dirs
        )
        for name in files:
            if len(scripts) >= 100:
                break
            abs_path = os.path.join(dirpath, name)
            if not os.path.isfile(abs_path):
                continue
            _, ext = os.path.splitext(name.lower())
            if ext in shell_extensions or in_script_dir:
                scripts.append(abs_path)
                continue
            try:
                with open(abs_path, "rb") as f:
                    header = f.read(2)
                    if header == b"#!":
                        first_line = (header + f.readline(256)).strip()
                        if any(pat in first_line for pat in shebang_patterns):
                            scripts.append(abs_path)
            except OSError:
                continue

    if not scripts:
        return

    # Security-relevant SC codes mapped to CWEs
    sc_cwe_map = {
        2086: ("CWE-78", "Unquoted variable — command injection"),
        2091: ("CWE-78", "Command substitution used as condition"),
        2046: ("CWE-78", "Unquoted $(…) — word splitting"),
    }

    count = 0
    for script_path in scripts:
        if count >= MAX_FINDINGS_PER_CHECK:
            break
        try:
            proc = subprocess.run(
                ["shellcheck", "-f", "json1", "-S", "warning", "-s", "sh", script_path],
                capture_output=True, timeout=30, text=True,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue

        if not proc.stdout:
            continue

        try:
            data = json.loads(proc.stdout)
            comments = data.get("comments", [])
        except json.JSONDecodeError:
            continue

        for c in comments:
            sc_code = c.get("code", 0)
            if sc_code not in sc_cwe_map:
                continue
            if count >= MAX_FINDINGS_PER_CHECK:
                break
            cwe_id, desc = sc_cwe_map[sc_code]
            level = c.get("level", "warning")
            severity_map = {"error": "high", "warning": "medium", "info": "low", "style": "info"}
            rel_path = _rel(script_path, root)
            findings.append(SecurityFinding(
                title=f"SC{sc_code}: {desc} in {os.path.basename(script_path)}",
                severity=severity_map.get(level, "medium"),
                description=f"ShellCheck SC{sc_code}: {c.get('message', '')}",
                evidence=None,
                file_path=rel_path,
                line_number=c.get("line"),
                cwe_ids=[cwe_id],
            ))
            count += 1


# ---------------------------------------------------------------------------
# Bandit scanner (optional — runs if bandit binary is installed)
# ---------------------------------------------------------------------------

def _scan_bandit(root: str, findings: list[SecurityFinding]) -> None:
    """Run Bandit on Python scripts found in the firmware."""
    import json
    import subprocess
    from shutil import which

    bandit_bin = which("bandit") or which("bandit", path="/app/.venv/bin")
    if not bandit_bin:
        logger.debug("bandit not installed — skipping")
        return

    # Discover Python scripts
    py_extensions = {".py", ".pyw"}
    shebang_patterns = {b"/usr/bin/python", b"/usr/bin/env python", b"/usr/bin/python3", b"/usr/bin/env python3"}

    scripts: list[str] = []
    for dirpath, _dirs, files in os.walk(root):
        if len(scripts) >= 100:
            break
        for name in files:
            if len(scripts) >= 100:
                break
            abs_path = os.path.join(dirpath, name)
            if not os.path.isfile(abs_path):
                continue
            _, ext = os.path.splitext(name.lower())
            if ext in py_extensions:
                scripts.append(abs_path)
                continue
            try:
                with open(abs_path, "rb") as f:
                    header = f.read(2)
                    if header == b"#!":
                        first_line = (header + f.readline(256)).strip()
                        if any(pat in first_line for pat in shebang_patterns):
                            scripts.append(abs_path)
            except OSError:
                continue

    if not scripts:
        return

    try:
        proc = subprocess.run(
            [bandit_bin, "-f", "json", "-ll", "-ii"] + scripts,
            capture_output=True, timeout=60, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("bandit execution failed: %s", e)
        return

    if not proc.stdout:
        return

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return

    results = data.get("results", [])
    severity_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    count = 0

    for r in results:
        if count >= MAX_FINDINGS_PER_CHECK:
            break
        test_id = r.get("test_id", "?")
        test_name = r.get("test_name", "unknown")
        issue_text = r.get("issue_text", "")
        file_path = r.get("filename", "")
        line_num = r.get("line_number")
        sev = r.get("issue_severity", "MEDIUM")
        issue_cwe = r.get("issue_cwe", {})
        cwe_id = f"CWE-{issue_cwe['id']}" if issue_cwe.get("id") else None

        if file_path.startswith(root):
            file_path = _rel(file_path, root)

        findings.append(SecurityFinding(
            title=f"[Bandit {test_id}] {test_name}: {issue_text[:80]}",
            severity=severity_map.get(sev, "medium"),
            description=f"Bandit {test_id} ({test_name}): {issue_text}",
            file_path=file_path,
            line_number=line_num,
            cwe_ids=[cwe_id] if cwe_id else None,
        ))
        count += 1


# ---------------------------------------------------------------------------
# Update mechanism scanner
# ---------------------------------------------------------------------------

def _scan_update_mechanisms(root: str, findings: list[SecurityFinding]) -> None:
    """Scan for firmware update mechanisms and flag insecure patterns.

    Calls the update_mechanism_service and converts important findings
    to SecurityFinding objects for the audit report.
    """
    from app.services.update_mechanism_service import detect_update_mechanisms

    mechanisms = detect_update_mechanisms(root)
    count = 0

    for mech in mechanisms:
        for f in mech.findings:
            if count >= MAX_FINDINGS_PER_CHECK:
                return
            severity = f.get("severity", "info")
            # Only promote high/medium findings to the audit report
            if severity not in ("high", "medium"):
                continue
            description = f.get("description", "")
            cwe = f.get("cwe")
            evidence = f.get("evidence")

            title_prefix = mech.system.upper()
            if mech.system == "none":
                title_prefix = "Update Mechanism"
            elif mech.system == "custom_ota":
                title_prefix = "Custom OTA"

            findings.append(SecurityFinding(
                title=f"[{title_prefix}] {description[:80]}",
                severity=severity,
                description=description,
                evidence=evidence,
                cwe_ids=[cwe] if cwe else None,
            ))
            count += 1


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
