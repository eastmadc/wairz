"""Automated security scanning that persists findings to the database.

Runs the same checks as the MCP security tools but writes results directly
to the findings table so they're visible in the UI without needing an
active AI conversation.

Designed to run as a sync function in a thread executor (CPU-bound filesystem
scanning), then persist findings via an async DB session.
"""

import logging
import math
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

MAX_FINDINGS_PER_CHECK = 50

# ---------------------------------------------------------------------------
# Credential patterns (mirrored from ai/tools/strings.py)
# ---------------------------------------------------------------------------

from app.utils.credential_patterns import (
    API_KEY_PATTERNS as _API_KEY_PATTERNS,
    CREDENTIAL_PATTERNS as _CREDENTIAL_PATTERNS,
    HASH_TYPES as _HASH_TYPES,
)

_KNOWN_SERVICES = {
    "telnetd": ("high", "Telnet daemon — plaintext credential transmission"),
    "ftpd": ("high", "FTP daemon — plaintext credential transmission"),
    "tftpd": ("high", "TFTP daemon — unauthenticated file access"),
    "miniupnpd": ("medium", "UPnP daemon — may expose internal services"),
    "snmpd": ("medium", "SNMP daemon — check community strings"),
}

# Binary extensions to skip during text scanning
_BINARY_EXTENSIONS = frozenset({
    ".bin", ".img", ".gz", ".xz", ".bz2", ".zst", ".lz4", ".lzma",
    ".zip", ".tar", ".elf", ".so", ".o", ".a", ".ko", ".dtb",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".wav", ".avi", ".mkv",
    ".pyc", ".pyo", ".class", ".wasm",
})


@dataclass
class SecurityFinding:
    """A single security finding ready for DB insertion."""
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    cwe_ids: list[str] | None = None


@dataclass
class ScanResult:
    """Aggregate result of a full security scan."""
    findings: list[SecurityFinding] = field(default_factory=list)
    checks_run: int = 0
    errors: list[str] = field(default_factory=list)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts.values()
    )


def _is_text_file(path: str) -> bool:
    _, ext = os.path.splitext(path.lower())
    if ext in _BINARY_EXTENSIONS:
        return False
    try:
        with open(path, "rb") as f:
            chunk = f.read(512)
            if b"\x00" in chunk:
                return False
    except OSError:
        return False
    return True


def _rel(abs_path: str, root: str) -> str:
    return "/" + os.path.relpath(abs_path, root)


# ---------------------------------------------------------------------------
# Individual scan checks
# ---------------------------------------------------------------------------

def _scan_credentials(root: str, findings: list[SecurityFinding]) -> None:
    """Scan for hardcoded credentials and API keys."""
    count = 0
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
                        # Cloud/service API keys (high value)
                        matched = False
                        for pat, category, severity in _API_KEY_PATTERNS:
                            m = pat.search(line)
                            if m:
                                value = m.group(0)
                                entropy = _shannon_entropy(value)
                                if entropy < 2.0:
                                    continue  # Skip low-entropy matches
                                findings.append(SecurityFinding(
                                    title=f"{category.replace('_', ' ').title()} found in {rel_path}",
                                    severity=severity,
                                    description=f"Detected {category} pattern (entropy: {entropy:.1f})",
                                    evidence=line.strip()[:200],
                                    file_path=rel_path,
                                    line_number=line_num,
                                    cwe_ids=["CWE-798"],
                                ))
                                count += 1
                                matched = True
                                break
                        if matched:
                            continue
                        # Generic credential patterns
                        for pat in _CREDENTIAL_PATTERNS:
                            m = pat.search(line)
                            if m:
                                value = m.group(1)
                                entropy = _shannon_entropy(value)
                                if entropy < 2.5 or len(value) < 4:
                                    continue  # Skip trivial matches
                                findings.append(SecurityFinding(
                                    title=f"Hardcoded credential in {rel_path}",
                                    severity="medium",
                                    description=f"Possible hardcoded credential (entropy: {entropy:.1f})",
                                    evidence=line.strip()[:200],
                                    file_path=rel_path,
                                    line_number=line_num,
                                    cwe_ids=["CWE-798"],
                                ))
                                count += 1
                                break
            except (OSError, PermissionError):
                continue


def _scan_shadow(root: str, findings: list[SecurityFinding]) -> None:
    """Check /etc/shadow for weak or empty passwords."""
    for shadow_rel in ("etc/shadow", "etc_ro/shadow"):
        shadow_path = os.path.join(root, shadow_rel)
        if not os.path.isfile(shadow_path):
            continue
        try:
            with open(shadow_path) as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) < 2:
                        continue
                    user, hash_field = parts[0], parts[1]
                    if not hash_field or hash_field in ("*", "!", "!!", "x"):
                        continue
                    if hash_field == "":
                        findings.append(SecurityFinding(
                            title=f"Empty password for user '{user}'",
                            severity="critical",
                            description=f"User '{user}' has no password set in /{shadow_rel}",
                            file_path=f"/{shadow_rel}",
                            cwe_ids=["CWE-258"],
                        ))
                        continue
                    # Check hash strength
                    for prefix, (algo, strength) in _HASH_TYPES.items():
                        if hash_field.startswith(prefix):
                            if strength == "weak":
                                findings.append(SecurityFinding(
                                    title=f"Weak password hash for user '{user}'",
                                    severity="medium",
                                    description=f"User '{user}' uses {algo} hash in /{shadow_rel} — consider stronger algorithm",
                                    file_path=f"/{shadow_rel}",
                                    cwe_ids=["CWE-916"],
                                ))
                            break
                    else:
                        # DES or unknown — likely weak
                        if not hash_field.startswith("$"):
                            findings.append(SecurityFinding(
                                title=f"Legacy DES password hash for user '{user}'",
                                severity="high",
                                description=f"User '{user}' uses DES crypt in /{shadow_rel} — trivially crackable",
                                file_path=f"/{shadow_rel}",
                                cwe_ids=["CWE-916"],
                            ))
        except OSError:
            continue


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


def _scan_crypto_material(root: str, findings: list[SecurityFinding]) -> None:
    """Find private keys and certificates."""
    count = 0
    crypto_extensions = {".pem", ".key", ".p12", ".pfx"}
    # Skip system CA certificate bundles — these are standard and not findings
    ca_dirs = {"ssl/certs", "ssl/ca-certificates", "pki/tls/certs", "ca-certificates"}
    for dirpath, _dirs, files in os.walk(root):
        if count >= MAX_FINDINGS_PER_CHECK:
            break
        # Skip system CA bundle directories
        rel_dir = os.path.relpath(dirpath, root)
        if any(ca in rel_dir for ca in ca_dirs):
            continue
        for name in files:
            _, ext = os.path.splitext(name.lower())
            if ext not in crypto_extensions:
                continue
            abs_path = os.path.join(dirpath, name)
            if not os.path.isfile(abs_path):
                continue
            try:
                with open(abs_path, "rb") as f:
                    header = f.read(256)
            except OSError:
                continue
            if b"PRIVATE KEY" in header:
                rel = _rel(abs_path, root)
                findings.append(SecurityFinding(
                    title=f"Private key found: {name}",
                    severity="high",
                    description=f"Private key file at {rel}. Embedded private keys can be extracted and used to impersonate the device.",
                    file_path=rel,
                    cwe_ids=["CWE-321"],
                ))
                count += 1
            elif b"CERTIFICATE" in header:
                rel = _rel(abs_path, root)
                findings.append(SecurityFinding(
                    title=f"Device certificate: {name}",
                    severity="info",
                    description=f"Non-CA certificate at {rel}. May contain device identity or service credentials.",
                    file_path=rel,
                ))
                count += 1


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
# Main scan orchestrator
# ---------------------------------------------------------------------------

def run_security_audit(extracted_root: str) -> ScanResult:
    """Run all security checks against an extracted firmware filesystem.

    This is a sync function — call from a thread executor for async contexts.

    Built-in checks always run. External scanners (TruffleHog, Nosey Parker)
    run only if the binary is installed — they are optional enhancements.
    """
    result = ScanResult()

    checks = [
        ("credentials", _scan_credentials),
        ("shadow", _scan_shadow),
        ("setuid", _scan_setuid),
        ("init_services", _scan_init_services),
        ("world_writable", _scan_world_writable),
        ("crypto_material", _scan_crypto_material),
        # Optional external scanners — silently skip if not installed
        ("trufflehog", _scan_trufflehog),
        ("noseyparker", _scan_noseyparker),
    ]

    for name, func in checks:
        try:
            before = len(result.findings)
            func(extracted_root, result.findings)
            result.checks_run += 1
            after = len(result.findings)
            if after > before:
                logger.info("Security check '%s': %d finding(s)", name, after - before)
        except Exception as e:
            result.errors.append(f"{name}: {e}")
            logger.warning("Security check '%s' failed: %s", name, e, exc_info=True)

    return result
