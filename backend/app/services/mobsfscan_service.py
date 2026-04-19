"""mobsfscan integration service — orchestrates the full SAST pipeline.

Provides two layers:

**Low-level runner** (``run_mobsfscan``, ``_parse_mobsfscan_output``):
    Executes the ``mobsfscan`` CLI tool (which wraps semgrep + custom rules)
    against a directory of decompiled Java/Kotlin source code.

**Orchestration layer** (``MobsfScanPipeline``):
    End-to-end pipeline that accepts a JADX output path (or APK path),
    invokes the runner, parses results, caches them in AnalysisCache,
    normalizes findings with firmware-context severity adjustments,
    persists them to the findings table, and returns structured output.

The runner is designed to work with sources materialized by
:mod:`app.services.jadx_service` (``write_sources_to_disk``).

The :func:`normalize_mobsfscan_findings` function converts raw
:class:`MobsfScanFinding` objects into the project's unified
:class:`~app.schemas.finding.FindingCreate` schema, suitable for
persistence via :class:`~app.services.finding_service.FindingService`
or direct ORM insertion with ``flush()``.

All methods are async.  The actual CLI invocation uses
``asyncio.create_subprocess_exec()`` with configurable timeout.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from shutil import which
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.utils.firmware_context import FirmwareContext

logger = logging.getLogger(__name__)

# Default timeout for mobsfscan execution (seconds).
# Full-app scans typically complete in 30-90s; cap at 180s.
_DEFAULT_TIMEOUT: int = 180


# ---------------------------------------------------------------------------
# Rule suppressions & severity overrides
# ---------------------------------------------------------------------------
# These configurations reduce false-positive noise and align mobsfscan
# severity with APK-specific context.  They are applied during the
# normalization step so that cached raw results remain un-filtered (a
# config change triggers a different normalized output without rescan).

#: Rules that are **always suppressed** (high false-positive rate or
#: redundant with Wairz Phase 1 manifest checks / Phase 2a bytecode).
#: Keys are exact mobsfscan ``rule_id`` strings.
SUPPRESSED_RULES: frozenset[str] = frozenset({
    # --- Manifest-level rules already covered by Phase 1 ---
    # Phase 1 androguard_service.py checks allowBackup, debuggable,
    # exported components, NSC cleartext, etc. with firmware-context
    # awareness that mobsfscan lacks.
    "android_manifest_backup",
    "android_manifest_debug",
    "android_exported_component",
    "android_exported_content_provider",
    "android_manifest_cleartext",
    "android_ns_cleartext",
    "android_ns_temp_cert",
    "android_permission_dangerous",

    # --- High false-positive / low-signal rules ---
    # Logging detection: matches all Log.* calls; nearly every app uses
    # android.util.Log — true positives require runtime context (e.g.
    # logging of PII) that static analysis cannot determine.
    "android_logging",
    "android_log_info",

    # IP address regex: fires on localhost (127.0.0.1), link-local,
    # broadcast, and documentation IPs embedded in comments/strings.
    "android_ip_disclosure",
    "android_ip_private",

    # Generic temp file detection: flags File.createTempFile() which is
    # the *correct* way to create temp files on Android (vs. hardcoded
    # paths).  The real risk is not cleaning up — which this rule
    # doesn't check.
    "android_temp_file",

    # URL-in-string detections that match every https:// literal
    # including Google Play, Firebase, and documentation URLs.
    "android_hardcoded_url",

    # Clipboard usage: flags ClipboardManager access.  Nearly all apps
    # interact with the clipboard; the risk is context-dependent.
    "android_clipboard",

    # ADB backup flag: duplicate of android_manifest_backup already
    # handled by Phase 1's allowBackup check (with firmware context).
    "android_adb_backup",
})

#: Rules with **overridden severity** (mobsfscan default → Wairz
#: override).  This aligns scanner output with APK-specific risk:
#: e.g. mobsfscan rates some crypto issues as WARNING (medium) but
#: they are genuinely high-severity for mobile apps handling user data.
#:
#: Format: ``rule_id → target_severity`` where severity is one of
#: "critical", "high", "medium", "low", "info".
SEVERITY_OVERRIDES: dict[str, str] = {
    # --- Crypto: promote to high ---
    # Weak/broken algorithms (DES, RC4, MD5 for integrity) are high
    # risk in mobile apps that handle PII, auth tokens, or payment.
    "android_insecure_random": "high",       # java.util.Random instead of SecureRandom
    "android_weak_crypto_des": "high",       # DES/DESede usage
    "android_weak_crypto_rc4": "high",       # RC4 stream cipher
    "android_ecb_cipher": "high",            # ECB mode (pattern-preserving)
    "android_rsa_no_oaep": "high",           # RSA without OAEP padding
    "android_weak_hash": "high",             # MD5/SHA-1 for integrity

    # --- Hardcoded secrets: promote to high/critical ---
    # Embedded API keys and secrets are always high; private keys are critical.
    "android_hardcoded_secret": "high",
    "android_hardcoded_api_key": "high",
    "android_hardcoded_firebase": "high",
    "android_private_key_hardcoded": "critical",

    # --- SQL injection: promote to high ---
    "android_sql_injection_rawquery": "high",
    "android_sql_injection_content_provider": "high",

    # --- TLS/SSL: keep or promote to high ---
    "android_ssl_pinning_bypass": "high",    # disabled cert pinning
    "android_trust_all_certs": "high",       # TrustManager accepting all
    "android_ssl_hostname_bypass": "high",   # hostname verifier bypass
    "android_custom_trust_manager": "medium",

    # --- WebView: align with risk ---
    "android_webview_js_enabled": "medium",  # JS in WebView (context-dependent)
    "android_webview_file_access": "high",   # file:// access in WebView
    "android_webview_debug": "medium",       # WebView remote debugging

    # --- Sensitive data exposure: demote noise ---
    "android_shared_prefs_world_readable": "high",   # world-readable prefs
    "android_external_storage": "medium",    # writing to SD card (common)
    "android_broadcast_sensitive": "low",    # sending sensitive broadcast

    # --- Runtime: adjust for APK context ---
    "android_root_detection_bypass": "info", # root detection is optional
    "android_emulator_detection": "info",    # emulator detection is optional
    "android_dynamic_dex_loading": "medium", # dynamic loading is suspicious
}

#: File-path patterns that should be excluded from scanning.  Matches
#: in *decompiled* source paths often originate from bundled libraries
#: or generated code where findings are not actionable by the APK author.
SUPPRESSED_PATH_PATTERNS: tuple[str, ...] = (
    # Google/Android support/jetpack libraries — enormous volume, not
    # user code.  Findings here are against the platform, not the app.
    "com/google/android/",
    "androidx/",
    "android/support/",

    # Common third-party SDKs that generate high-volume findings.
    "com/facebook/",
    "com/crashlytics/",
    "com/google/firebase/",
    "com/squareup/okhttp",
    "io/reactivex/",
    "kotlin/",
    "kotlinx/",

    # Auto-generated code (R.java, BuildConfig, databinding).
    "/R$",      # R$style.java, R$layout.java, etc.
    "/R.java",
    "/BuildConfig.java",
    "/databinding/",
)


def _is_suppressed_path(file_path: str) -> bool:
    """Return True if *file_path* matches a suppressed path pattern.

    Uses substring matching against :data:`SUPPRESSED_PATH_PATTERNS`.
    Forward-slash normalisation handles both Unix and Windows-style
    paths from mobsfscan output.
    """
    normalised = file_path.replace("\\", "/")
    return any(pat in normalised for pat in SUPPRESSED_PATH_PATTERNS)


def _apply_severity_override(rule_id: str, base_severity: str) -> str:
    """Return the overridden severity for *rule_id*, or *base_severity*
    if no override is configured.
    """
    return SEVERITY_OVERRIDES.get(rule_id, base_severity)


@dataclass(frozen=True, slots=True)
class MobsfScanFinding:
    """A single finding produced by mobsfscan."""

    rule_id: str
    title: str
    description: str
    severity: str  # "ERROR" | "WARNING" | "INFO" from mobsfscan → mapped below
    section: str  # e.g. "code_analysis", "manifest_analysis"
    file_path: str  # relative path within the scanned source tree
    line_number: int  # 1-based; 0 if unavailable
    match_string: str  # the matched code snippet
    cwe: str  # CWE ID string, e.g. "CWE-312"
    owasp_mobile: str  # e.g. "M9: Reverse Engineering"
    masvs: str  # OWASP MASVS reference
    metadata: dict  # raw rule metadata for downstream consumers

    @property
    def normalized_severity(self) -> str:
        """Map mobsfscan severity to Wairz finding severity."""
        mapping = {
            "ERROR": "high",
            "WARNING": "medium",
            "INFO": "info",
        }
        return mapping.get(self.severity.upper(), "info")


@dataclass(slots=True)
class MobsfScanResult:
    """Aggregated result of a mobsfscan run."""

    success: bool
    findings: list[MobsfScanFinding] = field(default_factory=list)
    raw_json: dict | None = None
    error: str | None = None
    scan_duration_ms: int = 0
    files_scanned: int = 0
    suppressed_rule_count: int = 0
    suppressed_path_count: int = 0

    @property
    def summary(self) -> dict:
        """Return a compact summary suitable for MCP tool output."""
        severity_counts: dict[str, int] = {}
        for f in self.findings:
            sev = f.normalized_severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        return {
            "success": self.success,
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "files_scanned": self.files_scanned,
            "scan_duration_ms": self.scan_duration_ms,
            "error": self.error,
            "suppressed_rule_count": self.suppressed_rule_count,
            "suppressed_path_count": self.suppressed_path_count,
        }


def _find_mobsfscan() -> str | None:
    """Locate the ``mobsfscan`` binary, checking venv bin path too.

    In Docker with uv/venv, pip-installed CLI tools land in
    ``/app/.venv/bin/`` which may not be on the system PATH.
    """
    return which("mobsfscan") or which("mobsfscan", path="/app/.venv/bin")


def mobsfscan_available() -> bool:
    """Check whether the ``mobsfscan`` binary is available."""
    return _find_mobsfscan() is not None


async def run_mobsfscan(
    source_dir: str,
    *,
    timeout: int | None = None,
) -> MobsfScanResult:
    """Execute ``mobsfscan`` against *source_dir* and return parsed results.

    Parameters
    ----------
    source_dir:
        Absolute path to the directory containing decompiled Java/Kotlin
        sources (typically produced by JADX).
    timeout:
        Maximum seconds to wait for the scan to complete.  Defaults to
        ``_DEFAULT_TIMEOUT`` (180 s).

    Returns
    -------
    MobsfScanResult
        Parsed scan results with individual findings and metadata.

    Raises
    ------
    FileNotFoundError
        If *source_dir* does not exist or is not a directory.
    RuntimeError
        If the ``mobsfscan`` binary is not found on PATH.
    """
    effective_timeout = timeout or _DEFAULT_TIMEOUT

    # ------- pre-flight checks -------
    if not os.path.isdir(source_dir):
        raise FileNotFoundError(
            f"Source directory does not exist or is not a directory: {source_dir}"
        )

    mobsfscan_bin = _find_mobsfscan()
    if mobsfscan_bin is None:
        raise RuntimeError(
            "mobsfscan binary not found on PATH. "
            "Install with: pip install mobsfscan"
        )

    # ------- build command -------
    cmd: list[str] = [
        mobsfscan_bin,
        "--json",          # JSON output
        "--no-fail",       # don't exit non-zero when findings are present
        source_dir,
    ]

    logger.info(
        "Running mobsfscan on %s (timeout=%ds)", source_dir, effective_timeout,
    )

    t0 = time.monotonic()

    # Ensure venv bin is on PATH so mobsfscan can find semgrep
    # (mobsfscan spawns semgrep as a subprocess internally)
    env = os.environ.copy()
    venv_bin = "/app/.venv/bin"
    if venv_bin not in env.get("PATH", ""):
        env["PATH"] = f"{venv_bin}:{env.get('PATH', '')}"

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(), timeout=effective_timeout,
        )
    except asyncio.TimeoutError:
        # Kill the process tree on timeout
        try:
            process.kill()  # type: ignore[possibly-undefined]
            await process.wait()  # type: ignore[possibly-undefined]
        except Exception:
            pass
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        logger.error(
            "mobsfscan timed out after %ds on %s", effective_timeout, source_dir,
        )
        return MobsfScanResult(
            success=False,
            error=f"mobsfscan timed out after {effective_timeout}s",
            scan_duration_ms=elapsed_ms,
        )

    elapsed_ms = int((time.monotonic() - t0) * 1000)

    stdout_text = stdout_bytes.decode(errors="replace")
    stderr_text = stderr_bytes.decode(errors="replace").strip()

    if stderr_text:
        logger.debug("mobsfscan stderr: %s", stderr_text[:1000])

    # mobsfscan --no-fail returns 0 even when findings exist.
    # A non-zero exit with --no-fail indicates a real error.
    if process.returncode != 0:
        error_msg = stderr_text[:500] if stderr_text else f"exit code {process.returncode}"
        logger.error("mobsfscan failed: %s", error_msg)
        return MobsfScanResult(
            success=False,
            error=f"mobsfscan failed: {error_msg}",
            scan_duration_ms=elapsed_ms,
        )

    # ------- parse JSON output -------
    return _parse_mobsfscan_output(stdout_text, elapsed_ms)


def _parse_mobsfscan_output(
    raw_stdout: str,
    elapsed_ms: int,
) -> MobsfScanResult:
    """Parse mobsfscan JSON output into structured findings.

    mobsfscan JSON schema (v0.3+):
    ```json
    {
      "results": {
        "<rule_id>": {
          "metadata": {
            "description": "...",
            "severity": "ERROR|WARNING|INFO",
            "cwe": "CWE-...",
            "masvs": "...",
            "owasp-mobile": "...",
            "ref": "...",
            "input_case": "exact",
          },
          "files": [
            {
              "file_path": "relative/path.java",
              "match_string": "matched code",
              "match_position": [start, end],
              "match_lines": [start_line, end_line],
            }
          ]
        }
      },
      "errors": []
    }
    ```
    """
    try:
        data = json.loads(raw_stdout)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse mobsfscan JSON output: %s", exc)
        return MobsfScanResult(
            success=False,
            error=f"Failed to parse mobsfscan output: {exc}",
            scan_duration_ms=elapsed_ms,
        )

    findings: list[MobsfScanFinding] = []
    results: dict = data.get("results", {})
    errors: list = data.get("errors", [])

    suppressed_rule_count = 0
    suppressed_path_count = 0

    for rule_id, rule_data in results.items():
        # --- Rule-level suppression ---
        if rule_id in SUPPRESSED_RULES:
            suppressed_rule_count += len(rule_data.get("files", []))
            continue

        metadata = rule_data.get("metadata", {})
        title = metadata.get("description", rule_id)
        description = metadata.get("description", "")
        severity = metadata.get("severity", "INFO")
        cwe = metadata.get("cwe", "")
        owasp_mobile = metadata.get("owasp-mobile", "")
        masvs = metadata.get("masvs", "")
        section = metadata.get("input_case", "code_analysis")

        matched_files = rule_data.get("files", [])
        for file_entry in matched_files:
            file_path = file_entry.get("file_path", "")

            # --- Path-level suppression (library/generated code) ---
            if file_path and _is_suppressed_path(file_path):
                suppressed_path_count += 1
                continue

            match_string = file_entry.get("match_string", "")

            # match_lines is [start, end]; use start
            match_lines = file_entry.get("match_lines", [0, 0])
            line_number = match_lines[0] if match_lines else 0

            findings.append(
                MobsfScanFinding(
                    rule_id=rule_id,
                    title=title,
                    description=description,
                    severity=severity,
                    section=section,
                    file_path=file_path,
                    line_number=line_number,
                    match_string=match_string,
                    cwe=cwe,
                    owasp_mobile=owasp_mobile,
                    masvs=masvs,
                    metadata=metadata,
                )
            )

    if suppressed_rule_count or suppressed_path_count:
        logger.info(
            "mobsfscan suppressions: %d findings from suppressed rules, "
            "%d from suppressed paths",
            suppressed_rule_count,
            suppressed_path_count,
        )

    if errors:
        logger.warning("mobsfscan reported %d errors: %s", len(errors), errors[:3])

    return MobsfScanResult(
        success=True,
        findings=findings,
        raw_json=data,
        scan_duration_ms=elapsed_ms,
        files_scanned=_count_source_files(data),
        suppressed_rule_count=suppressed_rule_count,
        suppressed_path_count=suppressed_path_count,
    )


def _count_source_files(data: dict) -> int:
    """Count unique files referenced in scan results."""
    files: set[str] = set()
    for rule_data in data.get("results", {}).values():
        for file_entry in rule_data.get("files", []):
            fp = file_entry.get("file_path", "")
            if fp:
                files.add(fp)
    return len(files)


# ---------------------------------------------------------------------------
# Severity ordering & firmware-context helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]

# CWE regex: accept "CWE-123", "cwe-123", "CWE:123", or bare "123"
_CWE_RE = re.compile(r"(?:CWE[-:]?\s*)?(\d+)", re.IGNORECASE)


def _parse_cwe_ids(raw_cwe: str) -> list[str]:
    """Extract structured CWE IDs from mobsfscan's free-form CWE string.

    mobsfscan uses inconsistent formats:
      - ``"CWE-312"``
      - ``"CWE-312, CWE-200"``
      - ``"cwe-312"``
      - ``""`` (empty)

    Returns a list of normalised ``"CWE-NNN"`` strings, deduplicated.
    """
    if not raw_cwe or not raw_cwe.strip():
        return []
    seen: set[str] = set()
    result: list[str] = []
    for m in _CWE_RE.finditer(raw_cwe):
        cwe_id = f"CWE-{m.group(1)}"
        if cwe_id not in seen:
            seen.add(cwe_id)
            result.append(cwe_id)
    return result


def _is_priv_app(apk_rel_path: str) -> bool:
    """Return True if the APK lives under a privileged app directory."""
    parts = apk_rel_path.replace("\\", "/").split("/")
    return "priv-app" in parts


def _bump_severity(severity: str) -> str:
    """Increase severity by one level (for priv-app context bump).

    ``info`` → ``low``, ``low`` → ``medium``, etc.
    ``critical`` stays ``critical``.
    """
    idx = _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else 2
    return _SEVERITY_ORDER[max(0, idx - 1)]


def _dedup_key(rule_id: str, severity: str, file_path: str | None) -> str:
    """Produce a stable dedup key for a normalized finding.

    Two findings are duplicates when they share the same rule, severity,
    and file (ignoring line number, since mobsfscan may match the same
    pattern on slightly different lines across re-scans).
    """
    raw = f"{rule_id}|{severity}|{file_path or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Normalized finding dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NormalizedFinding:
    """A mobsfscan finding mapped to the project's Finding schema.

    This is the bridge between :class:`MobsfScanFinding` (raw scanner output)
    and the unified ``findings`` table.  Fields match
    :class:`~app.schemas.finding.FindingCreate` exactly so that persistence
    code can unpack them directly.
    """

    rule_id: str
    title: str
    severity: str  # one of _SEVERITY_ORDER values
    description: str
    evidence: str
    file_path: str | None  # APK path (for findings DB)
    source_file: str | None  # Java/Kotlin source file path from mobsfscan
    line_number: int | None
    cwe_ids: list[str]
    source: str  # always "apk-mobsfscan"
    owasp_mobile: str  # preserved for rich output
    masvs: str  # preserved for rich output
    dedup_hash: str  # SHA-256 dedup key


# ---------------------------------------------------------------------------
# Public API — normalize
# ---------------------------------------------------------------------------

#: The ``source`` value used for mobsfscan-originated findings.
MOBSFSCAN_SOURCE = "apk-mobsfscan"


def normalize_mobsfscan_findings(
    result: MobsfScanResult,
    *,
    apk_rel_path: str = "",
    priv_app_bump: bool = True,
    min_severity: str = "info",
) -> list[NormalizedFinding]:
    """Transform a :class:`MobsfScanResult` into normalized finding objects.

    Parameters
    ----------
    result:
        The raw result returned by :func:`run_mobsfscan`.
    apk_rel_path:
        Path of the APK relative to the firmware extraction root.  Used for
        firmware-context severity adjustments (priv-app bump) and recorded
        as ``file_path`` on each finding.
    priv_app_bump:
        When *True* **and** the APK resides in a privileged-app directory
        (``priv-app/``), severity is bumped up one level.
    min_severity:
        Minimum severity to include.  Findings below this threshold are
        silently dropped.  Defaults to ``"info"`` (keep everything).

    Returns
    -------
    list[NormalizedFinding]
        Deduplicated, filtered, and severity-adjusted findings ready for
        persistence.
    """
    if not result.success or not result.findings:
        return []

    # Resolve min-severity index (lower index = higher severity)
    min_sev_idx = (
        _SEVERITY_ORDER.index(min_severity)
        if min_severity in _SEVERITY_ORDER
        else len(_SEVERITY_ORDER) - 1
    )

    is_priv = priv_app_bump and _is_priv_app(apk_rel_path)

    normalized: list[NormalizedFinding] = []
    seen_hashes: set[str] = set()

    for raw in result.findings:
        # --- severity mapping ---
        # 1. Start with the base mapping (ERROR→high, WARNING→medium, INFO→info)
        severity = raw.normalized_severity
        # 2. Apply APK-specific severity overrides (e.g. crypto→high)
        severity = _apply_severity_override(raw.rule_id, severity)
        # 3. Apply priv-app firmware context bump on top
        if is_priv:
            severity = _bump_severity(severity)

        # --- min-severity filter ---
        sev_idx = (
            _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else 2
        )
        if sev_idx > min_sev_idx:
            continue

        # --- CWE extraction ---
        cwe_ids = _parse_cwe_ids(raw.cwe)

        # --- evidence construction ---
        evidence_parts: list[str] = []
        if raw.match_string:
            # Truncate long code matches to keep evidence readable
            snippet = raw.match_string[:500]
            if len(raw.match_string) > 500:
                snippet += " …(truncated)"
            evidence_parts.append(f"Code match:\n{snippet}")
        if raw.file_path:
            evidence_parts.append(f"File: {raw.file_path}")
        if raw.line_number:
            evidence_parts.append(f"Line: {raw.line_number}")
        if raw.owasp_mobile:
            evidence_parts.append(f"OWASP Mobile: {raw.owasp_mobile}")
        if raw.masvs:
            evidence_parts.append(f"MASVS: {raw.masvs}")
        if raw.section and raw.section != "code_analysis":
            evidence_parts.append(f"Section: {raw.section}")
        evidence = "\n".join(evidence_parts) if evidence_parts else raw.match_string

        # --- title construction ---
        title = f"[{raw.rule_id}] {raw.title}"
        # Cap title at 255 chars (DB column limit)
        if len(title) > 255:
            title = title[:252] + "..."

        # --- build normalized finding ---
        resolved_path = apk_rel_path or raw.file_path or None
        # Preserve the Java/Kotlin source file path from mobsfscan
        # (raw.file_path is the decompiled source path, not the APK path)
        source_file = None
        if raw.file_path and raw.file_path.endswith(('.java', '.kt')):
            # Strip temp directory prefix to get relative Java path
            # e.g. "/tmp/mobsfscan_xxx/sources/com/example/Foo.java" -> "com/example/Foo.java"
            fp = raw.file_path
            sources_idx = fp.find('/sources/')
            source_file = fp[sources_idx + len('/sources/'):] if sources_idx >= 0 else os.path.basename(fp)
        dedup_hash = _dedup_key(raw.rule_id, severity, resolved_path)

        nf = NormalizedFinding(
            rule_id=raw.rule_id,
            title=title,
            severity=severity,
            description=raw.description or raw.title,
            evidence=evidence,
            file_path=resolved_path,
            source_file=source_file,
            line_number=raw.line_number if raw.line_number else None,
            cwe_ids=cwe_ids,
            source=MOBSFSCAN_SOURCE,
            owasp_mobile=raw.owasp_mobile,
            masvs=raw.masvs,
            dedup_hash=dedup_hash,
        )

        # --- deduplication ---
        if nf.dedup_hash in seen_hashes:
            continue
        seen_hashes.add(nf.dedup_hash)

        normalized.append(nf)

    return normalized


# ---------------------------------------------------------------------------
# Public API — persist
# ---------------------------------------------------------------------------


async def persist_mobsfscan_findings(
    db: "AsyncSession",
    project_id: uuid.UUID,
    firmware_id: uuid.UUID | None,
    normalized: list[NormalizedFinding],
    *,
    fw_ctx: "FirmwareContext | None" = None,
) -> int:
    """Write normalized mobsfscan findings to the ``findings`` table.

    Uses ``flush()`` (not ``commit()``) so the caller controls the
    transaction boundary — matching the MCP handler convention.

    When *fw_ctx* is provided, finding descriptions and evidence are
    enriched with firmware metadata (device model, Android version, etc.).

    Parameters
    ----------
    db:
        Async SQLAlchemy session (typically ``context.db`` from MCP tools
        or ``async_session_factory()`` in REST handlers).
    project_id:
        UUID of the project that owns the findings.
    firmware_id:
        UUID of the firmware the APK belongs to (nullable for standalone).
    normalized:
        Output of :func:`normalize_mobsfscan_findings`.
    fw_ctx:
        Optional :class:`FirmwareContext` for enriching finding
        descriptions with device/firmware metadata.

    Returns
    -------
    int
        Number of findings persisted.
    """
    from app.models.finding import Finding

    for nf in normalized:
        description = nf.description
        evidence = nf.evidence

        # Enrich with firmware context when available
        if fw_ctx:
            from app.utils.firmware_context import enrich_description, enrich_evidence
            description = enrich_description(description, fw_ctx)
            evidence = enrich_evidence(evidence, fw_ctx)

        finding = Finding(
            project_id=project_id,
            firmware_id=firmware_id,
            title=nf.title,
            severity=nf.severity,
            description=description,
            evidence=evidence,
            file_path=nf.file_path,
            line_number=nf.line_number,
            cwe_ids=nf.cwe_ids if nf.cwe_ids else None,
            source=nf.source,
        )
        db.add(finding)

    if normalized:
        await db.flush()

    return len(normalized)


def format_mobsfscan_text(
    result: MobsfScanResult,
    normalized: list[NormalizedFinding],
    apk_rel_path: str = "",
    *,
    jadx_elapsed_ms: int = 0,
    total_elapsed_ms: int = 0,
) -> str:
    """Format mobsfscan results as human-readable text for MCP tool output.

    Parameters
    ----------
    result:
        The raw :class:`MobsfScanResult` (used for summary stats).
    normalized:
        Filtered/normalized findings from :func:`normalize_mobsfscan_findings`.
    apk_rel_path:
        Display path for the APK.
    jadx_elapsed_ms:
        Time spent in JADX decompilation (for pipeline timing display).
    total_elapsed_ms:
        Total pipeline wall-clock time (for pipeline timing display).

    Returns
    -------
    str
        Formatted text suitable for MCP tool response (will be truncated
        downstream by ``truncation.py`` if over 30 KB).
    """
    lines: list[str] = []

    # Header
    lines.append(f"=== mobsfscan Source Code Analysis ===")
    if apk_rel_path:
        lines.append(f"APK: {apk_rel_path}")

    # Pipeline timing
    if total_elapsed_ms:
        lines.append(
            f"Pipeline: {total_elapsed_ms}ms total "
            f"(JADX: {jadx_elapsed_ms}ms, "
            f"mobsfscan: {result.scan_duration_ms}ms)"
        )
    else:
        lines.append(f"Scan duration: {result.scan_duration_ms}ms")

    lines.append(f"Files scanned: {result.files_scanned}")
    lines.append(f"Total raw findings: {len(result.findings)}")
    suppressed_total = result.suppressed_rule_count + result.suppressed_path_count
    if suppressed_total:
        lines.append(
            f"Suppressed: {suppressed_total} "
            f"({result.suppressed_rule_count} noisy rules, "
            f"{result.suppressed_path_count} library paths)"
        )
    lines.append(f"Normalized findings: {len(normalized)}")

    # Severity summary
    sev_counts: dict[str, int] = {}
    for nf in normalized:
        sev_counts[nf.severity] = sev_counts.get(nf.severity, 0) + 1
    if sev_counts:
        parts = [f"{sev}: {cnt}" for sev, cnt in sorted(sev_counts.items())]
        lines.append(f"By severity: {', '.join(parts)}")

    lines.append("")

    # Individual findings
    for i, nf in enumerate(normalized, 1):
        lines.append(f"--- Finding {i} [{nf.severity.upper()}] ---")
        lines.append(f"Rule: {nf.rule_id}")
        lines.append(f"Title: {nf.title}")
        lines.append(f"Description: {nf.description}")
        if nf.cwe_ids:
            lines.append(f"CWE: {', '.join(nf.cwe_ids)}")
        if nf.owasp_mobile:
            lines.append(f"OWASP Mobile: {nf.owasp_mobile}")
        if nf.masvs:
            lines.append(f"MASVS: {nf.masvs}")
        if nf.file_path:
            lines.append(f"File: {nf.file_path}")
        if nf.line_number:
            lines.append(f"Line: {nf.line_number}")
        if nf.evidence:
            lines.append(f"Evidence:\n{nf.evidence}")
        lines.append("")

    if not normalized:
        lines.append("No findings above the minimum severity threshold.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orchestration dataclass — full pipeline result
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class MobsfScanPipelineResult:
    """Complete result of the mobsfscan orchestration pipeline.

    Aggregates scan results, normalized findings, persistence counts,
    and formatted text output — everything downstream consumers need.
    """

    scan_result: MobsfScanResult
    normalized: list[NormalizedFinding]
    persisted_count: int = 0
    cached: bool = False  # True if result was served from AnalysisCache
    text_output: str = ""
    # Phase timing (milliseconds)
    total_elapsed_ms: int = 0  # wall-clock time for the entire pipeline
    jadx_elapsed_ms: int = 0  # time spent in JADX decompilation
    mobsfscan_elapsed_ms: int = 0  # time spent in mobsfscan scanning

    @property
    def summary(self) -> dict[str, Any]:
        """Compact summary dict for API responses and MCP tool output."""
        return {
            **self.scan_result.summary,
            "normalized_findings": len(self.normalized),
            "persisted_count": self.persisted_count,
            "cached": self.cached,
            "total_elapsed_ms": self.total_elapsed_ms,
            "jadx_elapsed_ms": self.jadx_elapsed_ms,
            "mobsfscan_elapsed_ms": self.mobsfscan_elapsed_ms,
        }


# ---------------------------------------------------------------------------
# MobsfScanPipeline — end-to-end orchestration
# ---------------------------------------------------------------------------

#: AnalysisCache operation key for cached mobsfscan results.
_CACHE_OP = "mobsfscan_scan"

#: Total pipeline budget (seconds).  The 3-minute cap is shared across
#: JADX decompilation + mobsfscan scanning.  After JADX completes, the
#: remaining budget is passed to mobsfscan as its timeout.
_PIPELINE_BUDGET_SECONDS: int = 600


class MobsfScanPipeline:
    """Orchestrates the full mobsfscan SAST scanning pipeline.

    Responsibilities:

    1. Accept either a **JADX output directory** (already decompiled) or
       an **APK path** (triggers lazy decompilation via jadx_service).
    2. If sources live in AnalysisCache (JSONB), materialise them to a
       temporary directory for mobsfscan CLI consumption.
    3. Invoke ``run_mobsfscan()`` with configurable timeout.
    4. Parse + normalise findings with firmware-context severity adjustments.
    5. Cache raw scan results in AnalysisCache (keyed by APK SHA-256).
    6. Persist normalised findings to the ``findings`` table via ``flush()``.
    7. Return a :class:`MobsfScanPipelineResult` with everything bundled.

    The pipeline includes a concurrency guard so only one scan per APK
    SHA-256 runs at a time (matching the jadx_service pattern).
    """

    def __init__(self) -> None:
        self._scan_locks: dict[str, asyncio.Event] = {}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Cache helpers (AnalysisCache integration)
    # ------------------------------------------------------------------

    async def _get_cached_result(
        self,
        firmware_id: uuid.UUID,
        apk_sha256: str,
        db: "AsyncSession",
    ) -> dict | None:
        """Retrieve a previously cached mobsfscan result."""
        from app.services import _cache

        return await _cache.get_cached(
            db, firmware_id, _CACHE_OP, binary_sha256=apk_sha256,
        )

    async def _store_cached_result(
        self,
        firmware_id: uuid.UUID,
        apk_path: str,
        apk_sha256: str,
        result_data: dict,
        db: "AsyncSession",
    ) -> None:
        """Store a mobsfscan result (delete-then-insert upsert)."""
        from app.services import _cache

        await _cache.store_cached(
            db,
            firmware_id,
            _CACHE_OP,
            result_data,
            binary_sha256=apk_sha256,
            binary_path=apk_path,
        )

    # ------------------------------------------------------------------
    # Rebuild helpers — reconstruct dataclasses from cached dicts
    # ------------------------------------------------------------------

    @staticmethod
    def _rebuild_scan_result(cached: dict) -> MobsfScanResult:
        """Reconstruct a :class:`MobsfScanResult` from cached JSONB data."""
        findings: list[MobsfScanFinding] = []
        for fd in cached.get("findings", []):
            findings.append(
                MobsfScanFinding(
                    rule_id=fd.get("rule_id", ""),
                    title=fd.get("title", ""),
                    description=fd.get("description", ""),
                    severity=fd.get("severity", "INFO"),
                    section=fd.get("section", ""),
                    file_path=fd.get("file_path", ""),
                    line_number=fd.get("line_number", 0),
                    match_string=fd.get("match_string", ""),
                    cwe=fd.get("cwe", ""),
                    owasp_mobile=fd.get("owasp_mobile", ""),
                    masvs=fd.get("masvs", ""),
                    metadata=fd.get("metadata", {}),
                )
            )
        return MobsfScanResult(
            success=cached.get("success", True),
            findings=findings,
            raw_json=cached.get("raw_json"),
            scan_duration_ms=cached.get("scan_duration_ms", 0),
            files_scanned=cached.get("files_scanned", 0),
            suppressed_rule_count=cached.get("suppressed_rule_count", 0),
            suppressed_path_count=cached.get("suppressed_path_count", 0),
        )

    @staticmethod
    def _serialize_scan_result(result: MobsfScanResult) -> dict:
        """Serialise a :class:`MobsfScanResult` to a dict for JSONB storage."""
        serialised_findings = []
        for f in result.findings:
            serialised_findings.append({
                "rule_id": f.rule_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "section": f.section,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "match_string": f.match_string[:1000],  # cap for JSONB
                "cwe": f.cwe,
                "owasp_mobile": f.owasp_mobile,
                "masvs": f.masvs,
                "metadata": f.metadata,
            })
        return {
            "success": result.success,
            "findings": serialised_findings,
            "raw_json": None,  # raw_json can be huge; omit from cache
            "scan_duration_ms": result.scan_duration_ms,
            "files_scanned": result.files_scanned,
            "error": result.error,
            "suppressed_rule_count": result.suppressed_rule_count,
            "suppressed_path_count": result.suppressed_path_count,
        }

    # ------------------------------------------------------------------
    # Source materialisation
    # ------------------------------------------------------------------

    @staticmethod
    async def _materialise_sources_from_cache(
        apk_path: str,
        firmware_id: uuid.UUID,
        db: "AsyncSession",
        target_dir: str,
    ) -> str:
        """Write cached JADX sources to disk for mobsfscan consumption.

        Uses :meth:`JadxDecompilationCache.write_sources_to_disk`.
        """
        from app.services.jadx_service import get_jadx_cache

        cache = get_jadx_cache()
        return await cache.write_sources_to_disk(
            apk_path, firmware_id, db, target_dir,
        )

    @staticmethod
    async def _ensure_decompilation(
        apk_path: str,
        firmware_id: uuid.UUID,
        db: "AsyncSession",
    ) -> str:
        """Ensure JADX has decompiled the APK; returns the SHA-256 hash."""
        from app.services.jadx_service import get_jadx_cache

        cache = get_jadx_cache()
        return await cache.ensure_decompilation(apk_path, firmware_id, db)

    # ------------------------------------------------------------------
    # Public API — scan_apk (full pipeline from APK path)
    # ------------------------------------------------------------------

    async def scan_apk(
        self,
        *,
        apk_path: str,
        firmware_id: uuid.UUID,
        project_id: uuid.UUID,
        db: "AsyncSession",
        apk_rel_path: str = "",
        timeout: int | None = None,
        min_severity: str = "info",
        persist: bool = True,
        use_cache: bool = True,
        fw_ctx: "FirmwareContext | None" = None,
    ) -> MobsfScanPipelineResult:
        """Run the full jadx → mobsfscan pipeline against an APK.

        This is the primary entry point for MCP tools and REST endpoints.
        The pipeline runs sequentially with a shared timeout budget
        (default ``_PIPELINE_BUDGET_SECONDS`` = 180 s / 3 minutes):

        1. **JADX decompilation** (lazy, cached) — consumes part of the budget.
        2. Check AnalysisCache for prior mobsfscan results.
        3. **mobsfscan SAST scan** — gets the *remaining* budget as its timeout.
        4. Cache scan results in AnalysisCache.
        5. Normalise findings with firmware-context severity adjustments.
        6. Optionally persist findings to the ``findings`` table.
        7. Format human-readable text output.

        Total elapsed time and per-phase timing are recorded on the
        returned :class:`MobsfScanPipelineResult`.

        Parameters
        ----------
        apk_path:
            Absolute path to the APK file.
        firmware_id:
            UUID of the firmware the APK belongs to.
        project_id:
            UUID of the project (for finding persistence).
        db:
            Async SQLAlchemy session.
        apk_rel_path:
            Relative path of the APK within firmware extraction root.
            Used for priv-app severity bump and display.
        timeout:
            Total pipeline budget in seconds.  Defaults to
            ``_PIPELINE_BUDGET_SECONDS`` (180 s).  The budget is shared:
            after JADX finishes, the remainder is given to mobsfscan.
        min_severity:
            Minimum severity threshold for normalised findings.
        persist:
            Whether to write findings to the ``findings`` table.
        use_cache:
            Whether to check/store AnalysisCache.  Set ``False`` to
            force a rescan.
        fw_ctx:
            Optional :class:`FirmwareContext` for enriching finding
            descriptions with device/firmware metadata.

        Returns
        -------
        MobsfScanPipelineResult
            Complete pipeline result with scan data, findings, timing,
            and formatted text.

        Raises
        ------
        FileNotFoundError
            If the APK path does not exist.
        RuntimeError
            If mobsfscan is not installed or JADX decompilation fails.
        TimeoutError
            If the total pipeline budget is exhausted.
        """
        if not os.path.isfile(apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")

        budget = timeout or _PIPELINE_BUDGET_SECONDS
        pipeline_t0 = time.monotonic()

        # ------------------------------------------------------------------
        # Phase 1: JADX decompilation (lazy, cached, concurrency-guarded)
        # ------------------------------------------------------------------
        jadx_t0 = time.monotonic()
        try:
            apk_sha256 = await asyncio.wait_for(
                self._ensure_decompilation(apk_path, firmware_id, db),
                timeout=budget,
            )
        except asyncio.TimeoutError:
            elapsed_ms = int((time.monotonic() - pipeline_t0) * 1000)
            logger.error(
                "Pipeline budget exhausted during JADX decompilation for %s "
                "(%ds budget)",
                os.path.basename(apk_path),
                budget,
            )
            raise TimeoutError(
                f"Pipeline budget ({budget}s) exhausted during JADX "
                f"decompilation of {os.path.basename(apk_path)} "
                f"after {elapsed_ms}ms"
            )
        jadx_elapsed_ms = int((time.monotonic() - jadx_t0) * 1000)

        # ------------------------------------------------------------------
        # Check remaining budget
        # ------------------------------------------------------------------
        elapsed_so_far = time.monotonic() - pipeline_t0
        remaining_budget = max(budget - elapsed_so_far, 0)

        if remaining_budget < 5:
            # Less than 5 s left — not enough for a meaningful scan
            total_ms = int((time.monotonic() - pipeline_t0) * 1000)
            logger.warning(
                "Only %.1fs remaining after JADX — skipping mobsfscan for %s",
                remaining_budget,
                os.path.basename(apk_path),
            )
            empty_result = MobsfScanResult(
                success=False,
                error=(
                    f"Pipeline budget exhausted: JADX took {jadx_elapsed_ms}ms, "
                    f"only {remaining_budget:.1f}s remaining (need ≥5s for scan)"
                ),
                scan_duration_ms=0,
            )
            return MobsfScanPipelineResult(
                scan_result=empty_result,
                normalized=[],
                total_elapsed_ms=total_ms,
                jadx_elapsed_ms=jadx_elapsed_ms,
                mobsfscan_elapsed_ms=0,
            )

        # ------------------------------------------------------------------
        # Phase 1.5: Check cache (fast, no budget concern)
        # ------------------------------------------------------------------
        if use_cache:
            cached_data = await self._get_cached_result(
                firmware_id, apk_sha256, db,
            )
            if cached_data is not None:
                logger.info(
                    "mobsfscan cache hit for %s (sha256=%s)",
                    os.path.basename(apk_path),
                    apk_sha256[:12],
                )
                scan_result = self._rebuild_scan_result(cached_data)
                normalized = normalize_mobsfscan_findings(
                    scan_result,
                    apk_rel_path=apk_rel_path,
                    min_severity=min_severity,
                )
                persisted = 0
                if persist and normalized:
                    persisted = await persist_mobsfscan_findings(
                        db, project_id, firmware_id, normalized,
                        fw_ctx=fw_ctx,
                    )
                total_ms = int((time.monotonic() - pipeline_t0) * 1000)
                text = format_mobsfscan_text(
                    scan_result, normalized, apk_rel_path,
                    jadx_elapsed_ms=jadx_elapsed_ms,
                    total_elapsed_ms=total_ms,
                )
                return MobsfScanPipelineResult(
                    scan_result=scan_result,
                    normalized=normalized,
                    persisted_count=persisted,
                    cached=True,
                    text_output=text,
                    total_elapsed_ms=total_ms,
                    jadx_elapsed_ms=jadx_elapsed_ms,
                    mobsfscan_elapsed_ms=scan_result.scan_duration_ms,
                )

        # ------------------------------------------------------------------
        # Phase 2: mobsfscan SAST scan (gets remaining budget)
        # ------------------------------------------------------------------
        mobsfscan_timeout = int(remaining_budget)
        logger.info(
            "Running mobsfscan with %ds remaining budget (JADX took %dms)",
            mobsfscan_timeout,
            jadx_elapsed_ms,
        )

        mobsfscan_t0 = time.monotonic()
        scan_result = await self._run_with_guard(
            apk_path=apk_path,
            apk_sha256=apk_sha256,
            firmware_id=firmware_id,
            db=db,
            timeout=mobsfscan_timeout,
        )
        mobsfscan_elapsed_ms = int((time.monotonic() - mobsfscan_t0) * 1000)

        # ------------------------------------------------------------------
        # Post-scan: cache, normalise, persist, format
        # ------------------------------------------------------------------
        if use_cache and scan_result.success:
            await self._store_cached_result(
                firmware_id,
                apk_path,
                apk_sha256,
                self._serialize_scan_result(scan_result),
                db,
            )

        normalized = normalize_mobsfscan_findings(
            scan_result,
            apk_rel_path=apk_rel_path,
            min_severity=min_severity,
        )

        persisted = 0
        if persist and normalized:
            persisted = await persist_mobsfscan_findings(
                db, project_id, firmware_id, normalized,
                fw_ctx=fw_ctx,
            )

        total_elapsed_ms = int((time.monotonic() - pipeline_t0) * 1000)
        text = format_mobsfscan_text(
            scan_result, normalized, apk_rel_path,
            jadx_elapsed_ms=jadx_elapsed_ms,
            total_elapsed_ms=total_elapsed_ms,
        )

        return MobsfScanPipelineResult(
            scan_result=scan_result,
            normalized=normalized,
            persisted_count=persisted,
            cached=False,
            text_output=text,
            total_elapsed_ms=total_elapsed_ms,
            jadx_elapsed_ms=jadx_elapsed_ms,
            mobsfscan_elapsed_ms=mobsfscan_elapsed_ms,
        )

    # ------------------------------------------------------------------
    # Public API — scan_source_dir (from pre-existing JADX output)
    # ------------------------------------------------------------------

    async def scan_source_dir(
        self,
        *,
        source_dir: str,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID | None = None,
        db: "AsyncSession",
        apk_rel_path: str = "",
        timeout: int | None = None,
        min_severity: str = "info",
        persist: bool = True,
    ) -> MobsfScanPipelineResult:
        """Run mobsfscan against a pre-existing JADX output directory.

        Use this when decompiled sources are already on disk (e.g. an
        extracted firmware that shipped with Java source, or a directory
        prepared by the caller).  No caching or decompilation is performed.

        Parameters
        ----------
        source_dir:
            Absolute path to the directory containing Java/Kotlin sources.
        project_id:
            UUID of the project for finding persistence.
        firmware_id:
            UUID of the firmware (nullable for standalone APKs).
        db:
            Async SQLAlchemy session.
        apk_rel_path:
            Display path for findings.
        timeout:
            Mobsfscan timeout in seconds.
        min_severity:
            Minimum severity for normalised findings.
        persist:
            Whether to write findings to the ``findings`` table.

        Returns
        -------
        MobsfScanPipelineResult

        Raises
        ------
        FileNotFoundError
            If *source_dir* does not exist.
        RuntimeError
            If mobsfscan is not installed.
        """
        scan_result = await run_mobsfscan(source_dir, timeout=timeout)

        normalized = normalize_mobsfscan_findings(
            scan_result,
            apk_rel_path=apk_rel_path,
            min_severity=min_severity,
        )

        persisted = 0
        if persist and normalized:
            persisted = await persist_mobsfscan_findings(
                db, project_id, firmware_id, normalized,
            )

        text = format_mobsfscan_text(scan_result, normalized, apk_rel_path)

        return MobsfScanPipelineResult(
            scan_result=scan_result,
            normalized=normalized,
            persisted_count=persisted,
            cached=False,
            text_output=text,
        )

    # ------------------------------------------------------------------
    # Internal — concurrency-guarded scan execution
    # ------------------------------------------------------------------

    async def _run_with_guard(
        self,
        *,
        apk_path: str,
        apk_sha256: str,
        firmware_id: uuid.UUID,
        db: "AsyncSession",
        timeout: int | None,
    ) -> MobsfScanResult:
        """Execute mobsfscan with a per-APK concurrency guard.

        If another coroutine is already scanning the same APK (by SHA-256),
        this coroutine waits for it to finish and then reads from cache.
        """
        should_scan = False
        async with self._lock:
            event = self._scan_locks.get(apk_sha256)
            if event is not None:
                pass  # Another coroutine is scanning — we'll wait
            else:
                event = asyncio.Event()
                self._scan_locks[apk_sha256] = event
                should_scan = True

        if not should_scan:
            # Wait for the other coroutine to finish, then try cache
            await event.wait()
            cached = await self._get_cached_result(firmware_id, apk_sha256, db)
            if cached is not None:
                return self._rebuild_scan_result(cached)
            # Fallthrough: cache miss after wait (shouldn't happen, but
            # be defensive — just run the scan ourselves)

        try:
            return await self._execute_scan(
                apk_path=apk_path,
                firmware_id=firmware_id,
                db=db,
                timeout=timeout,
            )
        finally:
            if should_scan:
                async with self._lock:
                    self._scan_locks.pop(apk_sha256, None)
                event.set()

    async def _execute_scan(
        self,
        *,
        apk_path: str,
        firmware_id: uuid.UUID,
        db: "AsyncSession",
        timeout: int | None,
    ) -> MobsfScanResult:
        """Materialise cached sources to a temp dir and run mobsfscan."""
        with tempfile.TemporaryDirectory(prefix="mobsfscan_") as tmp_dir:
            source_dir = os.path.join(tmp_dir, "sources")

            # Write decompiled sources from AnalysisCache to disk
            await self._materialise_sources_from_cache(
                apk_path, firmware_id, db, source_dir,
            )

            # Verify sources were written
            if not os.path.isdir(source_dir) or not os.listdir(source_dir):
                return MobsfScanResult(
                    success=True,  # Not an error — resource-only APKs have no code
                    error=(
                        "No decompiled sources found — this APK contains no "
                        "DEX bytecode (resource-only package). SAST analysis "
                        "is not applicable."
                    ),
                )

            return await run_mobsfscan(source_dir, timeout=timeout)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_pipeline = MobsfScanPipeline()


def get_mobsfscan_pipeline() -> MobsfScanPipeline:
    """Get the module-level MobsfScanPipeline singleton."""
    return _pipeline
