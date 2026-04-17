"""YARA malware scanning service for firmware analysis.

Compiles YARA rules from the built-in rule set and scans extracted firmware
filesystems for malware, backdoors, and suspicious patterns. Results are
returned as SecurityFinding objects compatible with the finding persistence
layer.

Designed to run as a sync function in a thread executor (CPU-bound YARA
matching), then persist findings via an async DB session.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

import yara

from app.services.security_audit_service import SecurityFinding

logger = logging.getLogger(__name__)

# Directory containing built-in YARA rule files
_RULES_DIR = Path(__file__).resolve().parent.parent / "yara_rules"

MAX_SCAN_FINDINGS = 200
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB per file

# Binary-heavy extensions to skip (archives, images, compressed blobs)
_SKIP_EXTENSIONS = frozenset({
    ".gz", ".xz", ".bz2", ".zst", ".lz4", ".lzma", ".zip", ".tar",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".wav", ".avi", ".mkv",
    ".pyc", ".pyo", ".class", ".wasm",
})


@dataclass
class YaraScanResult:
    """Aggregate result of a YARA scan."""
    findings: list[SecurityFinding] = field(default_factory=list)
    files_scanned: int = 0
    files_matched: int = 0
    rules_loaded: int = 0
    errors: list[str] = field(default_factory=list)


def compile_rules(extra_rules_dir: str | None = None) -> yara.Rules:
    """Compile all YARA rules from the built-in directory, YARA Forge, and optional extras.

    Loads rules from three sources (in order):
    1. Built-in rules in backend/app/yara_rules/
    2. YARA Forge community rules from settings.yara_forge_dir (if downloaded)
    3. Optional extra rules directory passed by caller

    Args:
        extra_rules_dir: Optional path to a directory with additional .yar files.

    Returns:
        Compiled yara.Rules object.
    """
    from app.config import get_settings

    sources: dict[str, str] = {}
    yara_forge_dir = get_settings().yara_forge_dir

    for rules_dir in [_RULES_DIR, yara_forge_dir, extra_rules_dir]:
        if rules_dir is None:
            continue
        rules_path = Path(rules_dir)
        if not rules_path.is_dir():
            continue
        for rule_file in sorted(rules_path.glob("*.yar")):
            namespace = rule_file.stem
            # Prefix YARA Forge namespaces to avoid collisions
            if str(rules_path) == yara_forge_dir:
                namespace = f"forge_{namespace}"
            try:
                sources[namespace] = rule_file.read_text()
            except Exception as e:
                logger.warning("Failed to read YARA rule %s: %s", rule_file, e)

    if not sources:
        raise ValueError(f"No YARA rule files found in {_RULES_DIR}")

    return yara.compile(sources=sources)


def _rel(abs_path: str, root: str) -> str:
    return "/" + os.path.relpath(abs_path, root)


def _severity_from_meta(meta: dict) -> str:
    """Extract severity from rule metadata, default to medium."""
    return meta.get("severity", "medium")


def _category_from_meta(meta: dict) -> str:
    """Extract category from rule metadata."""
    return meta.get("category", "unknown")


def _cwe_from_meta(meta: dict) -> list[str] | None:
    """Extract CWE IDs from rule metadata."""
    cwe = meta.get("cwe")
    if cwe:
        return [cwe] if isinstance(cwe, str) else list(cwe)
    return None


def _scan_single_root(
    rules: "yara.Rules",
    scan_root: str,
    path_rel_base: str,
    result: YaraScanResult,
    matched_shas: set[str],
) -> None:
    """Walk ``scan_root`` and append YARA matches to ``result``.

    ``path_rel_base`` is the directory used for relative-path display.
    ``matched_shas`` is a cross-root dedupe set — per-root SHAs of
    already-matched files so a blob appearing in two partitions doesn't
    produce duplicate findings.
    """
    import hashlib as _hashlib

    matched_files: set[str] = set()

    for dirpath, _dirs, files in os.walk(scan_root):
        if len(result.findings) >= MAX_SCAN_FINDINGS:
            break

        for filename in files:
            if len(result.findings) >= MAX_SCAN_FINDINGS:
                break

            abs_path = os.path.join(dirpath, filename)

            # Skip symlinks, non-files
            if not os.path.isfile(abs_path) or os.path.islink(abs_path):
                continue

            # Skip by extension
            _, ext = os.path.splitext(filename.lower())
            if ext in _SKIP_EXTENSIONS:
                continue

            # Skip oversized files
            try:
                size = os.path.getsize(abs_path)
                if size > MAX_FILE_SIZE or size == 0:
                    continue
            except OSError:
                continue

            result.files_scanned += 1

            try:
                matches = rules.match(abs_path, timeout=30)
            except yara.TimeoutError:
                result.errors.append(
                    f"YARA timeout scanning {_rel(abs_path, path_rel_base)}"
                )
                continue
            except yara.Error as e:
                # Skip files that can't be scanned (permission, etc.)
                logger.debug("YARA scan error on %s: %s", abs_path, e)
                continue

            if not matches:
                continue

            # Cross-root dedupe by SHA — identical blobs in two
            # partitions produce findings once.
            try:
                with open(abs_path, "rb") as f:
                    sha = _hashlib.sha256(f.read()).hexdigest()
            except OSError:
                sha = abs_path  # fallback key — keep this file's findings
            if sha in matched_shas:
                continue
            matched_shas.add(sha)

            rel_path = _rel(abs_path, path_rel_base)
            if rel_path not in matched_files:
                matched_files.add(rel_path)

            for match in matches:
                meta = match.meta
                severity = _severity_from_meta(meta)
                category = _category_from_meta(meta)
                description = meta.get("description", match.rule)

                # Build evidence from matched strings (truncated)
                evidence_parts = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        try:
                            snippet = instance.matched_data.decode(
                                "utf-8", errors="replace"
                            )[:80]
                        except Exception:
                            snippet = instance.matched_data.hex()[:80]
                        evidence_parts.append(
                            f"  0x{instance.offset:08x}: {string_match.identifier} = {snippet!r}"
                        )
                        if len(evidence_parts) >= 5:
                            break
                    if len(evidence_parts) >= 5:
                        break

                evidence = (
                    f"Rule: {match.rule} ({match.namespace})\n"
                    f"Category: {category}\n"
                    f"Matched strings:\n" + "\n".join(evidence_parts)
                )

                result.findings.append(SecurityFinding(
                    title=f"YARA: {description}",
                    severity=severity,
                    description=(
                        f"YARA rule '{match.rule}' matched in {rel_path}. "
                        f"Category: {category}. {description}"
                    ),
                    evidence=evidence[:2000],
                    file_path=rel_path,
                    cwe_ids=_cwe_from_meta(meta),
                ))

    result.files_matched += len(matched_files)


def scan_firmware(
    extracted_path: str,
    extra_rules_dir: str | None = None,
    path_filter: str | None = None,
) -> YaraScanResult:
    """Scan an extracted firmware filesystem with YARA rules.

    This is a synchronous, CPU-bound function. Call it from an async context
    via ``loop.run_in_executor(None, scan_firmware, ...)``.

    Args:
        extracted_path: Root directory of the extracted firmware.
        extra_rules_dir: Optional directory with additional .yar rule files.
        path_filter: Optional subdirectory within the firmware to limit scanning.

    Returns:
        YaraScanResult with findings and scan statistics.
    """
    result = YaraScanResult()

    # Compile rules
    try:
        rules = compile_rules(extra_rules_dir)
        result.rules_loaded = sum(1 for _ in rules)
    except Exception as e:
        result.errors.append(f"Failed to compile YARA rules: {e}")
        logger.error("YARA rule compilation failed", exc_info=True)
        return result

    # Determine scan root
    scan_root = os.path.realpath(extracted_path)
    if path_filter:
        filtered = os.path.realpath(os.path.join(scan_root, path_filter.lstrip("/")))
        if filtered.startswith(scan_root):
            scan_root = filtered

    if not os.path.isdir(scan_root):
        result.errors.append(f"Scan path does not exist: {scan_root}")
        return result

    _scan_single_root(
        rules,
        scan_root=scan_root,
        path_rel_base=extracted_path,
        result=result,
        matched_shas=set(),
    )
    return result


def scan_firmware_multi(
    paths: list[str],
    extra_rules_dir: str | None = None,
) -> YaraScanResult:
    """Scan multiple detection roots with a single compiled rule set.

    Designed for Phase 3a multi-root walks — each path is scanned
    sequentially and SHA-256 dedup prevents double-reporting of blobs
    that exist in more than one partition dir.

    Call from an async context via ``loop.run_in_executor(None,
    scan_firmware_multi, paths)``.
    """
    result = YaraScanResult()

    try:
        rules = compile_rules(extra_rules_dir)
        result.rules_loaded = sum(1 for _ in rules)
    except Exception as e:
        result.errors.append(f"Failed to compile YARA rules: {e}")
        logger.error("YARA rule compilation failed", exc_info=True)
        return result

    if not paths:
        result.errors.append("No scan roots provided")
        return result

    matched_shas: set[str] = set()
    for path in paths:
        real = os.path.realpath(path)
        if not os.path.isdir(real):
            result.errors.append(f"Scan path does not exist: {real}")
            continue
        _scan_single_root(
            rules,
            scan_root=real,
            path_rel_base=real,
            result=result,
            matched_shas=matched_shas,
        )
        if len(result.findings) >= MAX_SCAN_FINDINGS:
            break

    return result
