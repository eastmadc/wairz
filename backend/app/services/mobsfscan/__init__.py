"""mobsfscan integration subpackage — orchestrates the full SAST pipeline.

Provides two layers:

**Low-level runner** (:func:`run_mobsfscan`, :class:`MobsfScanFinding`):
    Executes the ``mobsfscan`` CLI tool (which wraps semgrep + custom
    rules) against a directory of decompiled Java/Kotlin source code.
    See :mod:`~app.services.mobsfscan.parser`.

**Orchestration layer** (:class:`MobsfScanPipeline`):
    End-to-end pipeline that accepts a JADX output path (or APK path),
    invokes the runner, parses results, caches them in the
    ``analysis_cache`` table, normalizes findings with firmware-context
    severity adjustments, persists them to the findings table, and
    returns structured output.
    See :mod:`~app.services.mobsfscan.pipeline`.

The runner is designed to work with sources materialized by
:mod:`app.services.jadx_service` (``write_sources_to_disk``).

:func:`normalize_mobsfscan_findings` converts raw
:class:`MobsfScanFinding` objects into the project's unified
:class:`~app.schemas.finding.FindingCreate` schema, suitable for
persistence via :class:`~app.services.finding_service.FindingService`
or direct ORM insertion with ``flush()``.
See :mod:`~app.services.mobsfscan.normalization`.

All methods are async.  The actual CLI invocation uses
``asyncio.create_subprocess_exec()`` with configurable timeout.
"""

from __future__ import annotations

from app.services.mobsfscan.service import (
    MOBSFSCAN_SOURCE,
    SEVERITY_OVERRIDES,
    SUPPRESSED_PATH_PATTERNS,
    SUPPRESSED_RULES,
    MobsfScanFinding,
    MobsfScanPipeline,
    MobsfScanPipelineResult,
    MobsfScanResult,
    NormalizedFinding,
    _apply_severity_override,
    _bump_severity,
    _count_source_files,
    _dedup_key,
    _find_mobsfscan,
    _is_priv_app,
    _is_suppressed_path,
    _parse_cwe_ids,
    _parse_mobsfscan_output,
    format_mobsfscan_text,
    get_mobsfscan_pipeline,
    mobsfscan_available,
    normalize_mobsfscan_findings,
    persist_mobsfscan_findings,
    run_mobsfscan,
)

__all__ = [
    "MOBSFSCAN_SOURCE",
    "MobsfScanFinding",
    "MobsfScanPipeline",
    "MobsfScanPipelineResult",
    "MobsfScanResult",
    "NormalizedFinding",
    "SEVERITY_OVERRIDES",
    "SUPPRESSED_PATH_PATTERNS",
    "SUPPRESSED_RULES",
    "format_mobsfscan_text",
    "get_mobsfscan_pipeline",
    "mobsfscan_available",
    "normalize_mobsfscan_findings",
    "persist_mobsfscan_findings",
    "run_mobsfscan",
    # Test-only internals re-exported for backward compat
    "_apply_severity_override",
    "_bump_severity",
    "_count_source_files",
    "_dedup_key",
    "_find_mobsfscan",
    "_is_priv_app",
    "_is_suppressed_path",
    "_parse_cwe_ids",
    "_parse_mobsfscan_output",
]
