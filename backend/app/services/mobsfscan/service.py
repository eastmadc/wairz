"""Public facade for the mobsfscan subpackage.

Re-exports the stable public API — pipeline + runner + normalization —
so callers can ``from app.services.mobsfscan import <name>`` without
reaching into implementation modules.

Layering:

- :mod:`~app.services.mobsfscan.parser` — low-level CLI runner, dataclasses.
- :mod:`~app.services.mobsfscan.normalization` — finding post-processing.
- :mod:`~app.services.mobsfscan.pipeline` — end-to-end orchestration +
  the :class:`MobsfScanPipeline` singleton.

This module is intentionally thin: if you need the details of a given
symbol, go to the source module.
"""

from __future__ import annotations

from app.services.mobsfscan.normalization import (
    MOBSFSCAN_SOURCE,
    SEVERITY_OVERRIDES,
    SUPPRESSED_PATH_PATTERNS,
    SUPPRESSED_RULES,
    NormalizedFinding,
    _apply_severity_override,
    _bump_severity,
    _dedup_key,
    _is_priv_app,
    _is_suppressed_path,
    _parse_cwe_ids,
    format_mobsfscan_text,
    normalize_mobsfscan_findings,
    persist_mobsfscan_findings,
)
from app.services.mobsfscan.parser import (
    MobsfScanFinding,
    MobsfScanResult,
    _count_source_files,
    _find_mobsfscan,
    _parse_mobsfscan_output,
    mobsfscan_available,
    run_mobsfscan,
)
from app.services.mobsfscan.pipeline import (
    MobsfScanPipeline,
    MobsfScanPipelineResult,
    get_mobsfscan_pipeline,
)

__all__ = [
    # --- pipeline ---
    "MobsfScanPipeline",
    "MobsfScanPipelineResult",
    "get_mobsfscan_pipeline",
    # --- parser ---
    "MobsfScanFinding",
    "MobsfScanResult",
    "mobsfscan_available",
    "run_mobsfscan",
    # --- normalization ---
    "MOBSFSCAN_SOURCE",
    "NormalizedFinding",
    "SEVERITY_OVERRIDES",
    "SUPPRESSED_PATH_PATTERNS",
    "SUPPRESSED_RULES",
    "format_mobsfscan_text",
    "normalize_mobsfscan_findings",
    "persist_mobsfscan_findings",
    # --- test-only internals re-exported for backward compat ---
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
