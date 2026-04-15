"""Phase 2b: Android APK SAST scanning MCP tool (jadx + mobsfscan).

Provides an MCP tool for running the full decompilation → SAST pipeline:
JADX decompiles the APK to Java/Kotlin source, then mobsfscan performs
pattern-based static analysis.  Results are cached via AnalysisCache
and findings persisted to the project findings database via flush().

The pipeline enforces a 3-minute total timeout budget shared across
both phases (JADX decompilation + mobsfscan scanning).
"""

from __future__ import annotations

import logging
import os

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.ai.tools._android_helpers import find_apk
from app.utils.truncation import truncate_output

logger = logging.getLogger(__name__)


def register_android_sast_tools(registry: ToolRegistry) -> None:
    """Register Phase 2b SAST analysis tools."""

    registry.register(
        name="scan_apk_sast",
        description=(
            "Phase 2b: Full SAST pipeline — decompiles an APK with JADX, then "
            "runs mobsfscan for complex code-pattern static analysis. Detects: "
            "hardcoded secrets/keys, insecure crypto usage, SQL injection, "
            "insecure WebView, logging of sensitive data, weak TLS/SSL, "
            "insecure file operations, and 50+ OWASP Mobile patterns. "
            "Results include OWASP Mobile and MASVS references, CWE mappings, "
            "and code-level evidence. Cached by APK hash. "
            "3-minute timeout budget across decompilation + scan."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "app_name": {
                    "type": "string",
                    "description": (
                        "App directory name (e.g. 'Settings', 'Chrome') — "
                        "searched in standard Android app directories"
                    ),
                },
                "path": {
                    "type": "string",
                    "description": (
                        "Direct firmware path to the APK file "
                        "(e.g. /system/app/Settings/Settings.apk)"
                    ),
                },
                "min_severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "description": "Minimum severity to include in output (default: info)",
                },
                "force_rescan": {
                    "type": "boolean",
                    "description": "Skip cache and force a fresh scan (default: false)",
                },
            },
        },
        handler=_handle_scan_apk_sast,
    )


# ---------------------------------------------------------------------------
# APK resolution helper (shared via _android_helpers.py)
# ---------------------------------------------------------------------------


def _get_apk_rel_path(apk_path: str, extracted_root: str) -> str:
    """Get the firmware-relative path for display and priv-app detection."""
    try:
        return os.path.relpath(apk_path, extracted_root)
    except ValueError:
        return os.path.basename(apk_path)


# ---------------------------------------------------------------------------
# Tool handler
# ---------------------------------------------------------------------------


async def _handle_scan_apk_sast(input: dict, context: ToolContext) -> str:
    """Run the full jadx+mobsfscan SAST pipeline on an APK."""
    from app.services.mobsfscan_service import (
        get_mobsfscan_pipeline,
        mobsfscan_available,
    )

    # Pre-flight: check mobsfscan availability
    if not mobsfscan_available():
        return (
            "mobsfscan is not installed in this environment. "
            "Install with: pip install mobsfscan\n"
            "The SAST pipeline requires mobsfscan for source code analysis."
        )

    # Resolve APK path
    try:
        apk_path = find_apk(context, input.get("app_name"), input.get("path"))
    except ValueError as exc:
        return str(exc)

    min_severity = input.get("min_severity", "info")
    force_rescan = input.get("force_rescan", False)

    apk_rel_path = _get_apk_rel_path(apk_path, context.extracted_path)

    # Resolve firmware context for finding enrichment
    fw_ctx = None
    if context.db and context.firmware_id:
        try:
            from app.utils.firmware_context import get_firmware_context

            fw_ctx = await get_firmware_context(
                context.db, context.firmware_id,
                apk_path=apk_path,
                extracted_root=context.extracted_path,
            )
        except Exception as exc:
            logger.debug("Failed to resolve firmware context: %s", exc)

    # Run the pipeline (3-minute budget enforced internally)
    pipeline = get_mobsfscan_pipeline()

    try:
        result = await pipeline.scan_apk(
            apk_path=apk_path,
            firmware_id=context.firmware_id,
            project_id=context.project_id,
            db=context.db,
            apk_rel_path=apk_rel_path,
            min_severity=min_severity,
            persist=True,
            use_cache=not force_rescan,
            fw_ctx=fw_ctx,
        )
    except FileNotFoundError as exc:
        return f"APK not found: {exc}"
    except TimeoutError as exc:
        return (
            f"Pipeline timed out: {exc}\n\n"
            "The 3-minute budget was exhausted. This APK may be too large "
            "for the configured timeout. Try scanning with a longer timeout "
            "via the REST API, or check if JADX is available and working."
        )
    except RuntimeError as exc:
        return f"Pipeline error: {exc}"
    except Exception as exc:
        logger.exception(
            "Unexpected error in SAST pipeline for %s", apk_rel_path,
        )
        return f"Unexpected error during SAST scan: {exc}"

    # Return truncated text output (30KB max enforced by truncation.py)
    output = result.text_output

    # Prepend firmware context summary for the AI assistant
    if fw_ctx and not fw_ctx.is_empty:
        ctx_summary = fw_ctx.summary_line()
        if ctx_summary:
            output = f"Firmware: {ctx_summary}\n{output}"

    if result.cached:
        output = f"[CACHED RESULT]\n{output}"

    return truncate_output(output)
