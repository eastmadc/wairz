"""Android APK analysis AI tools.

Tools for deep analysis of Android APK files found in firmware using
Androguard: permissions, components, signatures, and security checks.
"""

import asyncio
import os

from app.ai.tool_registry import ToolContext, ToolRegistry


def register_android_tools(registry: ToolRegistry) -> None:
    """Register all Android APK analysis tools with the given registry."""

    registry.register(
        name="analyze_apk",
        description=(
            "Deep-analyse an Android APK file found in the firmware. "
            "Returns package name, SDK versions, permissions, activities, "
            "services, receivers, providers, and signature info. "
            "Accepts an app name (looked up in system/app, system/priv-app, etc.) "
            "or a direct path to the APK file."
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
                    "description": "Direct firmware path to the APK file (e.g. /system/app/Settings/Settings.apk)",
                },
            },
        },
        handler=_handle_analyze_apk,
    )

    registry.register(
        name="list_apk_permissions",
        description=(
            "List permissions declared by an Android APK with risk levels "
            "(dangerous, signature, normal). Useful for quick security "
            "assessment of an app's permission footprint."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "app_name": {
                    "type": "string",
                    "description": "App directory name (e.g. 'Settings')",
                },
                "path": {
                    "type": "string",
                    "description": "Direct firmware path to the APK file",
                },
            },
        },
        handler=_handle_list_apk_permissions,
    )

    registry.register(
        name="check_apk_signatures",
        description=(
            "Verify APK signing certificates and check for security issues: "
            "unsigned APKs, debug/test certificates, weak signature algorithms. "
            "Important for assessing firmware supply chain integrity."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "app_name": {
                    "type": "string",
                    "description": "App directory name (e.g. 'Settings')",
                },
                "path": {
                    "type": "string",
                    "description": "Direct firmware path to the APK file",
                },
            },
        },
        handler=_handle_check_apk_signatures,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_APK_DIRS = (
    "system/app",
    "system/priv-app",
    "product/app",
    "product/priv-app",
    "vendor/app",
)


def _find_apk(context: ToolContext, app_name: str | None, path: str | None) -> str:
    """Resolve an APK path from either *app_name* or *path*.

    Returns the absolute filesystem path to the APK file, validated
    against the sandbox.

    Raises ``ValueError`` with a user-friendly message on failure.
    """
    if path:
        resolved = context.resolve_path(path)
        if os.path.isfile(resolved) and resolved.lower().endswith(".apk"):
            return resolved
        # Maybe they gave a directory — look for an APK inside
        if os.path.isdir(resolved):
            for fname in os.listdir(resolved):
                if fname.lower().endswith(".apk"):
                    return os.path.join(resolved, fname)
        raise ValueError(
            f"No APK file found at path: {path}. "
            "Provide a direct path to an .apk file or use app_name instead."
        )

    if app_name:
        for app_dir in _APK_DIRS:
            app_path = os.path.join(context.extracted_path, app_dir, app_name)
            if not os.path.isdir(app_path):
                continue
            for fname in os.listdir(app_path):
                if fname.lower().endswith(".apk"):
                    return os.path.join(app_path, fname)

        raise ValueError(
            f"App '{app_name}' not found in standard Android directories "
            f"({', '.join(_APK_DIRS)}). Use list_directory to browse the "
            "firmware or provide a direct path."
        )

    raise ValueError(
        "Provide either 'app_name' or 'path' to identify the APK to analyse."
    )


def _check_androguard() -> str | None:
    """Return an error message if androguard is not installed, else None."""
    try:
        import androguard  # noqa: F401
        return None
    except ImportError:
        return (
            "Androguard is not installed in this environment. "
            "Install it with: pip install androguard>=4.1.2\n"
            "APK analysis requires the androguard package."
        )


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


async def _handle_analyze_apk(input: dict, context: ToolContext) -> str:
    """Analyse an APK and return a formatted summary."""
    err = _check_androguard()
    if err:
        return err

    try:
        apk_path = _find_apk(context, input.get("app_name"), input.get("path"))
    except ValueError as exc:
        return str(exc)

    from app.services.androguard_service import AndroguardService

    svc = AndroguardService()
    loop = asyncio.get_event_loop()
    try:
        info = await loop.run_in_executor(None, svc.analyze_apk, apk_path)
    except Exception as exc:
        return f"Error analysing APK: {exc}"

    return _format_apk_analysis(info)


async def _handle_list_apk_permissions(input: dict, context: ToolContext) -> str:
    """List APK permissions with risk levels."""
    err = _check_androguard()
    if err:
        return err

    try:
        apk_path = _find_apk(context, input.get("app_name"), input.get("path"))
    except ValueError as exc:
        return str(exc)

    from app.services.androguard_service import AndroguardService

    svc = AndroguardService()
    loop = asyncio.get_event_loop()
    try:
        perms = await loop.run_in_executor(
            None, svc.get_permissions_with_risk, apk_path
        )
    except Exception as exc:
        return f"Error extracting permissions: {exc}"

    if not perms:
        return "This APK declares no permissions."

    dangerous = [p for p in perms if p["risk"] == "dangerous"]
    signature = [p for p in perms if p["risk"] == "signature"]
    normal = [p for p in perms if p["risk"] == "normal"]

    lines = [f"Permissions for APK ({len(perms)} total):\n"]

    if dangerous:
        lines.append(f"DANGEROUS ({len(dangerous)}):")
        for p in dangerous:
            lines.append(f"  - {p['permission']}")

    if signature:
        lines.append(f"\nSIGNATURE ({len(signature)}):")
        for p in signature:
            lines.append(f"  - {p['permission']}")

    if normal:
        lines.append(f"\nNORMAL ({len(normal)}):")
        for p in normal:
            lines.append(f"  - {p['permission']}")

    if dangerous:
        lines.append(
            f"\n{len(dangerous)} dangerous permission(s) require runtime "
            "user consent and have privacy/security implications."
        )
    if signature:
        lines.append(
            f"{len(signature)} signature-level permission(s) require "
            "platform signing key — elevated system privileges."
        )

    return "\n".join(lines)


async def _handle_check_apk_signatures(
    input: dict, context: ToolContext
) -> str:
    """Check APK signatures for security issues."""
    err = _check_androguard()
    if err:
        return err

    try:
        apk_path = _find_apk(context, input.get("app_name"), input.get("path"))
    except ValueError as exc:
        return str(exc)

    from app.services.androguard_service import AndroguardService

    svc = AndroguardService()
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, svc.check_signatures, apk_path)
    except Exception as exc:
        return f"Error checking signatures: {exc}"

    return _format_signature_check(result)


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


def _format_apk_analysis(info: dict) -> str:
    """Format the full APK analysis dict into readable text."""
    lines = [
        f"APK Analysis: {info['package']}\n",
        f"Package:         {info['package']}",
        f"Version name:    {info.get('version_name') or 'N/A'}",
        f"Version code:    {info.get('version_code') or 'N/A'}",
        f"Min SDK:         {info.get('min_sdk') or 'N/A'}",
        f"Target SDK:      {info.get('target_sdk') or 'N/A'}",
        f"Main activity:   {info.get('main_activity') or 'N/A'}",
        f"Signed:          {info.get('is_signed', False)}",
    ]

    # Permissions summary
    perms = info.get("permissions", [])
    from app.services.androguard_service import classify_permission

    dangerous = [p for p in perms if classify_permission(p) == "dangerous"]
    lines.append(f"\nPermissions: {len(perms)} total, {len(dangerous)} dangerous")
    if dangerous:
        lines.append("Dangerous permissions:")
        for p in dangerous[:15]:
            lines.append(f"  - {p}")
        if len(dangerous) > 15:
            lines.append(f"  ... and {len(dangerous) - 15} more")

    # Components
    for label, key in [
        ("Activities", "activities"),
        ("Services", "services"),
        ("Receivers", "receivers"),
        ("Providers", "providers"),
    ]:
        items = info.get(key, [])
        if items:
            lines.append(f"\n{label} ({len(items)}):")
            for item in items[:50]:
                lines.append(f"  - {item}")
            if len(items) > 50:
                lines.append(f"  ... and {len(items) - 50} more")

    # Signatures
    sigs = info.get("signatures", [])
    if sigs:
        lines.append(f"\nSignatures ({len(sigs)}):")
        for sig in sigs:
            debug_tag = " [DEBUG CERT]" if sig.get("is_debug") else ""
            lines.append(f"  Issuer:    {sig.get('issuer', 'N/A')}{debug_tag}")
            lines.append(f"  Subject:   {sig.get('subject', 'N/A')}")
            lines.append(f"  Algorithm: {sig.get('algorithm', 'N/A')}")
            lines.append(f"  Serial:    {sig.get('serial', 'N/A')}")
            if sig.get("not_before"):
                lines.append(f"  Validity:  {sig['not_before']} — {sig.get('not_after', 'N/A')}")

    return "\n".join(lines)


def _format_signature_check(result: dict) -> str:
    """Format signature check results."""
    lines = [
        f"Signature check: {result['package']}\n",
        f"Signed: {result['is_signed']}",
    ]

    sigs = result.get("signatures", [])
    if sigs:
        lines.append(f"\nCertificates ({len(sigs)}):")
        for sig in sigs:
            debug_tag = " [DEBUG]" if sig.get("is_debug") else ""
            lines.append(f"  Subject:   {sig.get('subject', 'N/A')}{debug_tag}")
            lines.append(f"  Issuer:    {sig.get('issuer', 'N/A')}")
            lines.append(f"  Algorithm: {sig.get('algorithm', 'N/A')}")
            lines.append(f"  Serial:    {sig.get('serial', 'N/A')}")
            if sig.get("not_before"):
                lines.append(f"  Validity:  {sig['not_before']} — {sig.get('not_after', 'N/A')}")

    warnings = result.get("warnings", [])
    if warnings:
        lines.append(f"\nSECURITY WARNINGS ({len(warnings)}):")
        for w in warnings:
            lines.append(f"  !! {w}")
    else:
        lines.append("\nNo security warnings — signatures look clean.")

    return "\n".join(lines)
