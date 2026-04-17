"""Hardware firmware MCP tools.

Tools for inspecting detected modem / TEE / Wi-Fi / BT / GPU / DSP / kernel
firmware blobs from the current firmware.  Detection runs automatically
after extraction; Phase 2 adds per-format parsers that fill in version,
signing, chipset, and format-specific metadata.
"""

from __future__ import annotations

import json

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.services.hardware_firmware.cve_matcher import CveMatch


async def _handle_list_hardware_firmware(input: dict, context: ToolContext) -> str:
    """List detected hardware firmware blobs for the current firmware."""
    category = input.get("category")
    vendor = input.get("vendor")
    signed_only = bool(input.get("signed_only", False))

    stmt = select(HardwareFirmwareBlob).where(
        HardwareFirmwareBlob.firmware_id == context.firmware_id,
    )
    if category:
        stmt = stmt.where(HardwareFirmwareBlob.category == category)
    if vendor:
        stmt = stmt.where(HardwareFirmwareBlob.vendor == vendor)
    if signed_only:
        stmt = stmt.where(HardwareFirmwareBlob.signed == "signed")

    stmt = stmt.order_by(HardwareFirmwareBlob.category, HardwareFirmwareBlob.blob_path)
    result = await context.db.execute(stmt)
    blobs = result.scalars().all()

    if not blobs:
        return (
            "No hardware firmware detected for this firmware. "
            "If detection hasn't run yet, wait for the post-unpack detection task to complete."
        )

    lines = [f"# Hardware firmware blobs ({len(blobs)} total)"]
    by_category: dict[str, list[HardwareFirmwareBlob]] = {}
    for b in blobs:
        by_category.setdefault(b.category, []).append(b)

    for cat in sorted(by_category.keys()):
        group = by_category[cat]
        lines.append(f"\n## {cat} ({len(group)})")
        for b in group:
            size_kb = b.file_size // 1024
            v = b.vendor or "unknown"
            ver = f" v{b.version}" if b.version else ""
            lines.append(
                f"- `{b.blob_path}` - {v}/{b.format}{ver} - {size_kb} KB - {b.signed}"
            )
    return "\n".join(lines)


async def _handle_analyze_hardware_firmware(input: dict, context: ToolContext) -> str:
    """Return detailed per-blob analysis for a single detected hardware firmware path."""
    blob_path = input.get("blob_path")
    if not blob_path:
        return "Error: blob_path is required."

    stmt = select(HardwareFirmwareBlob).where(
        HardwareFirmwareBlob.firmware_id == context.firmware_id,
        HardwareFirmwareBlob.blob_path == blob_path,
    )
    result = await context.db.execute(stmt)
    blob = result.scalars().first()
    if blob is None:
        return f"No hardware firmware blob found at path: {blob_path}"

    lines = [
        f"# Hardware firmware: {blob.blob_path}",
        "",
        f"- **Category:** {blob.category}",
        f"- **Vendor:** {blob.vendor or 'unknown'}",
        f"- **Format:** {blob.format}",
        f"- **Size:** {blob.file_size:,} bytes",
        f"- **SHA-256:** `{blob.blob_sha256}`",
        f"- **Partition:** {blob.partition or '-'}",
    ]
    if blob.version:
        lines.append(f"- **Version:** {blob.version}")
    lines.append(f"- **Signed:** {blob.signed}")
    if blob.signature_algorithm:
        lines.append(f"- **Signature algorithm:** {blob.signature_algorithm}")
    if blob.cert_subject:
        lines.append(f"- **Signing cert subject:** `{blob.cert_subject}`")
    if blob.chipset_target:
        lines.append(f"- **Chipset target:** {blob.chipset_target}")

    lines.append(f"- **Detection source:** {blob.detection_source}")
    lines.append(f"- **Detection confidence:** {blob.detection_confidence}")

    md = blob.metadata_
    if md:
        lines.append("")
        lines.append("## Parser metadata")
        lines.append("")
        lines.append("```json")
        try:
            lines.append(json.dumps(md, indent=2, default=str, sort_keys=True))
        except (TypeError, ValueError):
            lines.append(str(md))
        lines.append("```")

    return "\n".join(lines)


async def _handle_list_firmware_drivers(input: dict, context: ToolContext) -> str:
    """Return the driver <-> firmware graph for the current firmware."""
    from app.services.hardware_firmware.graph import build_driver_firmware_graph

    pattern = input.get("module_pattern")
    result = await build_driver_firmware_graph(context.firmware_id, context.db)

    by_driver: dict[str, dict] = {}
    for e in result.edges:
        rec = by_driver.setdefault(
            e.driver_path,
            {
                "driver_path": e.driver_path,
                "fw_deps": [],
                "resolved": [],
                "unresolved": [],
            },
        )
        if e.firmware_blob_path:
            if e.firmware_name not in rec["fw_deps"]:
                rec["fw_deps"].append(e.firmware_name)
            if e.firmware_blob_path not in rec["resolved"]:
                rec["resolved"].append(e.firmware_blob_path)
        else:
            if e.firmware_name not in rec["unresolved"]:
                rec["unresolved"].append(e.firmware_name)

    if pattern:
        pat = pattern.lower()
        by_driver = {k: v for k, v in by_driver.items() if pat in k.lower()}

    if not by_driver:
        return (
            "No driver-firmware relationships detected. Either hardware "
            "firmware detection hasn't run, no kmod/DTB blobs were parsed, "
            "or no firmware_deps entries were found in .modinfo sections."
        )

    lines = [
        "# Driver -> Firmware Graph",
        "",
        f"- **Drivers:** {len(by_driver)}",
        f"- **Kmod drivers:** {result.kmod_drivers}",
        f"- **DTB sources:** {result.dtb_sources}",
        f"- **Unresolved firmware refs:** {result.unresolved_count}",
        "",
    ]
    for driver, rec in sorted(by_driver.items()):
        lines.append(f"## `{driver}`")
        if rec["resolved"]:
            lines.append("")
            lines.append("**Resolved:**")
            for r in rec["resolved"][:20]:
                lines.append(f"- `{r}`")
            if len(rec["resolved"]) > 20:
                lines.append(f"- _(+{len(rec['resolved']) - 20} more)_")
        if rec["unresolved"]:
            lines.append("")
            lines.append("**Unresolved (missing in image):**")
            for r in rec["unresolved"][:20]:
                lines.append(f"- {r}")
            if len(rec["unresolved"]) > 20:
                lines.append(f"- _(+{len(rec['unresolved']) - 20} more)_")
        lines.append("")
    return "\n".join(lines)


async def _handle_check_firmware_cves(input: dict, context: ToolContext) -> str:
    """Run the three-tier CVE matcher against all detected hw-firmware blobs."""
    from app.services.hardware_firmware.cve_matcher import match_firmware_cves

    force_rescan = bool(input.get("force_rescan", False))
    matches = await match_firmware_cves(
        context.firmware_id, context.db, force_rescan=force_rescan
    )

    if not matches:
        return (
            "No hardware firmware CVE matches. Either detection hasn't run, "
            "no blobs were classified/parsed, or none of them match curated "
            "CVE families.  Tier 3 (curated YAML) covers ~15 famous CVE "
            "families — modem, TEE, Wi-Fi, GPU, DSP, bootloader."
        )

    # Group by blob
    by_blob: dict[str, list[CveMatch]] = {}
    for m in matches:
        by_blob.setdefault(str(m.blob_id), []).append(m)

    lines = [
        f"# Hardware firmware CVE matches ({len(matches)} total across {len(by_blob)} blob(s))",
        "",
    ]
    for blob_id, group in by_blob.items():
        lines.append(f"## Blob `{blob_id}`")
        lines.append("")
        for m in group:
            sev = f"**{m.severity.upper()}**"
            cvss = f" (CVSS {m.cvss_score})" if m.cvss_score else ""
            tier = f"_{m.tier}_"
            conf = f"confidence={m.confidence}"
            lines.append(
                f"- {m.cve_id} · {sev}{cvss} · {tier} · {conf}"
            )
            lines.append(f"  {m.description.strip()[:200]}")
        lines.append("")
    return "\n".join(lines)


def register_hardware_firmware_tools(registry: ToolRegistry) -> None:
    """Register hardware firmware MCP tools with the given registry."""
    registry.register(
        name="list_hardware_firmware",
        description=(
            "List all detected hardware firmware blobs for the current firmware. "
            "Filter by category (modem/tee/wifi/bluetooth/gpu/dsp/camera/audio/sensor/"
            "touchpad/nfc/usb/display/fingerprint/dtb/kernel_module/bootloader/other), "
            "vendor (qualcomm/mediatek/samsung/broadcom/nvidia/imagination/arm/apple/"
            "cypress/unisoc/hisilicon/intel/realtek/unknown), or filter to only signed blobs."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Filter by category, e.g. 'modem' or 'tee'.",
                },
                "vendor": {
                    "type": "string",
                    "description": "Filter by vendor, e.g. 'qualcomm'.",
                },
                "signed_only": {
                    "type": "boolean",
                    "description": "Only include blobs with signed=signed.",
                },
            },
        },
        handler=_handle_list_hardware_firmware,
    )

    registry.register(
        name="analyze_hardware_firmware",
        description=(
            "Deep analysis of a single detected hardware firmware blob: parsed "
            "headers, version, signature algorithm, signing-cert subject, chipset "
            "target, and parser-specific metadata (MBN segments, DTB compatibles, "
            ".modinfo, etc.).  Use the blob_path returned by list_hardware_firmware."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "blob_path": {
                    "type": "string",
                    "description": (
                        "Absolute path to the blob inside the extracted firmware "
                        "(as reported by list_hardware_firmware)."
                    ),
                },
            },
            "required": ["blob_path"],
        },
        handler=_handle_analyze_hardware_firmware,
    )

    registry.register(
        name="list_firmware_drivers",
        description=(
            "Return the driver-firmware graph: kernel modules and device-tree "
            "sources with the firmware blobs they request via request_firmware(). "
            "Driver metadata comes from the .modinfo section (firmware= entries), "
            "DTB firmware-name properties, and vmlinux string scans. Unresolved "
            "references indicate missing firmware or incomplete extraction "
            "(also surface as 'Missing firmware' findings)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "module_pattern": {
                    "type": "string",
                    "description": (
                        "Optional substring filter on the driver path "
                        "(case-insensitive)."
                    ),
                },
            },
        },
        handler=_handle_list_firmware_drivers,
    )

    registry.register(
        name="check_firmware_cves",
        description=(
            "Run the three-tier CVE matcher against all detected hardware firmware "
            "blobs and return CVE matches. Results also persist to sbom_vulnerabilities "
            "with blob_id, match_tier (chipset_cpe|nvd_freetext|curated_yaml), and "
            "match_confidence (high|medium|low)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "force_rescan": {
                    "type": "boolean",
                    "description": (
                        "If true, re-run matching even for blobs that already "
                        "have persisted CVEs."
                    ),
                },
            },
        },
        handler=_handle_check_firmware_cves,
    )
