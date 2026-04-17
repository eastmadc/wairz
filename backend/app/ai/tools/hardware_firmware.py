"""Hardware firmware MCP tools — list detected modem/TEE/Wi-Fi/GPU/DSP blobs."""

from __future__ import annotations

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.hardware_firmware import HardwareFirmwareBlob


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
