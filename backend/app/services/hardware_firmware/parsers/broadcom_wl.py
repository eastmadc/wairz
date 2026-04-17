"""Broadcom / Cypress Wi-Fi firmware parser (brcmfmac).

Handles classifier format ``fw_bcm``.  ``brcmfmac*.bin`` is raw ARM/Thumb code
with no ELF header; signed verification is absent (this is the documented
BroadPwn / Frankenstein attack surface — firmware is loaded over SDIO/PCIe).

We look for ASCII version strings embedded in the first 64 KB of the blob,
and note the presence of the paired NVRAM (``.txt``) and CLM (``.clm_blob``)
files alongside.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser

logger = logging.getLogger(__name__)


_SCAN_BYTES = 64 * 1024

# Patterns to match common Broadcom firmware version strings.
# Examples in the wild:
#   "wl0: Broadcom: Wireless LAN Driver version 7.35.180.11"
#   "Firmware: 4366c0-roml/pcie-ag-ext-..."
#   "Version: 7.35.180.11 (r693010)"
_VERSION_RES = (
    re.compile(
        rb"wl0:\s*Broadcom:\s*(?:[^\n]*?)"
        rb"(?:Wireless\s+LAN\s+Driver\s+)?"
        rb"(?:version|ver|Firmware\s+version)[:\s]+([A-Za-z0-9._\-]+)",
        re.IGNORECASE,
    ),
    re.compile(rb"Firmware\s+version[:\s]+([A-Za-z0-9._\-]+)", re.IGNORECASE),
    re.compile(rb"fw_version[:\s=]+([A-Za-z0-9._\-/]+)", re.IGNORECASE),
    re.compile(rb"brcmfmac.*?(?:version|ver)[:\s]+([A-Za-z0-9._\-]+)", re.IGNORECASE),
    re.compile(rb"Version[:\s]+([0-9]+(?:\.[0-9]+){2,3})"),
)

_CHIPSET_FROM_FILENAME = re.compile(r"^brcmfmac([0-9a-z]+)", re.IGNORECASE)


def _scan_version(data: bytes) -> str | None:
    for rx in _VERSION_RES:
        m = rx.search(data)
        if m:
            try:
                return m.group(1).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue
    return None


def _infer_chipset(filename: str) -> str | None:
    m = _CHIPSET_FROM_FILENAME.match(filename.lower())
    if not m:
        return None
    tag = m.group(1)
    # Heuristic: strip trailing suffix after first non-digit following digits
    # (e.g. "43430-sdio" → "43430").
    head = re.match(r"[0-9]+[a-z]?", tag)
    if head:
        return f"bcm{head.group(0)}"
    return f"bcm{tag}"


def _parse_nvram(txt_path: str) -> dict[str, Any]:
    """Extract nvram_version= and boardrev= from a paired .txt NVRAM file."""
    out: dict[str, Any] = {}
    try:
        with open(txt_path, encoding="utf-8", errors="replace") as f:
            data = f.read(256 * 1024)
    except OSError:
        return out
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if key in {"nvram_version", "boardrev", "vendid", "devid", "boardtype", "manfid"}:
            out[key] = val
    return out


class BroadcomWlParser:
    """Parses Broadcom ``brcmfmac*.bin`` Wi-Fi firmware blobs."""

    FORMAT = "fw_bcm"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {}
        version: str | None = None
        chipset_target: str | None = None

        try:
            # Read the scan window.
            try:
                with open(path, "rb") as f:
                    head = f.read(min(size, _SCAN_BYTES))
            except OSError:
                head = b""
            if head:
                version = _scan_version(head)
                if version:
                    meta["fw_version_raw"] = version

            # Paired NVRAM / CLM discovery.
            base, ext = os.path.splitext(path)
            nvram_path = f"{base}.txt"
            clm_path = f"{base}.clm_blob"
            nvram_present = os.path.isfile(nvram_path)
            clm_present = os.path.isfile(clm_path)
            meta["nvram_present"] = nvram_present
            meta["clm_blob_present"] = clm_present

            if nvram_present:
                nv_info = _parse_nvram(nvram_path)
                if nv_info:
                    meta["nvram"] = nv_info

            # Chipset from filename.
            fname = os.path.basename(path)
            chipset_target = _infer_chipset(fname)
            if chipset_target:
                meta["chipset_model"] = chipset_target.upper()

        except Exception as exc:  # noqa: BLE001
            logger.debug("BroadcomWlParser failed on %s: %s", path, exc)
            meta["error"] = str(exc)

        return ParsedBlob(
            version=version,
            signed="unsigned",
            chipset_target=chipset_target,
            metadata=meta,
        )


register_parser(BroadcomWlParser())
