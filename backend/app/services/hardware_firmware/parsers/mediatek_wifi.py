"""MediaTek Wi-Fi firmware header parser (mt76 / WIFI_RAM_CODE_*).

Handles classifier format ``mtk_wifi_hdr``.  Covers two file-format
flavours:

1. ``_hdr``-suffixed ROM patch files (MT7615, MT7921, MT7925, …): the
   first 64 bytes include a 14-digit ASCII build timestamp.

2. Non-``_hdr`` ``WIFI_RAM_CODE_MT<NNNN>.bin`` files: raw NDS32 payloads
   with no structured header.  For these we fall back to filename-based
   chipset detection (``MT(\\d{4})`` capture group) and scan the first
   and last 512 bytes for an embedded timestamp.

The parser NEVER throws.  If neither pattern matches we return an empty
ParsedBlob; the classifier still records the blob as "unknown-version".
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser

logger = logging.getLogger(__name__)


_HEAD_SCAN_BYTES = 0x200
_TAIL_SCAN_BYTES = 0x200

# Build timestamps embedded by mt76 build scripts: 14-digit ASCII
# YYYYMMDDHHMMSS sequence.  Anchored on word boundaries so we don't
# accidentally match random digit runs in code.
_TIMESTAMP_RE = re.compile(rb"\b(20\d{2}(?:0[1-9]|1[0-2])(?:[0-2]\d|3[01])[0-2]\d[0-5]\d[0-5]\d)\b")

# Filename chipset capture: MT followed by 4 digits (MT7615, MT7921, ...).
_FILENAME_CHIPSET_RE = re.compile(r"MT(\d{4})", re.IGNORECASE)

# ASCII build identifier strings mt76 firmware uses as secondary metadata
# (e.g. "CRC32:0xabc12345", "CHIP_VERSION:2").
_BUILD_ID_RE = re.compile(rb"(?:BUILD_ID|build_id|BID)\s*[:=]\s*([A-Za-z0-9._\-]+)")

# WMT-connsys chipset attribution (from knowledge/hw-firmware-phase2
# research): WIFI_RAM_CODE_MT6759 is actually the MT6759 connsys combo
# paired with AP family MT6763/6765/6771/6779.
_CONNSYS_PAIRING: dict[str, str] = {
    "6759": "MT6759 connectivity combo (paired with AP: MT6763/6765/6771/6779)",
    "6765": "MT6765",
    "6771": "MT6771",
    "6779": "MT6779",
}


def _read_head_tail(path: str, size: int) -> tuple[bytes, bytes]:
    """Read the first ``_HEAD_SCAN_BYTES`` and last ``_TAIL_SCAN_BYTES``."""
    head = b""
    tail = b""
    try:
        with open(path, "rb") as f:
            head = f.read(_HEAD_SCAN_BYTES)
            if size > _HEAD_SCAN_BYTES:
                seek_to = max(size - _TAIL_SCAN_BYTES, len(head))
                try:
                    f.seek(seek_to)
                    tail = f.read(_TAIL_SCAN_BYTES)
                except OSError:
                    tail = b""
    except OSError:
        pass
    return head, tail


def _find_timestamp(data: bytes) -> str | None:
    if not data:
        return None
    m = _TIMESTAMP_RE.search(data)
    if m:
        try:
            return m.group(1).decode("ascii", errors="replace")
        except Exception:  # noqa: BLE001
            return None
    return None


def _find_build_id(data: bytes) -> str | None:
    if not data:
        return None
    m = _BUILD_ID_RE.search(data)
    if m:
        try:
            return m.group(1).decode("ascii", errors="replace")
        except Exception:  # noqa: BLE001
            return None
    return None


def _chipset_from_filename(name: str) -> str | None:
    m = _FILENAME_CHIPSET_RE.search(name)
    if not m:
        return None
    return f"MT{m.group(1)}"


class MediatekWifiParser:
    """Parser for mt76 Wi-Fi firmware (ROM patches + WIFI_RAM_CODE blobs)."""

    FORMAT = "mtk_wifi_hdr"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {}
        version: str | None = None
        chipset_target: str | None = None

        try:
            fname = os.path.basename(path)
            lname = fname.lower()

            head, tail = _read_head_tail(path, size if size > 0 else 0)

            # 1. Locate a build timestamp — first in the head, then the tail.
            timestamp: str | None = None
            origin = None
            if head:
                timestamp = _find_timestamp(head)
                if timestamp:
                    origin = "header"
            if timestamp is None and tail:
                timestamp = _find_timestamp(tail)
                if timestamp:
                    origin = "trailer"
            if timestamp:
                meta["build_timestamp"] = timestamp
                meta["timestamp_origin"] = origin
                version = timestamp

            # 2. Build id fallback: some mt76 images embed BUILD_ID= string.
            build_id = _find_build_id(head) or _find_build_id(tail)
            if build_id:
                meta["build_id"] = build_id
                if version is None:
                    version = build_id

            # 3. Chipset attribution.
            #    Priority: filename (MT7921, MT7925, …) > connsys map.
            fname_chip = _chipset_from_filename(fname)
            if fname_chip:
                chipset_target = fname_chip
                meta["chipset_match_origin"] = "filename"
                # Connsys pairing enrichment for WMT combos.
                code = fname_chip[2:] if fname_chip.upper().startswith("MT") else ""
                if code in _CONNSYS_PAIRING and lname.startswith("wifi_ram_code_"):
                    meta["chipset_role"] = _CONNSYS_PAIRING[code]

            if "_hdr" in lname:
                meta["variant"] = "mt76_hdr"
            elif lname.startswith("wifi_ram_code_"):
                meta["variant"] = "wifi_ram_code"
            elif lname.startswith("mt76"):
                meta["variant"] = "mt76"

        except Exception as exc:  # noqa: BLE001
            logger.debug("MediatekWifiParser failed on %s: %s", path, exc)
            meta["error"] = str(exc)

        return ParsedBlob(
            version=version,
            signed="unknown",
            chipset_target=chipset_target,
            metadata=meta,
        )


register_parser(MediatekWifiParser())
