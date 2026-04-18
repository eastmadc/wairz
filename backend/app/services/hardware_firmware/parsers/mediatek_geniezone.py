"""MediaTek GenieZone hypervisor (EL2) parser.

Handles classifier format ``mtk_geniezone``. Input begins with the outer
LK container header (``0x58881688``, partition name ``gz``). The payload
is raw AArch64 EL2 code — no inner wrapper, first instruction at payload
byte 0.

What we extract:

- Version banner: ``GZ_hypervisor: 3.2.1.004.V0MP1, Built: Dec 12 2025``
- Matching inner components: ``GZ_CORE_hypervisor`` + ``mTEE_SDK`` banners
- Platform tree reference (``geniezone/platform/common/platform_common.c``)
- Ghidra import params (AARCH64 at ``BL32_BASE`` / ``GZ_LOAD_BASE``)

**CVE-2025-20707 (GenieZone UAF, MSV-3820)** is fingerprint-checkable from
the banner alone:

- Fix landed in MediaTek's February 2026 Product Security Bulletin.
- Patched builds carry GenieZone ``≥ 3.2.2.x`` OR build-date ``>= 2026-02-01``.
- Older builds (like the DPCS10 ``3.2.1.004 / Dec 12 2025`` sample) are
  flagged by populating ``device_metadata["known_vulnerabilities"]``.

This is a concrete, version-pinned CVE match that doesn't depend on the
CVE matcher's bulletin YAML — it ships with the parser.

References:
    - MediaTek PSB September 2025 (original disclosure)
    - MediaTek PSB February 2026 (fix)
    - NVD CVE-2025-20707 (Medium, CWE-416)
"""

from __future__ import annotations

import datetime as _dt
import logging
import re
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser
from app.services.hardware_firmware.parsers.mediatek_gfh import (
    derive_chipset,
    signed_from_subimages,
    walk_sub_images,
)

logger = logging.getLogger(__name__)


_GZ_BANNER_RE = re.compile(
    rb"GZ_hypervisor:\s*(\d+\.\d+\.\d+\.\d+)(?:\.\w+)?"
    rb",\s*Built:\s*([\d:]+\s+\w+\s+\d+\s+\d{4})",
)
_GZ_CORE_RE = re.compile(rb"GZ_CORE_hypervisor:\s*(\d+\.\d+\.\d+\.\d+)(?:\.\w+)?")
_MTEE_RE = re.compile(rb"mTEE_SDK:\s*(\d+\.\d+\.\d+\.\d+)(?:\.\w+)?")
_PLAT_RE = re.compile(rb"(?:vendor/)?mediatek/geniezone/[^\x00]{0,160}")

# CVE-2025-20707 patched threshold.
_CVE_20707_PATCH_VERSION = (3, 2, 2)
_CVE_20707_PATCH_DATE = _dt.date(2026, 2, 1)

# Typical MediaTek GZ load address on Helio P60 / Genio 700.
# The authoritative value is in the GFH extension (not yet parsed).
_GZ_DEFAULT_BASE = 0xBFE00000


def _read_payload(path: str, limit: int = 8 * 1024 * 1024) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def _parse_built_date(s: str) -> _dt.date | None:
    """Parse TF-A / GZ ``Built`` timestamp like ``17:57:43 Dec 12 2025``.

    Returns the date portion only; time-of-day is discarded.
    """
    parts = s.strip().split()
    # Expected: ['HH:MM:SS', 'Mon', 'DD', 'YYYY']
    if len(parts) < 4:
        return None
    mon_str, day_str, year_str = parts[-3], parts[-2], parts[-1]
    try:
        return _dt.datetime.strptime(
            f"{mon_str} {day_str} {year_str}", "%b %d %Y",
        ).date()
    except ValueError:
        return None


def _is_vulnerable_20707(version: str, built: _dt.date | None) -> bool:
    """True when this GenieZone build is susceptible to CVE-2025-20707."""
    try:
        major, minor, patch = tuple(int(x) for x in version.split(".")[:3])
    except (ValueError, IndexError):
        return False
    if (major, minor, patch) >= _CVE_20707_PATCH_VERSION:
        return False
    if built is not None and built >= _CVE_20707_PATCH_DATE:
        return False
    return True


class MediatekGenieZoneParser:
    """Parser for MediaTek GenieZone hypervisor blobs."""

    FORMAT = "mtk_geniezone"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {"component": "geniezone", "runtime": "geniezone_el2"}
        version: str | None = None

        data = _read_payload(path)
        if not data:
            meta["error"] = "unable to read file"
            return ParsedBlob(metadata=meta)

        subimages = walk_sub_images(data)
        meta["sub_images"] = [
            {"name": s.name, "offset": s.offset, "size": s.payload_size,
             "is_signature": s.is_signature}
            for s in subimages
        ]

        primary = next((s for s in subimages if not s.is_signature), None)
        if primary is None:
            meta["error"] = "no primary payload found"
            return ParsedBlob(metadata=meta)

        payload = data[primary.payload_offset : primary.payload_offset + primary.payload_size]
        search_window = payload[: 2 * 1024 * 1024]

        built_date: _dt.date | None = None
        m = _GZ_BANNER_RE.search(search_window)
        if m:
            version = m.group(1).decode("ascii", errors="replace")
            built_str = m.group(2).decode("ascii", errors="replace")
            meta["gz_hypervisor_version"] = version
            meta["gz_hypervisor_build"] = built_str
            built_date = _parse_built_date(built_str)
            if built_date is not None:
                meta["gz_hypervisor_build_date"] = built_date.isoformat()

        core = _GZ_CORE_RE.search(search_window)
        if core:
            meta["gz_core_version"] = core.group(1).decode("ascii", errors="replace")

        mtee = _MTEE_RE.search(search_window)
        if mtee:
            meta["mtee_sdk_version"] = mtee.group(1).decode("ascii", errors="replace")

        plat = _PLAT_RE.search(search_window)
        if plat:
            meta["platform_source"] = plat.group(0).decode("ascii", errors="replace")

        # CVE-2025-20707 fingerprint — ships with the parser, no bulletin
        # YAML required. Patched: GZ >= 3.2.2.x OR build >= 2026-02-01.
        known_vulns: list[dict] = []
        if version and _is_vulnerable_20707(version, built_date):
            known_vulns.append({
                "cve_id": "CVE-2025-20707",
                "severity": "medium",
                "cwe": "CWE-416",
                "subcomponent": "geniezone",
                "confidence": "high",
                "source": "parser_version_pin",
                "rationale": (
                    f"GZ_hypervisor {version} built {built_date.isoformat() if built_date else 'unknown'} "
                    f"predates MediaTek February 2026 PSB fix (patched: >= 3.2.2 "
                    f"OR build-date >= 2026-02-01)."
                ),
                "reference": (
                    "https://corp.mediatek.com/product-security-bulletin/September-2025"
                ),
            })
        if known_vulns:
            meta["known_vulnerabilities"] = known_vulns

        # Ghidra import params
        meta["ghidra_import_params"] = {
            "processor": "AARCH64:LE:64:v8A",
            "loader": "BinaryLoader",
            "base_addr": _GZ_DEFAULT_BASE,
            "entry_point": _GZ_DEFAULT_BASE,
            "load_offset_in_file": primary.payload_offset,
            "load_length": primary.payload_size,
            "notes": "GZ_DEFAULT_BASE on Helio P60 / Genio 700; verify via GFH maddr",
        }

        return ParsedBlob(
            version=version,
            signed=signed_from_subimages(subimages),
            metadata=meta,
            chipset_target=derive_chipset(meta),
        )


register_parser(MediatekGenieZoneParser())
