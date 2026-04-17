"""Awinic ACF (Acoustic Calibration File) parser.

Handles classifier format ``awinic_acf``.  ACF files are consumed by the
kernel ``sound/soc/codecs/aw88*`` drivers via ``aw_dev_load_cfg_by_hdr()``
and carry per-profile tuning data for AW88-series smart audio amplifiers.

Synthesized header layout (consistent with the Awinic driver header
structures — exact byte offsets vary by driver version so we probe a few):

    0   6   "AWINIC" ASCII magic
    6   4   version  (u32 LE; 0x0001 = v1, 0x0002 = v2)
    10  8   chip_id  (ASCII, e.g. "aw88266\\0")
    18  4   profile_count (u32 LE)
    …       profile records (not parsed)

On mismatched magic we fall through to a "magic_mismatch" metadata note
instead of raising.  The parser NEVER throws.
"""

from __future__ import annotations

import logging
import re
import struct
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser

logger = logging.getLogger(__name__)


_MAGIC = b"AWINIC"
_HEADER_BYTES = 64  # read the first 64 bytes — more than enough for header probe.
_SCAN_BYTES = 4 * 1024  # for chip-id / version fallbacks

_CHIP_ID_RE = re.compile(rb"(aw88[0-9a-z]+)")
_VERSION_STR_RE = re.compile(rb"(?:VERSION|version)[:=\s]*([0-9]+(?:\.[0-9]+){0,3})")


def _read_bytes(path: str, limit: int) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def _decode_cstr(raw: bytes) -> str:
    nul = raw.find(b"\x00")
    if nul >= 0:
        raw = raw[:nul]
    try:
        return raw.decode("ascii", errors="replace").strip()
    except Exception:  # noqa: BLE001
        return ""


class AwinicAcfParser:
    """Parser for Awinic AW88-series Acoustic Calibration File blobs."""

    FORMAT = "awinic_acf"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {}
        version: str | None = None
        chipset_target: str | None = None

        try:
            header = _read_bytes(path, _HEADER_BYTES)
            if len(header) < 6:
                meta["error"] = "file too small for ACF header"
                return ParsedBlob(signed="unknown", metadata=meta)

            if header[:6] != _MAGIC:
                # Graceful fallback: scan for an aw88xxx chip id in the tail
                # so we still emit useful metadata.
                meta["magic_mismatch"] = header[:16].hex()
                scan = _read_bytes(path, min(size or _SCAN_BYTES, _SCAN_BYTES))
                m = _CHIP_ID_RE.search(scan)
                if m:
                    try:
                        chipset_target = m.group(1).decode("ascii", errors="replace")
                        meta["chip_id"] = chipset_target
                    except Exception:  # noqa: BLE001,S110 - best-effort decode
                        pass
                return ParsedBlob(
                    version=version,
                    signed="unknown",
                    chipset_target=chipset_target,
                    metadata=meta,
                )

            meta["magic"] = "AWINIC"

            if len(header) >= 10:
                try:
                    (acf_version,) = struct.unpack_from("<I", header, 6)
                    meta["acf_version"] = acf_version
                    version = str(acf_version)
                except struct.error:
                    pass

            if len(header) >= 18:
                chip_id = _decode_cstr(header[10:18])
                # chip_id looks like "aw88266" / "aw883xx"; validate
                # before reporting — the header field MAY be zeroed on
                # older driver revisions.
                if chip_id and chip_id.lower().startswith("aw"):
                    meta["chip_id"] = chip_id
                    chipset_target = chip_id
                else:
                    # Fallback: scan the file for an aw88xxx token.
                    scan = _read_bytes(path, min(size or _SCAN_BYTES, _SCAN_BYTES))
                    m = _CHIP_ID_RE.search(scan)
                    if m:
                        try:
                            chipset_target = m.group(1).decode("ascii", errors="replace")
                            meta["chip_id"] = chipset_target
                        except Exception:  # noqa: BLE001,S110 - best-effort decode
                            pass

            if len(header) >= 22:
                try:
                    (profile_count,) = struct.unpack_from("<I", header, 18)
                    # Sanity cap: some headers pack garbage into this slot
                    # on older driver revs — ignore obviously-bogus values.
                    if 0 < profile_count <= 1024:
                        meta["profile_count"] = profile_count
                except struct.error:
                    pass

        except Exception as exc:  # noqa: BLE001
            logger.debug("AwinicAcfParser failed on %s: %s", path, exc)
            meta["error"] = str(exc)

        return ParsedBlob(
            version=version,
            signed="unknown",
            chipset_target=chipset_target,
            metadata=meta,
        )


register_parser(AwinicAcfParser())
