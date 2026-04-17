"""MediaTek preloader (GFH) parser.

Handles classifier format ``mtk_preloader``.  Preloaders carry the ``MMM``
magic (0x4D4D4D01) followed by a Generic File Header (GFH) chain.  The
first GFH record (``GFH_FILE_INFO``, type 0x0000) holds the load address,
file length, signature type, and ``file_ver`` ASCII version.

References:
    - cyrozap/mediatek-lte-baseband-re ``SoC/mediatek_preloader.ksy``
    - u-boot ``tools/mtk_image.c`` (``gfh_file_info`` struct)
    - bkerler/mtkclient ``mtk_preloader.py``

GFH_FILE_INFO layout (LE):

    0   3   magic ("MMM")
    3   1   version (u8)
    4   2   size    (u16)
    6   2   type    (u16, 0x0000 for GFH_FILE_INFO)
    8   4   id      (ASCII, e.g. "pm\\0\\0")
    12  1   flash_dev
    13  1   sig_type
    14  4   load_addr
    18  4   file_len
    22  4   max_size
    26  4   content_offset
    30  4   sig_len
    34  4   jump_offset
    38  4   attr
    42  8   file_ver (ASCII, e.g. "V1.0")
"""

from __future__ import annotations

import logging
import struct
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser

logger = logging.getLogger(__name__)


# The preloader header begins with "MMM\x01" at offset 0.  The GFH block
# follows at offset 8 in real-world MediaTek preloaders, per
# cyrozap/mediatek-lte-baseband-re.
_PRELOADER_MAGIC = b"MMM\x01"
_GFH_OFFSET_CANDIDATES = (8, 0)  # try 8 first (preloader wrapper), then 0
_GFH_FILE_INFO_STRUCT = struct.Struct("<3sBHH4sBBIIIIIII8s")
_GFH_FILE_INFO_SIZE = _GFH_FILE_INFO_STRUCT.size  # = 50
_GFH_TYPE_FILE_INFO = 0x0000


def _read_bytes(path: str, limit: int) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def _decode_ascii_nul(raw: bytes) -> str:
    """Decode an ASCII field stripping trailing NUL / whitespace."""
    nul = raw.find(b"\x00")
    if nul >= 0:
        raw = raw[:nul]
    try:
        return raw.decode("ascii", errors="replace").strip()
    except Exception:  # noqa: BLE001
        return ""


def _locate_gfh(data: bytes) -> int | None:
    """Return the byte offset of a valid GFH_FILE_INFO block, or None."""
    for off in _GFH_OFFSET_CANDIDATES:
        if off + _GFH_FILE_INFO_SIZE > len(data):
            continue
        try:
            magic3 = data[off : off + 3]
        except Exception:  # noqa: BLE001,S112 - bounds checked above, defensive only
            continue
        if magic3 != b"MMM":
            continue
        # gfh_type at offset+6 must be 0x0000 for FILE_INFO.
        try:
            (gfh_type,) = struct.unpack_from("<H", data, off + 6)
        except struct.error:
            continue
        if gfh_type == _GFH_TYPE_FILE_INFO:
            return off
    return None


class MediatekPreloaderParser:
    """Parser for MediaTek preloader images wrapped in a GFH block."""

    FORMAT = "mtk_preloader"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {}
        version: str | None = None
        signed: str = "unknown"

        try:
            data = _read_bytes(path, 512)
            if len(data) < 4:
                meta["error"] = "file too small for preloader header"
                return ParsedBlob(signed=signed, metadata=meta)

            if data[:4] != _PRELOADER_MAGIC:
                meta["error"] = f"bad magic {data[:4].hex()}, expected MMM\\x01"
                return ParsedBlob(signed=signed, metadata=meta)

            meta["magic"] = "MMM\\x01"

            gfh_off = _locate_gfh(data)
            if gfh_off is None:
                meta["note"] = "GFH_FILE_INFO record not found after MMM header"
                return ParsedBlob(signed=signed, metadata=meta)

            meta["gfh_offset"] = gfh_off
            (
                gfh_magic,
                gfh_version,
                gfh_size,
                gfh_type,
                file_id,
                flash_dev,
                sig_type,
                load_addr,
                file_len,
                max_size,
                content_offset,
                sig_len,
                jump_offset,
                attr,
                file_ver,
            ) = _GFH_FILE_INFO_STRUCT.unpack_from(data, gfh_off)

            meta["gfh_version"] = int(gfh_version)
            meta["gfh_size"] = int(gfh_size)
            meta["gfh_type"] = f"0x{gfh_type:04x}"
            meta["file_type"] = _decode_ascii_nul(file_id)
            meta["flash_dev"] = int(flash_dev)
            meta["sig_type"] = int(sig_type)
            meta["load_addr"] = f"0x{load_addr:08x}"
            meta["file_len"] = int(file_len)
            meta["max_size"] = int(max_size)
            meta["content_offset"] = int(content_offset)
            meta["sig_len"] = int(sig_len)
            meta["jump_offset"] = int(jump_offset)
            meta["attr"] = f"0x{attr:08x}"

            ver_str = _decode_ascii_nul(file_ver)
            if ver_str:
                version = ver_str
                meta["file_ver"] = ver_str

            # Signing: GFH sig_type nonzero or sig_len > 0 means the image
            # expects a signature check at BROM load.
            if int(sig_type) != 0 or int(sig_len) > 0:
                signed = "signed"
            else:
                signed = "unsigned"

            # Ignore magic bytes — we already know they're "MMM".
            _ = gfh_magic

        except Exception as exc:  # noqa: BLE001
            logger.debug("MediatekPreloaderParser failed on %s: %s", path, exc)
            meta["error"] = str(exc)

        return ParsedBlob(
            version=version,
            signed=signed,
            metadata=meta,
        )


register_parser(MediatekPreloaderParser())
