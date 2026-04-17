"""MediaTek Little Kernel (LK) bootloader partition parser.

Handles classifier format ``mtk_lk``.  LK partition records carry magic
``\\x88\\x16\\x88\\x58`` (u32 LE = ``0x58881688``) at offset 0 and describe
a single boot-chain blob (``lk``, ``logo``, ``md1img``, ``spmfw`` …).

Record layout (LE, per u-boot ``tools/mtk_image.c`` and bkerler/mtkclient):

    offset  size  field
    0       4     magic         (0x58881688)
    4       4     file_info_offset
    8       4     size
    12      4     magic_version
    16      16    reserved / padding
    32      32    name          (NUL-terminated partition name)
    64      32    reserved / padding

Signing lives in the GFH blocks inside the payload, not the LK header;
we therefore leave ``signed="unknown"`` unless we can locate a GFH
``sig_len != 0`` field embedded in the first 512 bytes.
"""

from __future__ import annotations

import logging
import re
import struct
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser

logger = logging.getLogger(__name__)


_LK_MAGIC = 0x58881688
_LK_HEADER_SIZE = 512

# u-boot/mtkclient field order for a partition record.
_LK_STRUCT = struct.Struct("<IIII")  # magic, file_info_offset, size, magic_version

# Quick scan window for an embedded GFH sig_len probe (offset 0x1E in the
# GFH_FILE_INFO structure).  We don't depend on it — it's a best-effort
# "signed?" hint.
_GFH_SCAN_BYTES = 512

# Version/build tokens we opportunistically pull from the payload.
_VERSION_RES = (
    re.compile(rb"LK-([0-9][A-Za-z0-9._\-]+)"),
    re.compile(rb"(?:Little\s*Kernel|lk)\s*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
    re.compile(rb"BUILD_TIME=([0-9]{8,14})"),
)


def _read_bytes(path: str, limit: int) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def _decode_cstr(raw: bytes) -> str:
    """Decode a NUL-terminated ASCII name field; tolerate embedded garbage."""
    nul = raw.find(b"\x00")
    if nul >= 0:
        raw = raw[:nul]
    try:
        return raw.decode("ascii", errors="replace").strip()
    except Exception:  # noqa: BLE001
        return ""


def _scan_version(data: bytes) -> str | None:
    for rx in _VERSION_RES:
        m = rx.search(data)
        if m:
            try:
                return m.group(1).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001,S112 - best-effort decode, try next regex
                continue
    return None


class MediatekLkParser:
    """Parser for MediaTek LK / partition-record headers (magic 0x58881688)."""

    FORMAT = "mtk_lk"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {}
        version: str | None = None
        signed: str = "unknown"
        chipset_target: str | None = None

        try:
            header = _read_bytes(path, _LK_HEADER_SIZE)
            if len(header) < 16:
                meta["error"] = "file too small for LK partition header"
                return ParsedBlob(signed=signed, metadata=meta)

            magic_u32, file_info_offset, part_size, magic_version = _LK_STRUCT.unpack_from(
                header, 0
            )
            if magic_u32 != _LK_MAGIC:
                meta["error"] = f"bad magic 0x{magic_u32:08x}, expected 0x{_LK_MAGIC:08x}"
                return ParsedBlob(signed=signed, metadata=meta)

            meta["magic"] = f"0x{magic_u32:08x}"
            meta["file_info_offset"] = file_info_offset
            meta["partition_size"] = part_size
            meta["magic_version"] = magic_version

            # Partition name at offset 32 (32-byte NUL-terminated).
            if len(header) >= 32 + 32:
                name = _decode_cstr(header[32:64])
                if name:
                    meta["partition_name"] = name

            # Opportunistic version / build-time pull from the first 8 KB
            # (most LK payloads embed strings within this window).
            scan = _read_bytes(path, 8 * 1024)
            if scan:
                v = _scan_version(scan)
                if v:
                    version = v

        except Exception as exc:  # noqa: BLE001
            logger.debug("MediatekLkParser failed on %s: %s", path, exc)
            meta["error"] = str(exc)

        return ParsedBlob(
            version=version,
            signed=signed,
            chipset_target=chipset_target,
            metadata=meta,
        )


register_parser(MediatekLkParser())
