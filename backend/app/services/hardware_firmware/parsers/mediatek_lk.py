"""MediaTek LK / partition-record parser.

Handles classifier format ``mtk_lk``. LK partition records begin with
``0x58881688`` (LE) at offset 0 and wrap a boot-chain blob (``lk``,
``logo``, ``md1rom``, ``spmfw``, ``atf``, ``gz``, ``cam_vpu1``, etc.).

Two header layouts coexist:

*   **Legacy (512-byte)** — 32-byte partition name at offset 0x20.
    U-Boot ``tools/mtk_image.c`` builds this on older MTK SoCs.
*   **Compact (16-byte)** — 8-byte partition name at offset 0x08, used
    on MT6785 / MT6853 / MT8788 / Genio-700 and later.  Same magic, but
    the legacy size/magic_version fields don't exist here — reading
    them returns fragments of the name string.  Wairz used to emit
    those fragments as "partition_size: 1915839597" nonsense; this
    parser refuses to synthesise fields that don't belong to the
    detected layout.

The partition name drives the Wairz category via
``mediatek_gfh.lookup_partition`` — ``atf`` is ``tee``, ``md1rom`` is
``modem``, ``cam_vpu1`` is ``camera``, etc.  The classifier consults
the same table so blobs don't end up stuck with the default
``bootloader`` tag.

Signing information lives in an embedded ``LK_FILE_INFO`` footer
(magic ``0x58891689``) or a trailing GFH chain.  We detect the
footer's presence as a best-effort ``signed`` hint but don't claim a
verdict we can't substantiate.

References:
    - U-Boot ``tools/mtk_image.c`` (GPL-2.0)
    - bkerler/mtkclient ``mtk_main.py`` / ``mtkimg.py`` (GPL-3.0)
    - cyrozap/mediatek-lte-baseband-re ``SoC/mediatek_preloader.ksy``
"""

from __future__ import annotations

import logging
import re
import struct
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser
from app.services.hardware_firmware.parsers.mediatek_gfh import (
    is_stub_descriptor,
    lookup_partition,
    parse_lk_header,
)

logger = logging.getLogger(__name__)


_LK_HEADER_READ = 64       # covers both compact (16) and the header portion of legacy
_VERSION_SCAN_BYTES = 8192

_VERSION_RES = (
    re.compile(rb"LK-([0-9][A-Za-z0-9._\-]+)"),
    re.compile(rb"(?:Little\s*Kernel|lk)\s*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
    re.compile(rb"BUILD_TIME=([0-9]{8,14})"),
)

_LK_FILE_INFO_MAGIC = 0x58891689


def _read_bytes(path: str, limit: int) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def _scan_version(data: bytes) -> str | None:
    for rx in _VERSION_RES:
        m = rx.search(data)
        if m:
            try:
                return m.group(1).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001,S112 — best-effort decode, try next regex
                continue
    return None


class MediatekLkParser:
    """Parser for MediaTek LK partition-record headers (magic 0x58881688)."""

    FORMAT = "mtk_lk"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {}
        version: str | None = None
        signed: str = "unknown"

        try:
            header = _read_bytes(path, _LK_HEADER_READ)
            hdr = parse_lk_header(header)
            if hdr is None:
                meta["error"] = "LK magic mismatch or header truncated"
                return ParsedBlob(signed=signed, metadata=meta)

            meta["magic"] = f"0x{0x58881688:08x}"
            meta["layout"] = hdr.layout
            if hdr.name:
                meta["partition_name"] = hdr.name

            # Map partition name to component/subcomponent tag for
            # downstream CVE matching. The classifier uses the same table
            # to set the row's category/vendor.
            dispatch = lookup_partition(hdr.name) if hdr.name else None
            if dispatch:
                category, component = dispatch
                meta["component"] = component
                meta["classified_category"] = category

            # Stub detection: modem.img / md1dsp.img on modem-less SKUs
            # are tiny scatter-config placeholders; the old parser
            # interpreted the name bytes as struct fields and emitted
            # ridiculous sizes (1.9 GB for a 528-byte file). Skip all
            # struct-field emission on stubs.
            if is_stub_descriptor(hdr.name, size):
                meta["stub_descriptor"] = True
                meta["note"] = (
                    "Partition placeholder — no firmware payload in this file. "
                    "Real payload lives in a sibling image (e.g. md1img.img) "
                    "or on-chip ROM; often absent on modem-less SKUs."
                )
                return ParsedBlob(version=None, signed="unknown", metadata=meta)

            # file_info_offset is the u32 at 0x04. Meaningful only when
            # it points inside the file; otherwise suppress to avoid the
            # same nonsense-field problem that burned us before.
            fio = hdr.file_info_offset
            if 16 <= fio < size:
                meta["file_info_offset"] = fio

            # Best-effort signing hint: LK_FILE_INFO magic (0x58891689)
            # presence at offset 0x30 in compact-layout headers indicates
            # the image carries the secondary descriptor block that
            # normally precedes signature metadata. Absence != unsigned;
            # presence != signed — leave as "unknown" without harder
            # evidence.
            if hdr.has_file_info_magic:
                meta["has_lk_file_info"] = True

            # Scan the payload for an LK_FILE_INFO magic and a plausible
            # sig_len field. When sig_len > 0 at offset +0x1E of the GFH
            # we can report signed=signed confidently.
            payload = _read_bytes(path, min(size, _VERSION_SCAN_BYTES))
            sig_hint = _probe_signed(payload)
            if sig_hint is not None:
                signed = sig_hint

            # Opportunistic version extraction from the payload
            v = _scan_version(payload)
            if v:
                version = v

        except Exception as exc:  # noqa: BLE001
            logger.debug("MediatekLkParser failed on %s: %s", path, exc)
            meta["error"] = str(exc)

        return ParsedBlob(
            version=version,
            signed=signed,
            metadata=meta,
        )


def _probe_signed(data: bytes) -> str | None:
    """Best-effort signing probe: find LK_FILE_INFO magic, then read the
    sig_type / sig_len at the known offsets inside the following struct.

    Returns "signed" when sig_type != 0 OR sig_len > 0, "unsigned" when
    both are explicitly zero, or None when we can't locate the record.
    """
    needle = struct.pack("<I", _LK_FILE_INFO_MAGIC)
    idx = data.find(needle)
    if idx < 0 or idx + 0x40 > len(data):
        return None
    # After LK_FILE_INFO magic, the second-tier record layout varies by
    # SoC; sig_type is commonly at +0x0D and sig_len at +0x1E (GFH
    # FILE_INFO-compatible). Do a conservative read with bounds check
    # and only report a positive verdict.
    try:
        sig_type = data[idx + 0x0D]
        sig_len = int.from_bytes(data[idx + 0x1E : idx + 0x22], "little")
    except IndexError:
        return None
    if sig_type != 0 or sig_len > 0:
        return "signed"
    return None


register_parser(MediatekLkParser())
