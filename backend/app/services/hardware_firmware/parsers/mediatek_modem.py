"""MediaTek MD1IMG modem image parser (md1img / md1dsp).

Handles classifier format ``mtk_modem``.  Native reimplementation of the
MD1IMG section-walker logic from NCC Group's ``mtk_bp`` — no kaitai / no
``md1imgpy`` dependency.

Layout overview (per NCC Group ``md1_extract.py`` + mt6577 u-boot refs):

    - "MD1IMG" ASCII magic appears within the first 0x200 bytes (offset
      0x48 on mt6577, varies on newer SoCs).
    - Following the magic, the file embeds a section table of
      (name[8], offset[u32], size[u32], reserved[u32]) tuples.  Actual
      record sizes vary by generation — we accept 12- and 20-byte
      entries and heuristically validate offset/size bounds.
    - Sections commonly present: ``md1rom``, ``md1drdi``, ``md1dsp``,
      ``cert_md``, ``debuginfo``.

We deliberately keep this parser permissive: bad entries are skipped,
never fatal.  Signing is per-section (handled elsewhere) so we keep
``signed="unknown"`` unless we hit an obvious "cert_md" section (which
indicates the image expects to be verified).
"""

from __future__ import annotations

import logging
import re
import struct
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser

logger = logging.getLogger(__name__)


_MAGIC = b"MD1IMG"
_MAGIC_SCAN_BYTES = 0x200
_METADATA_SCAN_BYTES = 4 * 1024
_MAX_SECTIONS = 32

# MediaTek AP chipset regex (MT followed by 4 digits).  We scan for this
# pattern inside the first 4 KB of metadata.
_CHIPSET_RE = re.compile(rb"\b(MT\d{4}[A-Za-z]?)\b")

# ASCII version token: "V1.2.3", "v1.2", "1.2.3.4" (with at least two dots).
_VERSION_RES = (
    re.compile(rb"\b([vV][0-9]+(?:\.[0-9]+){1,3})\b"),
    re.compile(rb"BUILD_ID\s*[:=]\s*([A-Za-z0-9._\-]+)"),
    re.compile(rb"md1rom_version\s*[:=]\s*([A-Za-z0-9._\-]+)"),
)


def _read_bytes(path: str, offset: int, limit: int) -> bytes:
    if limit <= 0:
        return b""
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            return f.read(limit)
    except OSError:
        return b""


def _decode_section_name(raw: bytes) -> str:
    """Decode an 8-byte section name; NUL-trim, reject non-ASCII entries."""
    nul = raw.find(b"\x00")
    if nul >= 0:
        raw = raw[:nul]
    try:
        s = raw.decode("ascii", errors="strict").strip()
    except Exception:  # noqa: BLE001
        return ""
    # Reject garbage: section names use alnum + [_-].
    if not s or not re.fullmatch(r"[A-Za-z0-9_\-]+", s):
        return ""
    return s


def _walk_sections(data: bytes, start: int, file_size: int) -> list[dict[str, Any]]:
    """Walk 20-byte or 12-byte section records starting at ``start``.

    MD1IMG section record observed in mt6577-era firmware:
        name    : char[8]   (NUL-padded, e.g. "md1rom\\0\\0")
        offset  : u32 LE
        size    : u32 LE
        reserved: 0-8 bytes (generation-dependent; 20-byte total is common)

    We opportunistically probe 20-byte and 12-byte strides; accept the
    first one that yields a plausible set of sections (each with
    offset + size <= file_size and non-empty name).
    """
    sections: list[dict[str, Any]] = []
    for stride in (20, 12):
        candidate: list[dict[str, Any]] = []
        cursor = start
        for _ in range(_MAX_SECTIONS):
            if cursor + stride > len(data):
                break
            name = _decode_section_name(data[cursor : cursor + 8])
            try:
                (section_offset, section_size) = struct.unpack_from("<II", data, cursor + 8)
            except struct.error:
                break
            if not name:
                # Either we've run out of sections or the stride is wrong.
                break
            # Boundary check: sections must fit inside the file.
            if section_offset == 0 and section_size == 0:
                break
            if section_size > file_size or section_offset > file_size:
                # Wrong stride — reset and try the next one.
                candidate = []
                break
            if section_offset + section_size > file_size:
                # Skip this malformed entry; keep parsing.
                cursor += stride
                continue
            candidate.append(
                {
                    "name": name,
                    "offset": int(section_offset),
                    "size": int(section_size),
                }
            )
            cursor += stride
        if candidate:
            return candidate
    return sections


class MediatekModemParser:
    """Parser for MediaTek md1img / md1dsp modem images."""

    FORMAT = "mtk_modem"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {}
        version: str | None = None
        chipset_target: str | None = None
        signed: str = "unknown"

        try:
            head = _read_bytes(path, 0, _MAGIC_SCAN_BYTES)
            if not head:
                meta["error"] = "empty file or read failed"
                return ParsedBlob(signed=signed, metadata=meta)

            magic_pos = head.find(_MAGIC)
            if magic_pos < 0:
                meta["note"] = "MD1IMG magic not found in first 0x200 bytes"
                return ParsedBlob(signed=signed, metadata=meta)

            meta["magic_offset"] = magic_pos

            # Read a broader window that includes the section table.
            window = _read_bytes(path, 0, _METADATA_SCAN_BYTES)

            # Section table starts right after the "MD1IMG" magic on most
            # MediaTek modems.  We try a couple of cursor offsets because
            # some variants insert a small type/version word before the
            # table.
            file_size = size if size > 0 else len(window)
            section_start_candidates = (magic_pos + len(_MAGIC), magic_pos + 0x20)
            sections: list[dict[str, Any]] = []
            for start in section_start_candidates:
                s = _walk_sections(window, start, file_size)
                if s:
                    sections = s
                    meta["section_table_offset"] = start
                    break

            if sections:
                meta["sections"] = sections
                meta["section_names"] = [s["name"] for s in sections]
                # cert_md presence indicates the modem expects a verified load.
                if any("cert" in s["name"].lower() for s in sections):
                    signed = "signed"

            # Scan the metadata window for chipset + version strings.
            m = _CHIPSET_RE.search(window)
            if m:
                try:
                    chipset_target = m.group(1).decode("ascii", errors="replace")
                except Exception:  # noqa: BLE001
                    chipset_target = None

            for rx in _VERSION_RES:
                vmatch = rx.search(window)
                if vmatch:
                    try:
                        version = vmatch.group(1).decode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001,S112 - best-effort decode, try next
                        continue
                    break

        except Exception as exc:  # noqa: BLE001
            logger.debug("MediatekModemParser failed on %s: %s", path, exc)
            meta["error"] = str(exc)

        return ParsedBlob(
            version=version,
            signed=signed,
            chipset_target=chipset_target,
            metadata=meta,
        )


register_parser(MediatekModemParser())
