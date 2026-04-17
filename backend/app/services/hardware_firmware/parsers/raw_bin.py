"""Raw binary fallback parser.

Used for classified blobs whose format is ``raw_bin`` (Realtek Wi-Fi,
Broadcom BT HCD, various touch/fingerprint/NFC patches, etc.).  No
format-specific knowledge — we only compute entropy, extract ASCII
version candidates, and collect a handful of interesting strings.
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser

logger = logging.getLogger(__name__)


_ENTROPY_SCAN_BYTES = 1 * 1024 * 1024
_STRING_SCAN_BYTES = 2 * 1024 * 1024
_MIN_STRING_LEN = 6
_MAX_STRINGS = 50
_SHOW_STRINGS = 10

_VERSION_RES: tuple[re.Pattern[bytes], ...] = (
    re.compile(rb"VERSION_STRING\s*=\s*([A-Za-z0-9_.\-]+)"),
    re.compile(rb"version[:=\s]+([0-9]+(?:\.[0-9]+){1,3})", re.IGNORECASE),
    re.compile(rb"\bv([0-9]+(?:\.[0-9]+){1,3})\b"),
    re.compile(rb"Build[:\s]+(\S+)", re.IGNORECASE),
)

_PRINTABLE = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_STRING_LEN)


def _entropy(data: bytes) -> float:
    """Shannon entropy of the given byte-string, in bits per byte (0..8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def _scan_version(data: bytes) -> str | None:
    for rx in _VERSION_RES:
        m = rx.search(data)
        if m:
            try:
                return m.group(1).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue
    return None


def _extract_strings(data: bytes) -> list[str]:
    strings: list[str] = []
    for m in _PRINTABLE.finditer(data):
        try:
            strings.append(m.group(0).decode("ascii", errors="replace"))
        except Exception:  # noqa: BLE001
            continue
        if len(strings) >= _MAX_STRINGS:
            break
    return strings


class RawBinParser:
    """Generic fallback for unstructured firmware blobs."""

    FORMAT = "raw_bin"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {}
        version: str | None = None

        try:
            try:
                with open(path, "rb") as f:
                    entropy_chunk = f.read(min(size, _ENTROPY_SCAN_BYTES))
                    # Read the remainder up to the string scan cap (reuse the
                    # already-read prefix).
                    remainder = b""
                    if size > len(entropy_chunk) and _STRING_SCAN_BYTES > _ENTROPY_SCAN_BYTES:
                        to_read = min(size - len(entropy_chunk), _STRING_SCAN_BYTES - _ENTROPY_SCAN_BYTES)
                        remainder = f.read(to_read)
            except OSError as exc:
                return ParsedBlob(signed="unknown", metadata={"error": f"read failed: {exc}"})

            scan = entropy_chunk + remainder
            meta["entropy"] = round(_entropy(entropy_chunk), 3)

            version = _scan_version(scan)

            strings = _extract_strings(scan)
            if strings:
                meta["interesting_strings"] = strings[:_SHOW_STRINGS]
                meta["strings_sampled"] = len(strings)

            if meta["entropy"] > 7.5:
                meta["note"] = "High entropy — likely encrypted/compressed"

        except Exception as exc:  # noqa: BLE001
            logger.debug("RawBinParser failed on %s: %s", path, exc)
            meta["error"] = str(exc)

        return ParsedBlob(
            version=version,
            signed="unknown",
            metadata=meta,
        )


register_parser(RawBinParser())
