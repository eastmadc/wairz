"""Kernel module (.ko) parser.

Reads the ``.modinfo`` ELF section (NUL-separated ``key=value`` strings)
and the optional appended CMS signature magic ``~Module signature appended~``
to classify as ``signed`` / ``unknown``.

Extracts:

* ``license``, ``vermagic``, ``srcversion``, ``depends`` (list), ``alias``
  (list), and every ``firmware=<name>`` entry.
* ``version`` = the ``version`` field if present, else ``srcversion``.
* ``chipset_target`` — best-effort from ``vermagic`` / ``alias`` patterns.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser

logger = logging.getLogger(__name__)


# Magic that ``modinfo`` / kmod use to detect an appended CMS signature.
_MODSIG_MAGIC = b"~Module signature appended~"
_MODSIG_TAIL_BYTES = 256

# Chipset indicators commonly seen in vermagic / alias strings.
_CHIPSET_RES = (
    re.compile(r"(sm[0-9]{3,4})", re.IGNORECASE),
    re.compile(r"(msm[0-9]{3,4})", re.IGNORECASE),
    re.compile(r"(sdm[0-9]{3,4})", re.IGNORECASE),
    re.compile(r"(exynos[0-9]{3,4})", re.IGNORECASE),
    re.compile(r"(mt[0-9]{3,4})", re.IGNORECASE),
    re.compile(r"(bcm[0-9]{3,5})", re.IGNORECASE),
)


def _parse_modinfo(data: bytes) -> list[tuple[str, str]]:
    """Split a ``.modinfo`` section into ``(key, value)`` pairs."""
    pairs: list[tuple[str, str]] = []
    for chunk in data.split(b"\x00"):
        if not chunk or b"=" not in chunk:
            continue
        try:
            text = chunk.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        if "=" not in text:
            continue
        key, _, value = text.partition("=")
        pairs.append((key.strip(), value.strip()))
    return pairs


def _infer_chipset(vermagic: str | None, aliases: list[str]) -> str | None:
    candidates: list[str] = []
    if vermagic:
        candidates.append(vermagic)
    candidates.extend(aliases)
    for s in candidates:
        if not s:
            continue
        for rx in _CHIPSET_RES:
            m = rx.search(s)
            if m:
                return m.group(1).lower()
    return None


def _has_appended_signature(path: str, size: int) -> bool:
    """Check the last ``_MODSIG_TAIL_BYTES`` bytes for the CMS appendix magic."""
    try:
        with open(path, "rb") as f:
            if size > _MODSIG_TAIL_BYTES:
                f.seek(size - _MODSIG_TAIL_BYTES)
            tail = f.read(_MODSIG_TAIL_BYTES)
    except OSError:
        return False
    return _MODSIG_MAGIC in tail


class KmodParser:
    """Parser for Linux ``.ko`` kernel modules."""

    FORMAT = "ko"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {}
        version: str | None = None
        signed: str = "unknown"
        signature_algorithm: str | None = None
        chipset_target: str | None = None

        try:
            from elftools.elf.elffile import ELFFile  # type: ignore
        except Exception as exc:  # noqa: BLE001
            return ParsedBlob(signed="unknown", metadata={"error": f"pyelftools import: {exc}"})

        try:
            with open(path, "rb") as f:
                try:
                    elf = ELFFile(f)
                except Exception as exc:  # noqa: BLE001
                    return ParsedBlob(
                        signed="unknown",
                        metadata={"error": f"ELFFile parse: {exc}"},
                    )

                section = elf.get_section_by_name(".modinfo")
                if section is None:
                    meta["note"] = ".modinfo section missing"
                else:
                    data = section.data()
                    pairs = _parse_modinfo(data)
                    license_val: str | None = None
                    vermagic: str | None = None
                    srcversion: str | None = None
                    version_raw: str | None = None
                    depends: list[str] = []
                    aliases: list[str] = []
                    firmware_deps: list[str] = []
                    for key, value in pairs:
                        if key == "license":
                            license_val = value
                        elif key == "vermagic":
                            vermagic = value
                        elif key == "srcversion":
                            srcversion = value
                        elif key == "version":
                            version_raw = value
                        elif key == "depends":
                            depends.extend(v for v in value.split(",") if v)
                        elif key == "alias":
                            aliases.append(value)
                        elif key == "firmware":
                            firmware_deps.append(value)
                    version = version_raw or srcversion
                    chipset_target = _infer_chipset(vermagic, aliases)
                    meta.update(
                        {
                            "license": license_val,
                            "vermagic": vermagic,
                            "srcversion": srcversion,
                            "depends": depends,
                            "alias": aliases,
                            "firmware_deps": firmware_deps,
                            "version_raw": version_raw,
                        }
                    )
        except Exception as exc:  # noqa: BLE001
            logger.debug("KmodParser failed on %s: %s", path, exc)
            meta["error"] = str(exc)

        # Detect appended CMS signature.
        if _has_appended_signature(path, size):
            signed = "signed"
            signature_algorithm = "CMS (kernel module)"

        return ParsedBlob(
            version=version,
            signed=signed,
            signature_algorithm=signature_algorithm,
            chipset_target=chipset_target,
            metadata=meta,
        )


register_parser(KmodParser())
