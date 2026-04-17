"""ELF-wrapped TEE parser (OP-TEE TAs primarily).

Handles classifier format ``optee_ta``.  OP-TEE Trusted Applications are
PIE ELF shared objects with a ``.ta_head`` section containing a 16-byte
UUID followed by header fields.  OP-TEE TAs are signed by convention with
RSA-SHA256 using the build-time TA signing key.

If the file is an ELF without ``.ta_head`` we still return successfully
and note it's "ELF TEE (not OP-TEE)" — the detector may have classified
optimistically.

We attempt to extract a TA version from the ``TA_VERSION=`` string if the
TA built with ``-DTA_VERSION=…``.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser

logger = logging.getLogger(__name__)

_VERSION_RES = (
    re.compile(rb"TA_VERSION\s*=\s*([A-Za-z0-9_.\-]+)"),
    re.compile(rb"ta_version\s*=\s*([A-Za-z0-9_.\-]+)"),
    re.compile(rb"VERSION_STRING\s*=\s*([A-Za-z0-9_.\-]+)"),
)

_UUID_STR_RE = re.compile(rb"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})")


def _format_uuid(raw: bytes) -> str | None:
    """Format 16 bytes as a RFC 4122 UUID string (big-endian layout).

    OP-TEE TA UUIDs are stored in host byte order; we format as-is (big-endian
    since the bytes are the canonical representation in the TEE_UUID struct).
    """
    if len(raw) < 16:
        return None
    try:
        # Canonical: 8-4-4-4-12 formatting.
        hex_ = raw[:16].hex()
        return f"{hex_[0:8]}-{hex_[8:12]}-{hex_[12:16]}-{hex_[16:20]}-{hex_[20:32]}"
    except Exception:  # noqa: BLE001
        return None


def _scan_version(data: bytes) -> str | None:
    for rx in _VERSION_RES:
        m = rx.search(data)
        if m:
            try:
                return m.group(1).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue
    return None


class OpteeTaParser:
    """Parser for OP-TEE TA ELF shared objects."""

    FORMAT = "optee_ta"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {}
        version: str | None = None
        signed: str = "unknown"
        signature_algorithm: str | None = None
        cert_subject: str | None = None

        try:
            if len(magic) < 4 or magic[:4] != b"\x7fELF":
                meta["note"] = "not an ELF — optee_ta parser skipped"
                return ParsedBlob(metadata=meta)

            try:
                import lief  # type: ignore
            except Exception as exc:  # noqa: BLE001
                return ParsedBlob(metadata={"error": f"lief import: {exc}"})

            try:
                binary = lief.parse(path)
            except Exception as exc:  # noqa: BLE001
                return ParsedBlob(metadata={"error": f"lief parse: {exc}"})
            if binary is None:
                return ParsedBlob(metadata={"error": "lief returned None"})

            # Find .ta_head
            ta_head_bytes: bytes | None = None
            try:
                for sec in binary.sections:
                    if getattr(sec, "name", None) == ".ta_head":
                        content = bytes(sec.content)
                        ta_head_bytes = content
                        break
            except Exception as exc:  # noqa: BLE001
                meta["note"] = f"section iteration failed: {exc}"

            try:
                meta["entry_point"] = hex(int(binary.entrypoint))
            except Exception:  # noqa: BLE001
                pass

            if ta_head_bytes:
                # First 16 bytes of .ta_head is the TA UUID.
                uuid_str = _format_uuid(ta_head_bytes[:16])
                if uuid_str:
                    meta["ta_uuid"] = uuid_str
                signed = "signed"
                signature_algorithm = "RSA-SHA256"
                cert_subject = "OP-TEE TA Signing"
            else:
                meta["note"] = "ELF TEE (not OP-TEE)"

            # Version scan: load the file bytes (capped) and look for TA_VERSION=.
            try:
                with open(path, "rb") as f:
                    head = f.read(min(size, 2 * 1024 * 1024))
            except OSError:
                head = b""
            if head:
                v = _scan_version(head)
                if v:
                    version = v

                # Best-effort secondary UUID string match (some TAs embed as
                # a string symbol — nice to have alongside .ta_head).
                if "ta_uuid" not in meta:
                    m = _UUID_STR_RE.search(head)
                    if m:
                        try:
                            meta["ta_uuid_string_match"] = m.group(1).decode("ascii")
                        except Exception:  # noqa: BLE001
                            pass

        except Exception as exc:  # noqa: BLE001
            logger.debug("OpteeTaParser failed on %s: %s", path, exc)
            meta["error"] = str(exc)

        return ParsedBlob(
            version=version,
            signed=signed,
            signature_algorithm=signature_algorithm,
            cert_subject=cert_subject,
            metadata=meta,
        )


register_parser(OpteeTaParser())
