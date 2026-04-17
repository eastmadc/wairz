"""Qualcomm PIL / MBN parser.

Handles the four formats the classifier emits for Qualcomm firmware:

- ``qcom_mbn``   — generic / umbrella format string (used for ELF+hash and
                   most single-file .mbn images).
- ``mbn_v3``     — legacy 40-byte MBN header with codeword ``0x844bdcd1`` and
                   magic ``0x73d71034`` (older SBL1-style).
- ``mbn_v5``     — newer 80-byte MBN2 header.
- ``mbn_v6``     — MBN header version 6 (SM8xxx-era).

Strategy
========

* If the file starts with ``\\x7fELF``: parse with LIEF.  Walk program headers
  looking for Qualcomm-specific segment types encoded in the top 8 bits of
  ``p_flags`` (mask ``0x07000000``):

  * ``0x02000000`` — QC hash-table segment
  * ``0x04000000`` — QC signature segment
  * ``0x05000000`` — QC cert-chain segment

  For the cert chain we read the segment bytes, walk DER-encoded X.509 certs
  one at a time, pick the leaf (the cert whose ``subject`` matches the
  ``issuer`` of no other cert in the chain) and report its RFC 4514 subject
  plus algorithm.

* Otherwise we treat the file as a raw MBN header and extract the 40-byte
  v3 header fields (``image_id``, ``image_size``, ``code_size``, ``sig_ptr``,
  ``sig_size``, ``cert_chain_ptr``, ``cert_chain_size``).

* Chipset detection: scan the first ~2 MB for common SoC model tokens
  (``MSM``/``SDM``/``SM####``) and store in ``chipset_target``; also save
  the QC_IMAGE_VERSION_STRING under ``metadata["qc_image_version_string"]``.
"""

from __future__ import annotations

import logging
import re
import struct
from typing import Any

from app.services.hardware_firmware.parsers.base import (
    PARSER_REGISTRY,
    ParsedBlob,
    register_parser,
)

logger = logging.getLogger(__name__)


# QC segment type bitmask (top byte-plus of p_flags).
_QC_SEG_MASK = 0x07000000
_QC_SEG_HASH = 0x02000000
_QC_SEG_SIG = 0x04000000
_QC_SEG_CERT = 0x05000000

# MBN v3 40-byte raw header.
# codeword (0x844bdcd1), magic (0x73d71034), image_id, ...
_MBN_V3_CODEWORD = 0x844BDCD1
_MBN_V3_MAGIC = 0x73D71034

# Bytes we read for generic chipset/version string scanning.
_SCAN_LIMIT = 2 * 1024 * 1024

# Cap on cert-chain bytes to parse (guards against mis-parsed segments).
_CERT_CHAIN_MAX = 256 * 1024

# Regex for chipset tokens, in rough priority order.
_CHIPSET_RES = (
    re.compile(rb"QC_IMAGE_VERSION_STRING\s*=\s*(\S+)"),
    re.compile(rb"(SM[0-9]{3,4}[A-Za-z0-9]*)"),
    re.compile(rb"(SDM[0-9]{3,4}[A-Za-z0-9]*)"),
    re.compile(rb"(MSM[0-9]{3,4}[A-Za-z0-9]*)"),
)

_VERSION_RES = (
    re.compile(rb"QC_IMAGE_VERSION_STRING\s*=\s*(\S+)"),
    re.compile(rb"MBN\.([A-Za-z0-9_.\-]+)"),
    re.compile(rb"SBL(\d+)\.([A-Za-z0-9_.\-]+)"),
)


def _safe_str(b: bytes) -> str | None:
    try:
        return b.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 — last-chance safety
        return None


def _scan_for_chipset_and_version(data: bytes) -> tuple[str | None, str | None, str | None]:
    """Return (chipset_target, version, qc_image_version_string).

    Runs regex searches over up to ``_SCAN_LIMIT`` bytes of the file.
    """
    qc_version_raw: str | None = None
    qc_match = _CHIPSET_RES[0].search(data)
    if qc_match:
        qc_version_raw = _safe_str(qc_match.group(1))

    chipset: str | None = None
    for rx in _CHIPSET_RES[1:]:
        m = rx.search(data)
        if m:
            chipset = _safe_str(m.group(1))
            if chipset:
                break
    # If chipset not found but QC_IMAGE_VERSION_STRING contains a model,
    # try to extract it.
    if chipset is None and qc_version_raw:
        for rx in _CHIPSET_RES[1:]:
            m = rx.search(qc_version_raw.encode("utf-8", errors="replace"))
            if m:
                chipset = _safe_str(m.group(1))
                break

    version: str | None = None
    for rx in _VERSION_RES:
        m = rx.search(data)
        if m:
            # Join groups if multiple captured (SBL\d+\.(\S+))
            if m.lastindex and m.lastindex >= 2:
                version = ".".join(_safe_str(m.group(i)) or "" for i in range(1, m.lastindex + 1))
            else:
                version = _safe_str(m.group(1))
            if version:
                break

    return chipset, version, qc_version_raw


def _parse_x509_chain(cert_bytes: bytes) -> tuple[str | None, str | None, list[dict[str, Any]]]:
    """Walk a concatenated DER X.509 chain; return (leaf_subject, sig_algo, chain_info).

    cryptography's ``load_der_x509_certificate`` decodes one cert at a time but
    doesn't report how many bytes it consumed, so we parse the DER length prefix
    ourselves to advance between certs.  See RFC 5280 §4.1.
    """
    try:
        from cryptography import x509
    except Exception:  # noqa: BLE001
        return None, None, []

    offset = 0
    certs = []
    # Cap total scan
    max_len = min(len(cert_bytes), _CERT_CHAIN_MAX)
    while offset + 2 <= max_len:
        # DER: each cert starts with SEQUENCE (0x30) + length.
        if cert_bytes[offset] != 0x30:
            break
        lb = cert_bytes[offset + 1]
        if lb < 0x80:
            content_len = lb
            header_len = 2
        else:
            num_bytes = lb & 0x7F
            if num_bytes == 0 or num_bytes > 4:
                break
            header_len = 2 + num_bytes
            if offset + header_len > max_len:
                break
            content_len = int.from_bytes(cert_bytes[offset + 2 : offset + 2 + num_bytes], "big")
        total_len = header_len + content_len
        if total_len <= 0 or offset + total_len > max_len:
            break
        cert_der = cert_bytes[offset : offset + total_len]
        offset += total_len
        try:
            cert = x509.load_der_x509_certificate(cert_der)
        except Exception:  # noqa: BLE001
            # Don't let a single malformed cert derail the whole chain.
            continue
        try:
            subj = cert.subject.rfc4514_string()
        except Exception:  # noqa: BLE001
            subj = None
        try:
            issuer = cert.issuer.rfc4514_string()
        except Exception:  # noqa: BLE001
            issuer = None
        algo_name: str | None = None
        try:
            if getattr(cert, "signature_hash_algorithm", None) is not None:
                algo_name = cert.signature_hash_algorithm.name  # e.g. "sha256"
        except Exception:  # noqa: BLE001
            algo_name = None
        pub_key_type: str | None = None
        try:
            pk = cert.public_key()
            pk_cls = type(pk).__name__
            if "RSA" in pk_cls:
                pub_key_type = "RSA"
            elif "EllipticCurve" in pk_cls or "EC" in pk_cls:
                pub_key_type = "EC"
            elif "DSA" in pk_cls:
                pub_key_type = "DSA"
            else:
                pub_key_type = pk_cls
        except Exception:  # noqa: BLE001
            pub_key_type = None
        certs.append(
            {
                "subject": subj,
                "issuer": issuer,
                "hash_algo": algo_name,
                "pub_key": pub_key_type,
            }
        )

    if not certs:
        return None, None, []

    # Determine leaf: a cert whose subject is not the issuer of any other cert.
    subjects_as_issuers = {c["issuer"] for c in certs if c["issuer"]}
    leaf = None
    for c in certs:
        if c["subject"] and c["subject"] not in subjects_as_issuers:
            leaf = c
            break
    if leaf is None:
        # Fallback: take the last cert in the chain (common convention).
        leaf = certs[-1]

    sig_algo: str | None = None
    if leaf.get("pub_key") and leaf.get("hash_algo"):
        sig_algo = f"{leaf['pub_key']}-{leaf['hash_algo'].upper()}"
    elif leaf.get("hash_algo"):
        sig_algo = leaf["hash_algo"].upper()

    return leaf.get("subject"), sig_algo, certs


def _parse_mbn_v3_header(header: bytes) -> dict[str, Any]:
    """Parse the legacy 40-byte MBN v3 header.

    Field layout (all uint32 little-endian):
        0  codeword           0x844bdcd1
        4  magic              0x73d71034
        8  image_id
       12  flash_parti_ver
       16  image_src
       20  image_dest_ptr
       24  image_size
       28  code_size
       32  sig_ptr
       36  sig_size
       -- the next 8 bytes (cert_chain_ptr, cert_chain_size) are technically
       part of the same raw header block; v3 is 40 bytes, "v3+cert" variants
       include them.  We read 48 bytes opportunistically.
    """
    out: dict[str, Any] = {"mbn_header_version": "v3"}
    if len(header) < 40:
        return out
    try:
        (
            codeword,
            magic,
            image_id,
            flash_parti_ver,
            image_src,
            image_dest_ptr,
            image_size,
            code_size,
            sig_ptr,
            sig_size,
        ) = struct.unpack_from("<10I", header, 0)
    except struct.error:
        return out
    out.update(
        {
            "codeword": f"0x{codeword:08x}",
            "magic": f"0x{magic:08x}",
            "image_id": image_id,
            "flash_parti_ver": flash_parti_ver,
            "image_src": image_src,
            "image_dest_ptr": image_dest_ptr,
            "image_size": image_size,
            "code_size": code_size,
            "sig_ptr": sig_ptr,
            "sig_size": sig_size,
        }
    )
    if len(header) >= 48:
        try:
            cert_chain_ptr, cert_chain_size = struct.unpack_from("<2I", header, 40)
            out["cert_chain_ptr"] = cert_chain_ptr
            out["cert_chain_size"] = cert_chain_size
        except struct.error:
            pass
    return out


def _load_bytes(path: str, limit: int) -> bytes:
    """Read up to ``limit`` bytes from ``path``; return empty on error."""
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


class QualcommMbnParser:
    """Parser for Qualcomm PIL/MBN firmware (ELF and raw-header variants)."""

    FORMAT = "qcom_mbn"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {}
        version: str | None = None
        signed: str = "unknown"
        signature_algorithm: str | None = None
        cert_subject: str | None = None
        chipset_target: str | None = None

        try:
            # Two code paths: ELF-wrapped (most common) vs raw MBN v3 header.
            is_elf = len(magic) >= 4 and magic[:4] == b"\x7fELF"

            if is_elf:
                elf_meta, cert_subject, signature_algorithm = self._parse_elf(path, size, meta)
                meta.update(elf_meta)
                if cert_subject or signature_algorithm or meta.get("cert_chain_segment_size"):
                    signed = "signed"
            else:
                hdr = _load_bytes(path, 64)
                if len(hdr) >= 8:
                    codeword = int.from_bytes(hdr[0:4], "little")
                    m = int.from_bytes(hdr[4:8], "little")
                    if codeword == _MBN_V3_CODEWORD or m == _MBN_V3_MAGIC:
                        meta.update(_parse_mbn_v3_header(hdr))
                        # v3 vs v5/v6 distinguisher: v3 has file_size == 40 + code_size + sig_size + cert_chain_size
                        cs = meta.get("code_size")
                        ss = meta.get("sig_size")
                        ccs = meta.get("cert_chain_size")
                        if cs is not None and ss is not None:
                            expected = 40 + int(cs) + int(ss) + int(ccs or 0)
                            if expected == size:
                                meta["mbn_header_version"] = "v3"
                            else:
                                # Not quite v3 — could be v5 or v6 with extra fields.
                                meta["mbn_header_version"] = "v5_or_v6"
                        if ss and int(ss) > 0:
                            signed = "signed"
                        # Best-effort: if the header advertises a cert chain,
                        # read it from the tail of the file and parse X.509.
                        if ccs and int(ccs) > 0:
                            cert_bytes = self._tail_cert_bytes(path, size, int(ccs))
                            if cert_bytes:
                                leaf, algo, info = _parse_x509_chain(cert_bytes)
                                if info:
                                    meta["cert_chain"] = info
                                if leaf:
                                    cert_subject = leaf
                                if algo:
                                    signature_algorithm = algo

            # Scan file for chipset / version strings.
            scan = _load_bytes(path, min(_SCAN_LIMIT, max(size, 0)))
            if scan:
                chipset, scan_version, qc_version_raw = _scan_for_chipset_and_version(scan)
                if chipset and not chipset_target:
                    chipset_target = chipset
                if scan_version and not version:
                    version = scan_version
                if qc_version_raw:
                    meta["qc_image_version_string"] = qc_version_raw

        except Exception as exc:  # noqa: BLE001
            logger.debug("QualcommMbnParser failed on %s: %s", path, exc)
            meta["error"] = str(exc)

        return ParsedBlob(
            version=version,
            signed=signed,
            signature_algorithm=signature_algorithm,
            cert_subject=cert_subject,
            chipset_target=chipset_target,
            metadata=meta,
        )

    def _parse_elf(
        self, path: str, size: int, meta: dict[str, Any]
    ) -> tuple[dict[str, Any], str | None, str | None]:
        """Parse via LIEF; return (metadata_updates, cert_subject, signature_algorithm)."""
        try:
            import lief  # type: ignore
        except Exception as exc:  # noqa: BLE001
            return {"lief_error": f"import failed: {exc}"}, None, None

        updates: dict[str, Any] = {}
        cert_subject: str | None = None
        sig_algo: str | None = None

        try:
            binary = lief.parse(path)
        except Exception as exc:  # noqa: BLE001
            return {"lief_error": f"parse failed: {exc}"}, None, None
        if binary is None or getattr(binary, "format", None) is None:
            return {"lief_error": "not an ELF per LIEF"}, None, None

        try:
            segments = list(binary.segments)
        except Exception:  # noqa: BLE001
            segments = []

        qc_segments: list[dict[str, Any]] = []
        cert_chain_bytes: bytes | None = None
        for idx, seg in enumerate(segments):
            try:
                flags = int(seg.flags)
            except Exception:  # noqa: BLE001
                continue
            qc_type = flags & _QC_SEG_MASK
            if qc_type == 0:
                continue
            try:
                file_offset = int(getattr(seg, "file_offset", 0))
                file_size = int(getattr(seg, "physical_size", 0) or 0)
            except Exception:  # noqa: BLE001
                continue
            label = {
                _QC_SEG_HASH: "hash",
                _QC_SEG_SIG: "signature",
                _QC_SEG_CERT: "cert_chain",
            }.get(qc_type, f"qc_other_{qc_type:#x}")
            qc_segments.append(
                {
                    "index": idx,
                    "type": label,
                    "file_offset": file_offset,
                    "file_size": file_size,
                    "flags": f"{flags:#010x}",
                }
            )
            if qc_type == _QC_SEG_CERT and file_size > 0:
                chunk = self._read_range(path, file_offset, min(file_size, _CERT_CHAIN_MAX))
                if chunk:
                    cert_chain_bytes = chunk
                    updates["cert_chain_segment_size"] = file_size

        if qc_segments:
            updates["qc_segments"] = qc_segments

        # Entry point / ELF class for reference.
        try:
            updates["elf_entrypoint"] = hex(int(binary.entrypoint))
        except Exception:  # noqa: BLE001
            pass

        if cert_chain_bytes:
            leaf_subj, algo, chain_info = _parse_x509_chain(cert_chain_bytes)
            if chain_info:
                updates["cert_chain"] = chain_info
            if leaf_subj:
                cert_subject = leaf_subj
            if algo:
                sig_algo = algo

        return updates, cert_subject, sig_algo

    @staticmethod
    def _read_range(path: str, offset: int, length: int) -> bytes:
        """Read ``length`` bytes from ``path`` starting at ``offset``."""
        if length <= 0:
            return b""
        try:
            with open(path, "rb") as f:
                f.seek(offset)
                return f.read(length)
        except OSError:
            return b""

    @staticmethod
    def _tail_cert_bytes(path: str, size: int, cert_size: int) -> bytes:
        """Read the last ``cert_size`` bytes of a raw MBN (where the cert chain lives).

        The MBN v3 layout places the cert chain at the very end of the file,
        i.e. ``file[size - cert_chain_size : size]``.
        """
        cert_size = min(max(cert_size, 0), _CERT_CHAIN_MAX)
        if cert_size == 0 or size <= 0 or cert_size > size:
            return b""
        try:
            with open(path, "rb") as f:
                f.seek(max(size - cert_size, 0))
                return f.read(cert_size)
        except OSError:
            return b""


_parser = QualcommMbnParser()
register_parser(_parser)
# Aliases: the classifier may emit any of these formats; all map to the same parser.
for _alias in ("mbn_v3", "mbn_v5", "mbn_v6"):
    PARSER_REGISTRY[_alias] = _parser
