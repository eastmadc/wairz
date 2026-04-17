"""Device Tree Blob (DTB) and Android DTBO container parser.

Handles formats ``dtb`` (flat DTB, magic ``0xd00dfeed``) and ``dtbo``
(Android container, magic ``0xd7b7ab1e``).

For a flat DTB we read the root ``model`` property, all ``compatible``
property lists anywhere in the tree, and every ``firmware-name`` property
(commonly used in DTS nodes to name a ``.bin`` under ``/lib/firmware/``).

For a DTBO container, we walk the header to find the sub-DTB entries,
parse each one individually, and aggregate compatibles + firmware names
across all entries — individual entries are returned under
``metadata["dtb_entries"]``.

DTBs are unsigned by convention: we set ``signed="unsigned"``.

We attempt to infer ``chipset_target`` from the first ``compatible`` string
that matches a known vendor pattern (``qcom,sm8450``, ``qcom,sdm845``,
``mediatek,mt6873`` etc.).
"""

from __future__ import annotations

import logging
import re
import struct
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser

logger = logging.getLogger(__name__)


# Cap for how much we'll read and parse.  16 MB is well above any Android DTB.
_MAX_DTB_BYTES = 16 * 1024 * 1024

_DTB_MAGIC = 0xD00DFEED
_DTBO_MAGIC = 0xD7B7AB1E

_CHIPSET_RE = re.compile(
    r"(?:qcom|mediatek|mtk|samsung|exynos|nvidia|hisilicon|unisoc|rockchip|ti)"
    r"[-_,](?P<model>[a-z0-9_\-]+)",
    re.IGNORECASE,
)


def _load_bytes(path: str, limit: int) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def _collect_props_from_fdt(dt: Any) -> tuple[str | None, list[str], list[str]]:
    """Extract (model, compatible_strings, firmware_names) from an ``fdt.FDT`` tree."""
    model: str | None = None
    compatibles: list[str] = []
    firmware_names: list[str] = []

    def _node_props(node: Any) -> None:
        nonlocal model
        try:
            props = list(getattr(node, "props", []) or [])
        except Exception:  # noqa: BLE001
            props = []
        for prop in props:
            name = getattr(prop, "name", None)
            if name == "model" and model is None:
                val = _prop_strings(prop)
                if val:
                    model = val[0]
            elif name == "compatible":
                compatibles.extend(_prop_strings(prop))
            elif name == "firmware-name":
                firmware_names.extend(_prop_strings(prop))

    def _walk(node: Any) -> None:
        _node_props(node)
        for child in getattr(node, "nodes", []) or []:
            _walk(child)

    try:
        root = getattr(dt, "root", None)
        if root is not None:
            _walk(root)
    except Exception as exc:  # noqa: BLE001
        logger.debug("DTB walk error: %s", exc)

    return model, compatibles, firmware_names


def _prop_strings(prop: Any) -> list[str]:
    """Return a prop's value as a list of strings, defensive to library shape.

    ``fdt.PropStrings.data`` is a ``list[str]`` — the canonical source.
    ``fdt.PropBytes.data`` is a ``bytearray`` of concatenated NUL-terminated
    strings (per DT spec).  Older/alternate shapes may expose ``.value`` or
    ``.strings`` — we try each in turn.
    """
    out: list[str] = []

    # Primary path: PropStrings.data is list[str].
    try:
        data = getattr(prop, "data", None)
    except Exception:  # noqa: BLE001
        data = None
    if isinstance(data, list):
        for v in data:
            if isinstance(v, str) and v:
                out.append(v.rstrip("\x00"))
        if out:
            return out
    # Bytes path: PropBytes.data is bytearray — split on NUL.
    if isinstance(data, (bytes, bytearray)):
        for chunk in bytes(data).split(b"\x00"):
            if chunk:
                try:
                    out.append(chunk.decode("utf-8", errors="replace"))
                except Exception:  # noqa: BLE001
                    continue
        if out:
            return out
    # Fallback: .value (may be a single string, list, or bytes).
    try:
        val = getattr(prop, "value", None)
    except Exception:  # noqa: BLE001
        val = None
    if isinstance(val, list):
        for v in val:
            if isinstance(v, (bytes, bytearray)):
                out.append(v.decode("utf-8", errors="replace").rstrip("\x00"))
            elif isinstance(v, str):
                out.append(v.rstrip("\x00"))
    elif isinstance(val, str):
        out.append(val.rstrip("\x00"))
    elif isinstance(val, (bytes, bytearray)):
        for chunk in val.split(b"\x00"):
            if chunk:
                out.append(chunk.decode("utf-8", errors="replace"))
    return out


def _infer_chipset(compatibles: list[str], model: str | None) -> str | None:
    """Return a short chipset token like ``sm8450`` from compatible strings / model."""
    for s in compatibles + ([model] if model else []):
        if not s:
            continue
        m = _CHIPSET_RE.search(s)
        if m:
            token = m.group("model")
            if token:
                return token
    return None


def _parse_single_dtb(data: bytes) -> dict[str, Any]:
    """Parse one flat DTB blob; return metadata-ready dict."""
    out: dict[str, Any] = {}
    try:
        import fdt  # type: ignore
    except Exception as exc:  # noqa: BLE001
        return {"error": f"fdt import failed: {exc}"}
    try:
        dt = fdt.parse_dtb(data)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"parse_dtb failed: {exc}"}

    model, compatibles, firmware_names = _collect_props_from_fdt(dt)
    if model:
        out["model"] = model
    if compatibles:
        out["compatible_strings"] = compatibles
    if firmware_names:
        out["firmware_names"] = firmware_names
    return out


def _parse_dtbo(data: bytes) -> dict[str, Any]:
    """Parse an Android DTBO container and aggregate every sub-DTB.

    Header (big-endian):
        0   u32  magic = 0xd7b7ab1e
        4   u32  total_size
        8   u32  header_size
        12  u32  dt_entry_size
        16  u32  dt_entry_count
        20  u32  dt_entries_offset
        24  u32  page_size
        28  u32  version
    Each entry is ``dt_entry_size`` bytes; first two u32 of an entry are
    (dt_size, dt_offset) — remaining bytes are version/id/rev/custom.
    """
    out: dict[str, Any] = {"container": "dtbo"}
    if len(data) < 32 or int.from_bytes(data[:4], "big") != _DTBO_MAGIC:
        out["error"] = "dtbo: bad header magic"
        return out
    try:
        (
            _magic,
            _total_size,
            _header_size,
            dt_entry_size,
            dt_entry_count,
            dt_entries_offset,
            _page_size,
            version,
        ) = struct.unpack_from(">8I", data, 0)
    except struct.error as exc:
        out["error"] = f"dtbo: header unpack failed: {exc}"
        return out

    out["dtbo_version"] = version
    out["dt_entry_count"] = dt_entry_count
    entries: list[dict[str, Any]] = []
    combined_compats: list[str] = []
    combined_fws: list[str] = []

    for i in range(dt_entry_count):
        entry_off = dt_entries_offset + i * dt_entry_size
        if entry_off + 8 > len(data):
            break
        dt_size, dt_offset = struct.unpack_from(">2I", data, entry_off)
        if dt_offset + dt_size > len(data) or dt_size == 0:
            entries.append({"index": i, "error": "out-of-bounds or empty entry"})
            continue
        sub = data[dt_offset : dt_offset + dt_size]
        sub_meta = _parse_single_dtb(sub)
        entries.append(
            {
                "index": i,
                "size": dt_size,
                "offset": dt_offset,
                **{k: v for k, v in sub_meta.items() if k != "error"},
                **({"error": sub_meta["error"]} if "error" in sub_meta else {}),
            }
        )
        combined_compats.extend(sub_meta.get("compatible_strings", []) or [])
        combined_fws.extend(sub_meta.get("firmware_names", []) or [])

    out["dtb_entries"] = entries
    if combined_compats:
        out["compatible_strings"] = sorted(set(combined_compats))
    if combined_fws:
        out["firmware_names"] = sorted(set(combined_fws))
    return out


class DtbParser:
    """Parses flat DTB and Android DTBO containers."""

    FORMAT = "dtb"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {}
        chipset_target: str | None = None
        version: str | None = None

        try:
            data = _load_bytes(path, min(size or _MAX_DTB_BYTES, _MAX_DTB_BYTES))
            if not data:
                meta["error"] = "empty file or read failed"
                return ParsedBlob(signed="unsigned", metadata=meta)

            if len(data) >= 4 and int.from_bytes(data[:4], "big") == _DTBO_MAGIC:
                meta.update(_parse_dtbo(data))
            else:
                # Flat DTB path (magic 0xd00dfeed or best-effort).
                meta.update(_parse_single_dtb(data))

            # Infer chipset from the combined compatibles / model.
            chipset_target = _infer_chipset(
                list(meta.get("compatible_strings", []) or []),
                meta.get("model"),
            )
            # Version proxy: model string; DTs don't carry semver.
            version = meta.get("model")

        except Exception as exc:  # noqa: BLE001
            logger.debug("DtbParser failed on %s: %s", path, exc)
            meta["error"] = str(exc)

        return ParsedBlob(
            version=version,
            signed="unsigned",
            chipset_target=chipset_target,
            metadata=meta,
        )


class DtboParser(DtbParser):
    """Thin subclass so the classifier's ``dtbo`` format resolves to the same logic."""

    FORMAT = "dtbo"


register_parser(DtbParser())
register_parser(DtboParser())
