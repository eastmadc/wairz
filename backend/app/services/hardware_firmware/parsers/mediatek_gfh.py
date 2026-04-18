"""MediaTek LK / GFH shared utilities.

Two pieces live here so the outer LK-record parser (``mediatek_lk``), the
classifier, and future subsystem parsers (``mtk_atf``, ``mtk_geniezone``,
``mtk_tinysys``) all agree on:

1. **LK partition-record header parsing** — both the 512-byte *legacy*
   layout (name at 0x20) and the 16-byte *compact* layout (name at 0x08)
   used on newer MTK SoCs (MT6785/MT6853/MT8788+). Disambiguation is done
   by probing offset 0x08 for a valid ASCII name.

2. **Partition-name → (category, component, vendor)** lookup — the
   dispatch table distilled from U-Boot ``tools/mtk_image.c``,
   bkerler/mtkclient ``partitions.py``, and LineageOS MTK device trees.
   This is what turns ``cam_vpu1`` / ``atf`` / ``md1rom`` / ``spmfw`` /
   ``gz`` into the right Wairz category instead of defaulting every
   LK-wrapped blob to ``bootloader``.

The GFH "MMM\\x01" chain walker isn't implemented here — on the DPCS10
packages we observed, the outer LK record is followed directly by an
``LK_FILE_INFO`` (0x58891689) block and a trailer, not an MMM chain.
Add the chain walker if/when a target firmware exposes it.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass


_LK_MAGIC = 0x58881688
_LK_FILE_INFO_MAGIC = 0x58891689
_LK_HEADER_SIZE = 512

# Compact (16-byte) vs legacy (512-byte) layouts are distinguished at
# runtime by whether offset 0x08 holds a plausible ASCII name.  Valid
# partition names are short, start with a letter or digit, and contain
# only [A-Za-z0-9_-].
_NAME_RE = re.compile(rb"^[A-Za-z][A-Za-z0-9_\-]{0,30}$")


@dataclass
class LkHeader:
    """Parsed MediaTek LK partition-record header."""

    name: str                    # partition name (e.g. "lk", "atf", "md1rom")
    layout: str                  # "compact" (16-byte) | "legacy" (512-byte)
    file_info_offset: int        # u32 at offset 0x04
    has_file_info_magic: bool    # whether 0x58891689 lives inside the header


def parse_lk_header(data: bytes) -> LkHeader | None:
    """Parse an LK partition-record header from the first 64+ bytes.

    Returns ``None`` if magic doesn't match or header is too short.
    Never raises on truncated input.
    """
    if len(data) < 16:
        return None
    try:
        magic_u32, file_info_offset = struct.unpack_from("<II", data, 0)
    except struct.error:
        return None
    if magic_u32 != _LK_MAGIC:
        return None

    # Compact variant: 8-byte name at 0x08
    compact_name = _decode_cstr(data[8:16])
    if compact_name and _NAME_RE.match(compact_name.encode("ascii", "ignore")):
        has_fi = (
            len(data) >= 0x34
            and struct.unpack_from("<I", data, 0x30)[0] == _LK_FILE_INFO_MAGIC
        )
        return LkHeader(
            name=compact_name,
            layout="compact",
            file_info_offset=file_info_offset,
            has_file_info_magic=has_fi,
        )

    # Legacy variant: 32-byte name at 0x20
    if len(data) >= 0x40:
        legacy_name = _decode_cstr(data[0x20:0x40])
        if legacy_name and _NAME_RE.match(legacy_name.encode("ascii", "ignore")):
            return LkHeader(
                name=legacy_name,
                layout="legacy",
                file_info_offset=file_info_offset,
                has_file_info_magic=False,
            )

    # Magic matched but no usable name — return minimal header so callers
    # can still flag "bad/stub" without crashing.
    return LkHeader(
        name="",
        layout="compact" if file_info_offset < 64 else "legacy",
        file_info_offset=file_info_offset,
        has_file_info_magic=False,
    )


def _decode_cstr(raw: bytes) -> str:
    nul = raw.find(b"\x00")
    if nul >= 0:
        raw = raw[:nul]
    try:
        return raw.decode("ascii", errors="ignore").strip()
    except Exception:  # noqa: BLE001
        return ""


# ─────────────────────────────────────────────────────────────────────
# Partition-name → (category, component, vendor) dispatch
# ─────────────────────────────────────────────────────────────────────
#
# category: the Wairz CATEGORIES value for classifier output
# component: a stable subcomponent tag usable for CVE matching; mirrors
#            the "Subcomponent" column in MediaTek's monthly Product
#            Security Bulletins (e.g. "geniezone", "atf", "tinysys",
#            "modem", etc.)
# vendor: always "mediatek" for these names
#
# Sources:
#   - U-Boot tools/mtk_image.c (GPL-2.0)
#   - bkerler/mtkclient partitions.py (GPL-3.0)
#   - AOSP device/mediatek/*/BoardConfig.mk
#   - MediaTek monthly Product Security Bulletin subcomponent tags
#   - cyrozap/mediatek-lte-baseband-re
_MTK_PARTITIONS: dict[str, tuple[str, str]] = {
    # Bootloader family
    "preloader": ("bootloader", "preloader"),
    "lk": ("bootloader", "lk"),
    "lk_a": ("bootloader", "lk"),
    "lk_b": ("bootloader", "lk"),
    "lk2": ("bootloader", "lk"),
    "boot": ("bootloader", "android_boot"),
    "boot_a": ("bootloader", "android_boot"),
    "boot_b": ("bootloader", "android_boot"),
    "recovery": ("bootloader", "android_recovery"),
    "vbmeta": ("bootloader", "vbmeta"),

    # Trusted execution
    "atf": ("tee", "atf"),
    "tee": ("tee", "tee"),
    "tee1": ("tee", "tee"),
    "tee2": ("tee", "tee"),
    "gz": ("tee", "geniezone"),

    # Power / coprocessors
    "spmfw": ("mcu", "spmfw"),
    "sspm": ("mcu", "tinysys"),
    "mcupm": ("mcu", "mcupm"),
    "dpm": ("mcu", "dpm"),
    "scp": ("dsp", "tinysys"),
    "scp1": ("dsp", "tinysys"),
    "scp2": ("dsp", "tinysys"),

    # Camera
    "cam_vpu1": ("camera", "cam_vpu"),
    "cam_vpu2": ("camera", "cam_vpu"),
    "cam_vpu3": ("camera", "cam_vpu"),
    "ccu": ("camera", "ccu"),
    "ccu1": ("camera", "ccu"),

    # AI / neural accelerators
    "vpu": ("dsp", "apu"),
    "apu": ("dsp", "apu"),

    # Modem (MD1 / MD2)
    "md1rom": ("modem", "modem"),
    "md1dsp": ("modem", "modem_dsp"),
    "md1drdi": ("modem", "modem_drdi"),
    "md1img": ("modem", "modem"),
    "md2img": ("modem", "modem"),
    "cert_md": ("modem", "modem_cert"),
    "dsp_bl": ("dsp", "modem_dsp_bl"),
    "md1_filter": ("modem", "modem_filter"),
    "md1_filter_hw": ("modem", "modem_filter"),

    # Display / GPU
    "logo": ("display", "logo"),
    "gpueb": ("gpu", "mali_fw"),

    # Audio
    "audio_dsp": ("audio", "adsp"),
    "adsp": ("audio", "adsp"),

    # Device tree
    "dtb": ("dtb", "dtb"),
    "dtbo": ("dtb", "dtbo"),

    # Connectivity combo (Wi-Fi/BT/FM/GPS)
    "wifi": ("wifi", "connsys"),
    "connsys": ("wifi", "connsys"),
    "wmt": ("wifi", "connsys"),
}

# Names that ship as tiny partition-descriptor stubs when the corresponding
# die is depopulated (common on modem-less SKUs of the Genio 700 / AIoT8788
# platform). When we see one of these with a suspiciously small file, flag
# it so the UI can surface "partition placeholder — no firmware payload".
_STUB_CANDIDATES = frozenset({"md1rom", "md1dsp", "md1drdi", "cert_md"})
_STUB_SIZE_THRESHOLD = 4096


def lookup_partition(name: str) -> tuple[str, str] | None:
    """Return ``(category, component)`` for a known MTK partition name,
    or ``None`` if the name is unrecognised (classifier falls back to
    the generic ``bootloader`` / ``mtk_lk`` default).

    Also handles ``tinysys-<suffix>`` compact names by mapping the
    ``tinysys-`` prefix to SCP/SSPM category.
    """
    if not name:
        return None
    key = name.lower().strip()
    hit = _MTK_PARTITIONS.get(key)
    if hit is not None:
        return hit
    # Newer bundles name scp/sspm/mcupm as "tinysys-scp" etc.
    if key.startswith("tinysys"):
        return ("dsp", "tinysys")
    return None


def is_stub_descriptor(name: str, file_size: int) -> bool:
    """True when the blob is a known-stubbable partition AND the file is
    below the size that would hold any real payload.

    Used to suppress nonsense struct-field reads on files that are
    actually scatter-config placeholders (e.g. `md1rom` = 528 B on
    modem-less SKUs).
    """
    if not name:
        return False
    return name.lower() in _STUB_CANDIDATES and file_size < _STUB_SIZE_THRESHOLD
