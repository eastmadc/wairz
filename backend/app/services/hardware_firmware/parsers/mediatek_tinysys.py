"""MediaTek tinysys / SCP / SSPM / SPMFW parser.

Handles classifier format ``mtk_tinysys``. Covers four related component
types, all wrapped in the outer LK container (``0x58881688``):

- **SCP** (System Control Processor) — Cortex-M4F running FreeRTOS.
  Container has a tiny ``tinysys-loader-CM4_A`` bootstub plus the real
  payload ``tinysys-scp-CM4_A``. We target the real payload.
- **SSPM** (Secure System Power Manager) — Cortex-M running MediaTek's
  in-house RTOS (not FreeRTOS). Payload begins with ``0x58901690``
  segment-chain magic.
- **SPMFW** — proprietary MediaTek PCM microcode (``"2MPS"`` magic).
  NOT ARM code; no Ghidra import.
- **MCUPM** / **DPM** — tinysys siblings (not in DPCS10 sample).

What we extract (where applicable):

- Cortex-M vector table — MSP + Reset handler; validates Thumb bit.
- RTOS flavour (FreeRTOS vs SSPM RTOS vs PCM microcode)
- Board/BSP tag (``aiot8788ep1_64_bsp_k66``)
- Platform tree reference (``project/CM4_A/mt6771/...``)
- PCM microcode filename (``pcm_allinone_lp3_1866.bin``) for SPMFW
- Ghidra import params or a ``no_ghidra_import=true`` flag

References:
    - FreeRTOS port for ARM_CM4F (public)
    - MediaTek tinysys (internal, partial symbols visible in binaries)
"""

from __future__ import annotations

import logging
import re
import struct
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser
from app.services.hardware_firmware.parsers.mediatek_gfh import (
    derive_chipset,
    signed_from_subimages,
    walk_sub_images,
)

logger = logging.getLogger(__name__)


_FREERTOS_MARKER = re.compile(rb"FreeRTOS[/\\](?:Source|Core)[/\\]")
_BOARD_TAG_RE = re.compile(rb"aiot\w+_bsp_\w+")
_PLATFORM_TREE_RE = re.compile(rb"project/(?:CM4_A|CM4_B|CM0)/\w+/")
_SSPM_SEGMENT_MAGIC = b"\x90\x16\x90\x58"  # 0x58901690 LE
_SPMFW_PCM_MAGIC = b"2MPS"
_PCM_NAME_RE = re.compile(rb"pcm_\w+\.bin")

# Default Cortex-M base addresses per role (MTK MT6771 / MT8788).
# These are the boot-ROM-supplied load addresses; GFH extension blocks
# carry the authoritative values.
_SCP_DEFAULT_BASE = 0x00000000
_SSPM_DEFAULT_BASE = 0x00100000


def _read_payload(path: str, limit: int = 4 * 1024 * 1024) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def _vector_table_looks_valid(payload: bytes) -> tuple[int, int] | None:
    """Return (msp, reset_handler) when the first 8 bytes are a plausible
    Cortex-M vector table, else None. Requires reset-handler Thumb bit
    (bit 0) set and MSP to be 4-byte aligned.
    """
    if len(payload) < 8:
        return None
    msp, reset = struct.unpack_from("<II", payload, 0)
    if reset & 1 == 0:  # Thumb bit must be set on a valid ARMv7-M reset
        return None
    if msp & 0x3:  # MSP must be 4-byte aligned
        return None
    return msp, reset


class MediatekTinysysParser:
    """Parser for MediaTek tinysys / SCP / SSPM / SPMFW blobs."""

    FORMAT = "mtk_tinysys"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {"runtime": "tinysys_unknown"}
        version: str | None = None

        data = _read_payload(path)
        if not data:
            meta["error"] = "unable to read file"
            return ParsedBlob(metadata=meta)

        subimages = walk_sub_images(data)
        meta["sub_images"] = [
            {"name": s.name, "offset": s.offset, "size": s.payload_size,
             "is_signature": s.is_signature}
            for s in subimages
        ]

        # Pick the "real" payload. On SCP containers there are TWO
        # non-signature sub-images (loader + real image). Prefer the
        # larger one, since the loader is tiny (~1 KB).
        real_payloads = [s for s in subimages if not s.is_signature]
        if not real_payloads:
            meta["error"] = "no primary payload found"
            return ParsedBlob(metadata=meta)
        primary = max(real_payloads, key=lambda s: s.payload_size)
        meta["selected_sub_image"] = primary.name

        payload = data[primary.payload_offset : primary.payload_offset + primary.payload_size]

        # SPMFW — proprietary PCM microcode; no CPU disassembly possible.
        if payload[:4] == _SPMFW_PCM_MAGIC:
            meta["runtime"] = "mtk_pcm_microcode"
            meta["component"] = "spmfw"
            meta["no_ghidra_import"] = True
            pcm_name = _PCM_NAME_RE.search(payload[:512])
            if pcm_name:
                meta["pcm_artifact"] = pcm_name.group(0).decode("ascii", errors="replace")
            meta["note"] = (
                "MediaTek PCM state-machine microcode; not ARM code. No "
                "Ghidra language spec exists; parser surfaces metadata only."
            )
            return ParsedBlob(
                metadata=meta,
                signed=signed_from_subimages(subimages),
                chipset_target=derive_chipset(meta),
            )

        # SSPM — 0x58901690 segment-chain wrapper.
        if payload[:4] == _SSPM_SEGMENT_MAGIC:
            meta["runtime"] = "mtk_sspm_rtos"
            meta["component"] = "sspm"
            meta["inner_wrapper"] = "sspm_segment_chain"
            meta["ghidra_import_params"] = {
                "processor": "ARM:LE:32:Cortex",
                "loader": "BinaryLoader",
                "base_addr": _SSPM_DEFAULT_BASE,
                "entry_point": None,
                "load_offset_in_file": primary.payload_offset,
                "load_length": primary.payload_size,
                "notes": (
                    "SSPM uses a segment-chain wrapper (0x58901690); full "
                    "Ghidra import requires walking the segment table to "
                    "find the real vector table. Deferred."
                ),
            }
            return ParsedBlob(
                metadata=meta,
                signed=signed_from_subimages(subimages),
                chipset_target=derive_chipset(meta),
            )

        # Default: SCP / MCUPM / DPM — plain Cortex-M image with a
        # vector table at offset 0. Validate + extract.
        vt = _vector_table_looks_valid(payload)
        if vt is None:
            meta["error"] = "payload does not look like a Cortex-M image"
            return ParsedBlob(metadata=meta)
        msp, reset = vt
        meta["runtime"] = "tinysys_rtos"
        if _FREERTOS_MARKER.search(payload[: 512 * 1024]):
            meta["runtime"] = "freertos"
            meta["os_flavor"] = "freertos"
        # Determine component from the sub-image name
        if "scp" in primary.name.lower():
            meta["component"] = "scp"
        elif "sspm" in primary.name.lower():
            meta["component"] = "sspm"
        else:
            meta["component"] = "tinysys"
        meta["vector_msp"] = f"0x{msp:08x}"
        meta["vector_reset"] = f"0x{reset:08x}"

        # Board / BSP tag
        search_window = payload[: 1 * 1024 * 1024]
        board = _BOARD_TAG_RE.search(search_window)
        if board:
            meta["board_tag"] = board.group(0).decode("ascii", errors="replace")
        plat = _PLATFORM_TREE_RE.search(search_window)
        if plat:
            meta["platform_tree"] = plat.group(0).decode("ascii", errors="replace")

        # Ghidra import params: Cortex-M at base 0, entry = reset & ~1
        base = _SCP_DEFAULT_BASE if meta["component"] == "scp" else _SSPM_DEFAULT_BASE
        meta["ghidra_import_params"] = {
            "processor": "ARM:LE:32:Cortex",
            "loader": "BinaryLoader",
            "base_addr": base,
            "entry_point": reset & ~1,  # strip Thumb bit for Ghidra
            "load_offset_in_file": primary.payload_offset,
            "load_length": primary.payload_size,
            "notes": f"Default MTK {meta['component'].upper()} base; verify via GFH maddr",
        }

        return ParsedBlob(
            version=version,
            signed=signed_from_subimages(subimages),
            metadata=meta,
            chipset_target=derive_chipset(meta),
        )


register_parser(MediatekTinysysParser())
