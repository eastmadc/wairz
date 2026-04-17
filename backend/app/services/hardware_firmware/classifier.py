from __future__ import annotations

import os
import re
from dataclasses import dataclass

CATEGORIES: set[str] = {
    "modem",
    "tee",
    "wifi",
    "bluetooth",
    "gpu",
    "dsp",
    "camera",
    "audio",
    "sensor",
    "touchpad",
    "nfc",
    "usb",
    "display",
    "fingerprint",
    "dtb",
    "kernel_module",
    "bootloader",
    "other",
}

VENDORS: set[str] = {
    "qualcomm",
    "mediatek",
    "samsung",
    "broadcom",
    "nvidia",
    "imagination",
    "arm",
    "apple",
    "cypress",
    "unisoc",
    "hisilicon",
    "intel",
    "realtek",
    "unknown",
}

FORMATS: set[str] = {
    "qcom_mbn",
    "mbn_v3",
    "mbn_v5",
    "mbn_v6",
    "elf",
    "dtb",
    "dtbo",
    "ko",
    "fw_bcm",
    "raw_bin",
    "tzbsp",
    "kinibi_mclf",
    "optee_ta",
    "shannon_toc",
    "mtk_gfh",
    "mtk_preloader",
}


@dataclass
class Classification:
    """Result of classifying a firmware blob candidate."""

    category: str
    vendor: str
    format: str
    confidence: str  # high|medium|low


# Qualcomm PIL filename patterns (stems + extensions).  Case-insensitive.
_QCOM_EXT = re.compile(r"\.(mbn|mdt|b0[0-9a-f])$", re.IGNORECASE)
_QCOM_STEMS = {
    "xbl.elf",
    "xbl_config.elf",
    "tz.mbn",
    "hyp.mbn",
    "aop.mbn",
    "adsp.mbn",
    "cdsp.mbn",
    "modem.mbn",
    "slpi.mbn",
    "wlanmdsp.mbn",
    "mba.mbn",
    "abl.elf",
    "rpm.mbn",
    "sbl1.mbn",
    "aboot.mbn",
    "devcfg.mbn",
    "cmnlib.mbn",
    "cmnlib64.mbn",
    "keymaster.mbn",
    "qupfw.mbn",
    "tzbsp.mbn",
}

# Qualcomm Adreno GPU firmware (aNNN_zap/sqe/gmu)
_ADRENO_RE = re.compile(r"^a\d+_(zap|sqe|gmu)\b", re.IGNORECASE)

# Vendor Wi-Fi / Bluetooth patterns
_BRCM_WIFI_RE = re.compile(r"^brcmfmac.*\.bin$", re.IGNORECASE)
_BRCM_BT_RE = re.compile(r"^bcm.*\.hcd$", re.IGNORECASE)
_RTL_WIFI_RE = re.compile(r"^(rtl.*_fw\.bin|rtw88.*_fw\.bin)$", re.IGNORECASE)
_MTK_WIFI_RE = re.compile(r"^(mt76.*\.bin|wifi_ram_code_mt.*\.bin)$", re.IGNORECASE)

# Touch / fingerprint / NFC patterns
_GOODIX_RE = re.compile(r"^goodix.*\.bin$", re.IGNORECASE)
_SILEAD_RE = re.compile(r"^silead.*\.bin$", re.IGNORECASE)
_SYNAPTICS_TOUCH_RE = re.compile(r"^synaptics_.*\.img$", re.IGNORECASE)
_FT_TOUCH_RE = re.compile(r"^ft_.*\.bin$", re.IGNORECASE)
_HIMAX_TOUCH_RE = re.compile(r"^himax_.*\.bin$", re.IGNORECASE)
_NFC_RE = re.compile(r"^(pn54x_fw.*|sn100u_fw.*|nfc_fw\..*)", re.IGNORECASE)

# Kinibi TEE TA patterns
_TLBIN_RE = re.compile(r"\.tlbin$", re.IGNORECASE)

# Qualcomm Venus video codec / IPA network accelerator
_VENUS_RE = re.compile(r"^(venus\.mbn|video-firmware\.elf)$", re.IGNORECASE)
_IPA_RE = re.compile(r"^(ipa_fws\.elf|ipa_uc\.elf)$", re.IGNORECASE)

# Firmware-partition directory hints
_FW_PARTITION_HINTS = (
    "/vendor/firmware_mnt/",
    "/firmware/image/",
)


def _is_qcom_filename(name: str) -> bool:
    """True if filename matches a Qualcomm PIL pattern."""
    lname = name.lower()
    if lname in _QCOM_STEMS:
        return True
    return bool(_QCOM_EXT.search(lname))


def _category_from_qcom_name(name: str) -> str:
    """Infer category from a Qualcomm PIL filename stem."""
    lname = name.lower()
    if lname.startswith(("modem", "mba", "wlanmdsp")) or lname.startswith("non-hlos"):
        return "modem"
    if lname.startswith(("tz", "hyp", "cmnlib", "keymaster", "tzbsp")):
        return "tee"
    if lname.startswith(("xbl", "sbl1", "abl", "aboot", "aop", "rpm", "devcfg", "qupfw")):
        return "bootloader"
    if lname.startswith("adsp"):
        return "audio"
    if lname.startswith("cdsp"):
        return "dsp"
    if lname.startswith("slpi"):
        return "sensor"
    if lname.startswith("venus"):
        return "other"
    return "other"


def _is_elf_relocatable(magic: bytes) -> bool:
    """True if the ELF at offset 0 has e_type == ET_REL (kernel module)."""
    if len(magic) < 18 or magic[:4] != b"\x7fELF":
        return False
    # e_type is at offset 16-17, little-endian for ELFCLASS32/64 on LE hosts.
    # Android kernel modules are always LE in practice.
    if magic[5] == 1:  # EI_DATA = 1 => little-endian
        return magic[16] == 0x01 and magic[17] == 0x00
    return magic[16] == 0x00 and magic[17] == 0x01


def _classify_by_magic(magic: bytes) -> Classification | None:
    """First pass: classify by the first 64 bytes."""
    if len(magic) < 4:
        return None

    # Device tree blob (flat DTB)
    if magic[:4] == b"\xd0\x0d\xfe\xed":
        return Classification("dtb", "unknown", "dtb", "high")

    # Android DTBO container
    if magic[:4] == b"\xd7\xb7\xab\x1e":
        return Classification("dtb", "unknown", "dtbo", "high")

    # Samsung Shannon TOC (modem)
    if magic[:4] == b"TOC\x00":
        return Classification("modem", "samsung", "shannon_toc", "high")

    # Kinibi MCLF (TrustZone TA — Samsung Exynos or MediaTek)
    if magic[:4] == b"TRUS":
        return Classification("tee", "unknown", "kinibi_mclf", "high")

    # MediaTek LK image
    if magic[:4] == b"\x88\x16\x88\x58":
        return Classification("bootloader", "mediatek", "mtk_gfh", "high")

    # MediaTek preloader: MMM\x01 header, second byte starts with 0x38
    if len(magic) >= 5 and magic[:4] == b"MMM\x01" and magic[4] == 0x38:
        return Classification("bootloader", "mediatek", "mtk_preloader", "high")

    return None


def classify(path: str, magic: bytes, size: int) -> Classification | None:
    """Classify a firmware blob candidate; return None to skip."""
    name = os.path.basename(path)
    lname = name.lower()
    lpath = path.replace(os.sep, "/").lower()

    primary = _classify_by_magic(magic)

    is_elf = len(magic) >= 4 and magic[:4] == b"\x7fELF"

    # Kernel module: ELF with ET_REL and .ko extension
    if lname.endswith(".ko") and is_elf and _is_elf_relocatable(magic):
        return Classification("kernel_module", "unknown", "ko", "high")

    # ELF: secondary inspection via filename/path
    if is_elf and primary is None:
        # Adreno GPU firmware
        if _ADRENO_RE.match(name):
            return Classification("gpu", "qualcomm", "elf", "high")
        # Qualcomm PIL (single-file or split .b0X)
        if _is_qcom_filename(name):
            cat = _category_from_qcom_name(name)
            return Classification(cat, "qualcomm", "qcom_mbn", "high")
        # Venus video codec / IPA network accel (Qualcomm)
        if _VENUS_RE.match(name) or _IPA_RE.match(name):
            return Classification("other", "qualcomm", "elf", "medium")
        # In Qualcomm firmware-mount partition — likely PIL ELF
        if any(hint in lpath for hint in _FW_PARTITION_HINTS):
            return Classification("other", "qualcomm", "elf", "low")
        return Classification("other", "unknown", "elf", "low")

    # Qualcomm split PIL pieces (.b00..b0F, .mdt) even if magic didn't hit ELF at .bNN start
    if primary is None and _is_qcom_filename(name):
        cat = _category_from_qcom_name(name)
        return Classification(cat, "qualcomm", "qcom_mbn", "medium")

    # Broadcom Wi-Fi firmware
    if primary is None and _BRCM_WIFI_RE.match(name):
        return Classification("wifi", "broadcom", "fw_bcm", "high")
    # Broadcom / Cypress Bluetooth HCD
    if primary is None and _BRCM_BT_RE.match(name):
        return Classification("bluetooth", "broadcom", "raw_bin", "high")
    # Realtek Wi-Fi
    if primary is None and _RTL_WIFI_RE.match(name):
        return Classification("wifi", "realtek", "raw_bin", "high")
    # MediaTek Wi-Fi
    if primary is None and _MTK_WIFI_RE.match(name):
        return Classification("wifi", "mediatek", "raw_bin", "high")

    # Goodix touch/fingerprint
    if primary is None and _GOODIX_RE.match(name):
        if "goodix_fp" in lpath or "fingerprint" in lpath:
            return Classification("fingerprint", "unknown", "raw_bin", "medium")
        if "goodix_touch" in lpath or "touch" in lpath:
            return Classification("touchpad", "unknown", "raw_bin", "medium")
        return Classification("fingerprint", "unknown", "raw_bin", "low")
    # Silead touch/fingerprint (primarily fingerprint)
    if primary is None and _SILEAD_RE.match(name):
        return Classification("fingerprint", "unknown", "raw_bin", "medium")

    # Touchscreen controllers
    if primary is None and (
        _SYNAPTICS_TOUCH_RE.match(name)
        or _FT_TOUCH_RE.match(name)
        or _HIMAX_TOUCH_RE.match(name)
    ):
        return Classification("touchpad", "unknown", "raw_bin", "medium")

    # NFC controller
    if primary is None and _NFC_RE.match(name):
        return Classification("nfc", "unknown", "raw_bin", "medium")

    # Kinibi TA by extension (.tlbin) when magic didn't match TRUS (some variants)
    if primary is None and (_TLBIN_RE.search(lname) or "mcregistry" in lpath):
        return Classification("tee", "unknown", "kinibi_mclf", "medium")

    # DTB/DTBO files by extension without matching magic (unlikely but cheap)
    if primary is None and (lname.endswith(".dtb") or lname.endswith(".dtbo")):
        fmt = "dtbo" if lname.endswith(".dtbo") else "dtb"
        return Classification("dtb", "unknown", fmt, "medium")

    if primary is not None:
        return primary

    # Nothing matched — skip.
    return None
