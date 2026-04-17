"""Unit tests for per-format hardware firmware parsers (Phase 2).

Fixtures are synthesized at test time from ``tests.fixtures.hardware_firmware``
— no binary fixture files are checked in.  Each parser gets its own positive
case plus a shared malformed-input test to confirm graceful error handling.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services.hardware_firmware.parsers import PARSER_REGISTRY, ParsedBlob, get_parser
from app.services.hardware_firmware.parsers.base import Parser  # noqa: F401 - Protocol import
from tests.fixtures.hardware_firmware._build_fixtures import (
    build_broadcom_firmware,
    build_high_entropy_blob,
    build_mbn_v3,
    build_minimal_dtb,
    build_minimal_dtbo,
    build_minimal_ko,
    build_minimal_optee_ta,
    build_raw_bin_with_version,
    build_self_signed_cert_der,
    write_fixture,
)

# Skip whole module gracefully if `fdt` is missing — the test host doesn't
# always have it installed (Docker builds always do).
fdt = pytest.importorskip("fdt")


_EXPECTED_FORMATS = {
    "qcom_mbn",
    "mbn_v3",
    "mbn_v5",
    "mbn_v6",
    "dtb",
    "dtbo",
    "ko",
    "optee_ta",
    "fw_bcm",
    "raw_bin",
}


# -----------------------------------------------------------------------------
# Registry coverage.
# -----------------------------------------------------------------------------


def test_parser_registry_contains_all_formats() -> None:
    """Every format the detector may emit must map to a parser instance."""
    missing = _EXPECTED_FORMATS - set(PARSER_REGISTRY.keys())
    assert not missing, f"missing parsers for formats: {missing}"

    for fmt in _EXPECTED_FORMATS:
        parser = get_parser(fmt)
        assert parser is not None
        assert hasattr(parser, "parse")


# -----------------------------------------------------------------------------
# DTB parser.
# -----------------------------------------------------------------------------


def _read_magic(path: Path, n: int = 64) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def test_dtb_parser_extracts_compatible_and_firmware_names(tmp_path: Path) -> None:
    blob = build_minimal_dtb()
    dtb_path = tmp_path / "platform.dtb"
    write_fixture(dtb_path, blob)

    parser = get_parser("dtb")
    assert parser is not None
    result = parser.parse(str(dtb_path), _read_magic(dtb_path), len(blob))

    assert isinstance(result, ParsedBlob)
    assert result.signed == "unsigned"
    compats = result.metadata.get("compatible_strings") or []
    assert "wairz,test-v1" in compats
    assert "qcom,sm8450-test" in compats
    assert "qcom,wcn6750-wifi" in compats

    firmware_names = result.metadata.get("firmware_names") or []
    assert "wcn6750.bin" in firmware_names

    # Chipset should derive from the qcom,sm8450-test compatible string.
    assert result.chipset_target is not None
    assert "sm8450" in result.chipset_target.lower()


def test_dtbo_parser_aggregates_entries(tmp_path: Path) -> None:
    inner = build_minimal_dtb()
    blob = build_minimal_dtbo([inner, inner])
    dtbo_path = tmp_path / "overlay.dtbo"
    write_fixture(dtbo_path, blob)

    parser = get_parser("dtbo")
    assert parser is not None
    result = parser.parse(str(dtbo_path), _read_magic(dtbo_path), len(blob))

    assert result.signed == "unsigned"
    meta = result.metadata
    assert meta.get("container") == "dtbo"
    assert meta.get("dt_entry_count") == 2
    assert len(meta.get("dtb_entries") or []) == 2
    # Aggregated compatibles/firmware_names include sub-DTB values.
    compats = meta.get("compatible_strings") or []
    assert any("sm8450" in c for c in compats)
    fws = meta.get("firmware_names") or []
    assert "wcn6750.bin" in fws


# -----------------------------------------------------------------------------
# Kernel module (.ko) parser.
# -----------------------------------------------------------------------------


def test_kmod_parser_extracts_modinfo(tmp_path: Path) -> None:
    pytest.importorskip("elftools")
    blob = build_minimal_ko(
        [
            ("license", "GPL"),
            ("version", "1.2.3"),
            ("srcversion", "ABCDEF0123456789"),
            ("vermagic", "5.10.0 SMP preempt mod_unload aarch64"),
            ("depends", "cfg80211,mac80211"),
            ("alias", "pci:v00001234d0000ABCD"),
            ("firmware", "wcn6750.bin"),
            ("firmware", "athwlan.bin"),
        ]
    )
    ko_path = tmp_path / "test.ko"
    write_fixture(ko_path, blob)

    parser = get_parser("ko")
    assert parser is not None
    result = parser.parse(str(ko_path), _read_magic(ko_path), len(blob))

    assert result.version == "1.2.3"
    meta = result.metadata
    assert meta.get("license") == "GPL"
    assert meta.get("vermagic", "").startswith("5.10.0")
    assert meta.get("firmware_deps") == ["wcn6750.bin", "athwlan.bin"]
    assert "cfg80211" in (meta.get("depends") or [])
    assert "mac80211" in (meta.get("depends") or [])
    # Phase 2: leading semver is exposed for the Tier 4 kernel_cpe matcher.
    assert meta.get("kernel_semver") == "5.10.0"


def test_kmod_parser_extracts_android_kernel_semver(tmp_path: Path) -> None:
    """An Android vermagic string like ``6.6.102-android15-8-g...`` yields
    a clean ``6.6.102`` in ``metadata.kernel_semver``."""
    pytest.importorskip("elftools")
    blob = build_minimal_ko(
        [
            ("license", "GPL v2"),
            ("vermagic", "6.6.102-android15-8-g123456789abc SMP preempt mod_unload aarch64"),
        ]
    )
    ko_path = tmp_path / "bluetooth.ko"
    write_fixture(ko_path, blob)

    parser = get_parser("ko")
    assert parser is not None
    result = parser.parse(str(ko_path), _read_magic(ko_path), len(blob))

    meta = result.metadata
    assert meta.get("kernel_semver") == "6.6.102"


def test_kmod_parser_omits_kernel_semver_when_vermagic_missing(tmp_path: Path) -> None:
    """No vermagic → no ``kernel_semver`` key (not just a None value)."""
    pytest.importorskip("elftools")
    blob = build_minimal_ko(
        [
            ("license", "GPL"),
            ("srcversion", "1234567890ABCDEF"),
        ]
    )
    ko_path = tmp_path / "nomagic.ko"
    write_fixture(ko_path, blob)

    parser = get_parser("ko")
    assert parser is not None
    result = parser.parse(str(ko_path), _read_magic(ko_path), len(blob))

    # vermagic is None so kernel_semver should NOT be set.
    assert "kernel_semver" not in result.metadata


def test_kmod_parser_detects_appended_signature(tmp_path: Path) -> None:
    pytest.importorskip("elftools")
    blob = build_minimal_ko(
        [("license", "GPL"), ("version", "2.0.0")],
        with_signature=True,
    )
    ko_path = tmp_path / "signed.ko"
    write_fixture(ko_path, blob)

    parser = get_parser("ko")
    assert parser is not None
    result = parser.parse(str(ko_path), _read_magic(ko_path), len(blob))

    assert result.signed == "signed"
    assert result.signature_algorithm == "CMS (kernel module)"


# -----------------------------------------------------------------------------
# OP-TEE TA parser.
# -----------------------------------------------------------------------------


def test_optee_ta_parser_extracts_uuid(tmp_path: Path) -> None:
    pytest.importorskip("lief")
    uuid_bytes = bytes.fromhex("0123456789abcdef0011223344556677")
    blob = build_minimal_optee_ta(uuid_bytes, ta_version="3.1.4")
    ta_path = tmp_path / "trusted_app.ta"
    write_fixture(ta_path, blob)

    parser = get_parser("optee_ta")
    assert parser is not None
    result = parser.parse(str(ta_path), _read_magic(ta_path), len(blob))

    assert result.signed == "signed"
    assert result.signature_algorithm == "RSA-SHA256"
    assert result.cert_subject == "OP-TEE TA Signing"
    assert result.metadata.get("ta_uuid") == "01234567-89ab-cdef-0011-223344556677"
    assert result.version == "3.1.4"


# -----------------------------------------------------------------------------
# Qualcomm MBN parser.
# -----------------------------------------------------------------------------


def test_qualcomm_mbn_v3_parser_extracts_header_fields(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    cert_der = build_self_signed_cert_der("Wairz Test Signer")
    blob = build_mbn_v3(
        image_id=12,
        code=b"CODE" * 64,
        sig=b"SIG" * 32,
        cert_chain=cert_der,
        version_string="SDM660.MBN.1.0",
    )
    mbn_path = tmp_path / "tz.mbn"
    write_fixture(mbn_path, blob)

    parser = get_parser("mbn_v3")
    assert parser is not None
    result = parser.parse(str(mbn_path), _read_magic(mbn_path), len(blob))

    meta = result.metadata
    # Header parsed.
    assert meta.get("mbn_header_version") in {"v3", "v5_or_v6"}  # v3 expected for this fixture
    assert meta.get("image_id") == 12
    assert meta.get("codeword") == "0x844bdcd1"
    assert meta.get("magic") == "0x73d71034"
    # Version string scan hit.
    assert "qc_image_version_string" in meta
    # Cert chain extraction from the raw-header tail: leaf subject must
    # resolve to the CN we embedded.
    assert result.cert_subject is not None
    assert "Wairz Test Signer" in result.cert_subject
    assert result.signature_algorithm is not None
    assert "RSA" in result.signature_algorithm
    # Scan should pick up SDM660 from the embedded version string.
    if result.chipset_target:
        assert result.chipset_target.upper().startswith("SDM")


def test_qualcomm_mbn_v3_non_elf_signs_when_sig_present(tmp_path: Path) -> None:
    """A raw MBN v3 with non-zero sig_size should report signed=signed."""
    blob = build_mbn_v3(sig=b"X" * 128, cert_chain=b"")
    mbn_path = tmp_path / "sbl1.mbn"
    write_fixture(mbn_path, blob)

    parser = get_parser("mbn_v3")
    assert parser is not None
    result = parser.parse(str(mbn_path), _read_magic(mbn_path), len(blob))
    assert result.signed == "signed"


# -----------------------------------------------------------------------------
# Broadcom Wi-Fi parser.
# -----------------------------------------------------------------------------


def test_broadcom_wl_parser_extracts_version(tmp_path: Path) -> None:
    version = "7.35.180.11"
    blob = build_broadcom_firmware(version)
    fw_path = tmp_path / "brcmfmac43430-sdio.bin"
    write_fixture(fw_path, blob)

    parser = get_parser("fw_bcm")
    assert parser is not None
    result = parser.parse(str(fw_path), _read_magic(fw_path), len(blob))

    assert result.signed == "unsigned"
    assert result.version is not None
    assert version in result.version
    assert result.chipset_target is not None
    assert "43430" in result.chipset_target
    assert result.metadata.get("fw_version_raw") is not None


def test_broadcom_wl_parser_detects_paired_nvram(tmp_path: Path) -> None:
    blob = build_broadcom_firmware("7.35.180.11")
    fw_path = tmp_path / "brcmfmac4366c-pcie.bin"
    write_fixture(fw_path, blob)
    # Write paired NVRAM alongside.
    nvram = tmp_path / "brcmfmac4366c-pcie.txt"
    nvram.write_text("nvram_version=1.0\nboardrev=0x1234\n")

    parser = get_parser("fw_bcm")
    assert parser is not None
    result = parser.parse(str(fw_path), _read_magic(fw_path), len(blob))
    assert result.metadata.get("nvram_present") is True
    nv = result.metadata.get("nvram") or {}
    assert nv.get("nvram_version") == "1.0"


# -----------------------------------------------------------------------------
# Raw binary fallback.
# -----------------------------------------------------------------------------


def test_raw_bin_parser_extracts_version_and_entropy(tmp_path: Path) -> None:
    blob = build_raw_bin_with_version("1.2.3")
    bin_path = tmp_path / "touchpad.bin"
    write_fixture(bin_path, blob)

    parser = get_parser("raw_bin")
    assert parser is not None
    result = parser.parse(str(bin_path), _read_magic(bin_path), len(blob))

    assert result.signed == "unknown"
    assert result.version == "1.2.3"
    assert isinstance(result.metadata.get("entropy"), float)
    assert 0.0 <= result.metadata["entropy"] <= 8.0


def test_raw_bin_parser_flags_high_entropy(tmp_path: Path) -> None:
    blob = build_high_entropy_blob(4096)
    bin_path = tmp_path / "encrypted.bin"
    write_fixture(bin_path, blob)

    parser = get_parser("raw_bin")
    assert parser is not None
    result = parser.parse(str(bin_path), _read_magic(bin_path), len(blob))
    assert result.metadata["entropy"] > 7.0
    # Pseudo-random SHA-256 stream should trigger the high-entropy note.
    if result.metadata["entropy"] > 7.5:
        assert "high entropy" in (result.metadata.get("note") or "").lower()


# -----------------------------------------------------------------------------
# Malformed-input defense: every parser must handle zero / truncated bytes.
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", sorted(_EXPECTED_FORMATS))
def test_parser_handles_malformed_bytes_gracefully(tmp_path: Path, fmt: str) -> None:
    parser = get_parser(fmt)
    assert parser is not None, f"no parser for {fmt}"

    # Empty file.
    empty = tmp_path / f"empty_{fmt}.bin"
    empty.write_bytes(b"")
    res = parser.parse(str(empty), b"", 0)
    assert isinstance(res, ParsedBlob)

    # A few random bytes.
    junk = tmp_path / f"junk_{fmt}.bin"
    junk.write_bytes(b"\x00" * 64)
    res2 = parser.parse(str(junk), b"\x00" * 64, 64)
    assert isinstance(res2, ParsedBlob)

    # A random ELF-ish prefix (no valid structure past the magic).
    elfish = tmp_path / f"elfish_{fmt}.bin"
    elfish.write_bytes(b"\x7fELF" + b"\x41" * 200)
    res3 = parser.parse(str(elfish), b"\x7fELF" + b"\x41" * 60, 204)
    assert isinstance(res3, ParsedBlob)
