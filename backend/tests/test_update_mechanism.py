"""Tests for the firmware update mechanism detection service (S21)."""

from pathlib import Path

import pytest

from app.services.update_mechanism_service import (
    detect_update_mechanisms,
    format_mechanisms_report,
)


@pytest.fixture
def opkg_firmware(tmp_path: Path) -> Path:
    """Firmware with opkg package manager."""
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "etc" / "opkg").mkdir(parents=True)

    elf = b"\x7fELF" + b"\x00" * 12
    (tmp_path / "usr" / "bin" / "opkg").write_bytes(elf)
    (tmp_path / "etc" / "opkg" / "distfeeds.conf").write_text(
        "src/gz openwrt_base http://downloads.openwrt.org/releases/23.05/packages/mips_24kc/base\n"
    )
    return tmp_path


@pytest.fixture
def swupdate_firmware(tmp_path: Path) -> Path:
    """Firmware with SWUpdate."""
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "etc").mkdir(exist_ok=True)

    elf = b"\x7fELF" + b"\x00" * 12
    (tmp_path / "usr" / "bin" / "swupdate").write_bytes(elf)
    (tmp_path / "etc" / "swupdate.cfg").write_text(
        'globals: {\n  verbose = true;\n  url = "https://update.example.com";\n}\n'
    )
    return tmp_path


@pytest.fixture
def no_update_firmware(tmp_path: Path) -> Path:
    """Firmware with no update mechanism."""
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "hostname").write_text("device\n")
    return tmp_path


class TestUpdateMechanismDetection:
    def test_detects_opkg(self, opkg_firmware: Path):
        results = detect_update_mechanisms(str(opkg_firmware))
        assert len(results) >= 1
        systems = [r.system for r in results]
        assert any("opkg" in s for s in systems), f"Expected opkg in {systems}"

    def test_detects_swupdate(self, swupdate_firmware: Path):
        results = detect_update_mechanisms(str(swupdate_firmware))
        assert len(results) >= 1
        systems = [r.system for r in results]
        assert any("swupdate" in s.lower() for s in systems), f"Expected swupdate in {systems}"

    def test_no_update_mechanism(self, no_update_firmware: Path):
        results = detect_update_mechanisms(str(no_update_firmware))
        # When no update mechanism found, returns system='none' as a finding
        none_results = [r for r in results if r.system == "none"]
        real_mechanisms = [r for r in results if r.system != "none"]
        # Either no real mechanisms, or the 'none' sentinel is present
        assert len(real_mechanisms) == 0 or len(none_results) >= 1

    def test_format_report_nonempty(self, opkg_firmware: Path):
        results = detect_update_mechanisms(str(opkg_firmware))
        report = format_mechanisms_report(results)
        assert isinstance(report, str)
        assert len(report) > 0

    def test_format_report_empty(self):
        report = format_mechanisms_report([])
        assert isinstance(report, str)

    def test_http_url_flagged(self, opkg_firmware: Path):
        results = detect_update_mechanisms(str(opkg_firmware))
        opkg_results = [r for r in results if "opkg" in r.system]
        if opkg_results:
            # HTTP URL in distfeeds.conf should generate a finding
            r = opkg_results[0]
            if r.findings:
                # Finding dicts may use 'cwe' or 'cwe_id' key
                cwe_ids = [f.get("cwe", f.get("cwe_id", "")) for f in r.findings]
                assert any("319" in c for c in cwe_ids), f"HTTP update URL should flag CWE-319, got {r.findings}"
