"""Tests for the network dependency detection (S21, in security_audit_service)."""

from pathlib import Path

import pytest

from app.services.security_audit_service import (
    SecurityFinding,
    _scan_network_dependencies,
)


@pytest.fixture
def nfs_firmware(tmp_path: Path) -> Path:
    """Firmware with NFS exports using no_root_squash (detected by scanner)."""
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "exports").write_text(
        "/data 192.168.1.0/24(rw,no_root_squash,sync)\n"
    )
    return tmp_path


@pytest.fixture
def cifs_firmware(tmp_path: Path) -> Path:
    """Firmware with CIFS mount containing inline credentials."""
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "fstab").write_text(
        "//server/share /mnt/share cifs username=admin,password=secret 0 0\n"
    )
    return tmp_path


@pytest.fixture
def clean_firmware(tmp_path: Path) -> Path:
    """Firmware with no network dependencies."""
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "hostname").write_text("clean-device\n")
    return tmp_path


class TestNetworkDependencyDetection:
    def test_detects_nfs_no_root_squash(self, nfs_firmware: Path):
        findings: list[SecurityFinding] = []
        _scan_network_dependencies(str(nfs_firmware), findings)
        assert len(findings) >= 1
        titles = [f.title.lower() for f in findings]
        assert any("nfs" in t or "no_root_squash" in t for t in titles), f"Expected NFS finding in {titles}"

    def test_detects_cifs_credentials(self, cifs_firmware: Path):
        findings: list[SecurityFinding] = []
        _scan_network_dependencies(str(cifs_firmware), findings)
        assert len(findings) >= 1
        titles = [f.title.lower() for f in findings]
        assert any("cifs" in t or "credential" in t for t in titles), f"Expected CIFS finding in {titles}"

    def test_clean_firmware_no_findings(self, clean_firmware: Path):
        findings: list[SecurityFinding] = []
        _scan_network_dependencies(str(clean_firmware), findings)
        assert len(findings) == 0

    def test_findings_have_severity(self, nfs_firmware: Path):
        findings: list[SecurityFinding] = []
        _scan_network_dependencies(str(nfs_firmware), findings)
        for f in findings:
            assert f.severity in ("critical", "high", "medium", "low", "info")

    def test_findings_have_cwe(self, nfs_firmware: Path):
        findings: list[SecurityFinding] = []
        _scan_network_dependencies(str(nfs_firmware), findings)
        for f in findings:
            assert f.cwe_ids is not None
