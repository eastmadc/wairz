"""Tests for the attack surface scoring service (S19)."""

import os
from pathlib import Path

import pytest

from app.services.attack_surface_service import scan_attack_surface


@pytest.fixture
def attack_surface_root(tmp_path: Path) -> Path:
    """Create a firmware filesystem with various attack surface indicators."""
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "usr" / "sbin").mkdir(parents=True)
    (tmp_path / "etc" / "init.d").mkdir(parents=True)
    (tmp_path / "bin").mkdir(exist_ok=True)

    # Fake ELF binaries
    elf = b"\x7fELF" + b"\x00" * 12
    (tmp_path / "usr" / "bin" / "httpd").write_bytes(elf)
    (tmp_path / "usr" / "bin" / "dropbear").write_bytes(elf)
    (tmp_path / "usr" / "sbin" / "dnsmasq").write_bytes(elf)

    # Setuid binary
    suid = tmp_path / "usr" / "bin" / "busybox"
    suid.write_bytes(elf)
    os.chmod(suid, 0o4755)

    # Init script referencing a daemon
    (tmp_path / "etc" / "init.d" / "S50httpd").write_text(
        "#!/bin/sh\n/usr/bin/httpd -p 80 -h /www\n"
    )

    return tmp_path


class TestAttackSurface:
    def test_scan_finds_binaries(self, attack_surface_root: Path):
        results = scan_attack_surface(str(attack_surface_root))
        assert isinstance(results, list)
        assert len(results) > 0

    def test_scan_returns_scores(self, attack_surface_root: Path):
        results = scan_attack_surface(str(attack_surface_root))
        for r in results:
            assert hasattr(r, "score") or "score" in (r.__dict__ if hasattr(r, "__dict__") else {})

    def test_scan_empty_directory(self, tmp_path: Path):
        results = scan_attack_surface(str(tmp_path))
        assert isinstance(results, list)
        assert len(results) == 0

    def test_known_daemon_detected(self, attack_surface_root: Path):
        results = scan_attack_surface(str(attack_surface_root))
        binary_names = []
        for r in results:
            name = getattr(r, "binary_name", None) or getattr(r, "name", "")
            binary_names.append(name)
        # httpd or dnsmasq or dropbear should be detected as known daemons
        assert any(
            n in ("httpd", "dnsmasq", "dropbear") for n in binary_names
        ), f"Expected known daemon in {binary_names}"
