"""Shared test fixtures for the Wairz backend test suite."""

import os
from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4

import pytest


@pytest.fixture
def firmware_root(tmp_path: Path) -> Path:
    """Create a standard test firmware filesystem.

    Provides a minimal but realistic embedded Linux layout with directories,
    config files, fake ELF binaries, symlinks, and a certificate.
    """
    # Directories
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "init.d").mkdir()
    (tmp_path / "usr").mkdir()
    (tmp_path / "usr" / "bin").mkdir()
    (tmp_path / "bin").mkdir()
    (tmp_path / "var").mkdir()
    (tmp_path / "lib").mkdir()

    # Text files
    (tmp_path / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:Nobody:/:/bin/false\n"
    )
    (tmp_path / "etc" / "shadow").write_text("root::0:0:99999:7:::\n")
    (tmp_path / "etc" / "config.conf").write_text(
        "[server]\nport=8080\ndebug=true\n"
    )
    (tmp_path / "etc" / "init.d" / "rcS").write_bytes(
        b"#!/bin/sh\necho 'Starting services...'\n"
    )

    # Fake ELF binary (valid magic, minimal header)
    elf_header = b"\x7fELF" + b"\x00" * 12
    (tmp_path / "usr" / "bin" / "httpd").write_bytes(elf_header)

    # Certificate file
    (tmp_path / "etc" / "server.pem").write_text(
        "-----BEGIN CERTIFICATE-----\nMIIBojCCAUmgAwIBAgI...\n-----END CERTIFICATE-----\n"
    )

    # Shared library
    (tmp_path / "lib" / "libfoo.so.1").write_bytes(b"\x7fELF" + b"\x00" * 12)

    # Symlink (internal — points within the firmware root)
    (tmp_path / "bin" / "sh").symlink_to(str(tmp_path / "usr" / "bin" / "httpd"))

    return tmp_path


@pytest.fixture
def tool_context(firmware_root: Path):
    """Create a ToolContext with a mocked DB session pointed at firmware_root.

    Import is deferred to avoid pulling in heavy dependencies (elftools, etc.)
    when only lightweight tests are running.
    """
    from app.ai.tool_registry import ToolContext

    return ToolContext(
        project_id=uuid4(),
        firmware_id=uuid4(),
        extracted_path=str(firmware_root),
        db=MagicMock(),
    )
