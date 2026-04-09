"""Tests for the RTOS/bare-metal detection service (S13)."""

from pathlib import Path

import pytest

from app.services.rtos_detection_service import detect_rtos


@pytest.fixture
def freertos_binary(tmp_path: Path) -> Path:
    """Create a fake binary containing FreeRTOS signatures."""
    binary = tmp_path / "firmware.bin"
    # FreeRTOS signature strings embedded in binary
    content = b"\x00" * 64
    content += b"xTaskCreate\x00"
    content += b"vTaskDelay\x00"
    content += b"xQueueSend\x00"
    content += b"FreeRTOS V10.4.3\x00"
    content += b"\x00" * 64
    binary.write_bytes(content)
    return str(binary)


@pytest.fixture
def vxworks_binary(tmp_path: Path) -> Path:
    """Create a fake binary containing VxWorks signatures."""
    binary = tmp_path / "firmware.bin"
    content = b"\x00" * 64
    content += b"taskSpawn\x00"
    content += b"semTake\x00"
    content += b"Wind River Systems\x00"
    content += b"VxWorks\x00"
    content += b"\x00" * 64
    binary.write_bytes(content)
    return str(binary)


@pytest.fixture
def linux_binary(tmp_path: Path) -> Path:
    """Create a binary that is NOT an RTOS."""
    binary = tmp_path / "vmlinuz"
    # Linux kernel signature
    content = b"\x7fELF" + b"\x00" * 12
    content += b"Linux version 5.10.0\x00"
    content += b"\x00" * 64
    binary.write_bytes(content)
    return str(binary)


@pytest.fixture
def empty_binary(tmp_path: Path) -> Path:
    binary = tmp_path / "empty.bin"
    binary.write_bytes(b"\x00" * 128)
    return str(binary)


class TestRtosDetection:
    def test_detects_freertos(self, freertos_binary: str):
        result = detect_rtos(freertos_binary)
        assert result is not None
        assert result["rtos_name"].lower() == "freertos"
        assert result["confidence"] in ("high", "medium")

    def test_detects_vxworks(self, vxworks_binary: str):
        result = detect_rtos(vxworks_binary)
        assert result is not None
        assert result["rtos_name"].lower() == "vxworks"

    def test_no_rtos_in_linux(self, linux_binary: str):
        result = detect_rtos(linux_binary)
        # Should return None or a non-RTOS classification
        if result is not None:
            assert result["rtos_name"].lower() != "freertos"
            assert result["rtos_name"].lower() != "vxworks"

    def test_empty_binary(self, empty_binary: str):
        result = detect_rtos(empty_binary)
        # Should return None for empty/unknown binary
        assert result is None

    def test_result_structure(self, freertos_binary: str):
        result = detect_rtos(freertos_binary)
        assert result is not None
        assert "rtos_name" in result
        assert "rtos_display_name" in result
        assert "confidence" in result
        assert "detection_methods" in result
        assert isinstance(result["detection_methods"], list)
