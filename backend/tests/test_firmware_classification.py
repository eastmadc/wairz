"""Tests for firmware classification in the unpack worker."""

import tarfile
import zipfile
from pathlib import Path

import pytest

from app.workers.unpack import classify_firmware


class TestAndroidOtaDetection:
    """Test classify_firmware() recognises Android OTA ZIP files."""

    def test_zip_with_payload_bin(self, tmp_path: Path):
        """A ZIP containing payload.bin is classified as android_ota."""
        zip_path = tmp_path / "ota.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("payload.bin", b"\x00" * 16)
        assert classify_firmware(str(zip_path)) == "android_ota"

    def test_zip_with_system_and_boot_img(self, tmp_path: Path):
        """A ZIP containing system.img + boot.img (>= 2 markers) is android_ota."""
        zip_path = tmp_path / "ota.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system.img", b"\x00" * 16)
            zf.writestr("boot.img", b"\x00" * 16)
        assert classify_firmware(str(zip_path)) == "android_ota"

    def test_zip_with_system_img_only(self, tmp_path: Path):
        """A ZIP containing only system.img still counts as android_ota."""
        zip_path = tmp_path / "ota.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system.img", b"\x00" * 16)
        assert classify_firmware(str(zip_path)) == "android_ota"

    def test_zip_with_meta_inf_android(self, tmp_path: Path):
        """A ZIP with updater-script + update-binary (OTA metadata) is android_ota."""
        zip_path = tmp_path / "ota.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("META-INF/com/google/android/updater-script", "")
            zf.writestr("META-INF/com/google/android/update-binary", b"\x00")
        assert classify_firmware(str(zip_path)) == "android_ota"

    def test_zip_without_android_markers_not_ota(self, tmp_path: Path):
        """A generic ZIP without Android markers is NOT classified as android_ota."""
        zip_path = tmp_path / "generic.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("readme.txt", "Hello")
            zf.writestr("data.bin", b"\x00" * 16)
        result = classify_firmware(str(zip_path))
        assert result != "android_ota"


class TestAndroidSparseImageDetection:
    """Test classify_firmware() recognises Android sparse images."""

    def test_sparse_magic_bytes(self, tmp_path: Path):
        """A file starting with 0x3AFF26ED (little-endian) is android_sparse."""
        sparse_path = tmp_path / "system.img"
        sparse_path.write_bytes(b"\x3a\xff\x26\xed" + b"\x00" * 64)
        assert classify_firmware(str(sparse_path)) == "android_sparse"

    def test_wrong_magic_not_sparse(self, tmp_path: Path):
        """A file with similar but wrong magic bytes is NOT android_sparse."""
        path = tmp_path / "not_sparse.img"
        path.write_bytes(b"\x3a\xff\x26\xee" + b"\x00" * 64)
        assert classify_firmware(str(path)) != "android_sparse"


class TestLinuxRootfsTarDetection:
    """Test classify_firmware() recognises Linux rootfs tar archives."""

    def test_tar_with_linux_dirs(self, tmp_path: Path):
        """A tar containing standard Linux dirs is classified as linux_rootfs_tar."""
        tar_path = tmp_path / "rootfs.tar"
        with tarfile.open(tar_path, "w") as tf:
            for dirname in ("etc", "usr", "bin", "lib"):
                info = tarfile.TarInfo(name=dirname)
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
        assert classify_firmware(str(tar_path)) == "linux_rootfs_tar"


class TestElfBinaryDetection:
    """Test classify_firmware() recognises ELF binaries."""

    def test_elf_magic(self, tmp_path: Path):
        """A file with ELF magic \\x7fELF is classified as elf_binary."""
        elf_path = tmp_path / "firmware.elf"
        elf_path.write_bytes(b"\x7fELF" + b"\x00" * 60)
        assert classify_firmware(str(elf_path)) == "elf_binary"


class TestUnknownAndEdgeCases:
    """Test fallback and edge-case handling."""

    def test_unknown_format_returns_linux_blob(self, tmp_path: Path):
        """An unrecognised binary blob returns linux_blob (for binwalk)."""
        blob_path = tmp_path / "mystery.bin"
        blob_path.write_bytes(b"\xde\xad\xbe\xef" + b"\x00" * 64)
        assert classify_firmware(str(blob_path)) == "linux_blob"

    def test_empty_file(self, tmp_path: Path):
        """An empty file does not crash and returns a valid classification."""
        empty_path = tmp_path / "empty"
        empty_path.write_bytes(b"")
        result = classify_firmware(str(empty_path))
        assert result in (
            "android_ota", "android_sparse", "linux_rootfs_tar",
            "linux_blob", "elf_binary", "intel_hex", "pe_binary", "unknown",
        )

    def test_pe_binary_detection(self, tmp_path: Path):
        """A file starting with MZ is classified as pe_binary."""
        pe_path = tmp_path / "firmware.exe"
        pe_path.write_bytes(b"MZ" + b"\x00" * 64)
        assert classify_firmware(str(pe_path)) == "pe_binary"
