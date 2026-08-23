"""Tests for the FirmwareService and its helper functions.

Helper functions (_sanitize_filename, _zip_contains_rootfs, etc.) are tested
with real filesystem operations. The FirmwareService class methods that need
a DB session use mocks.
"""

import os
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.firmware_service import (
    FirmwareService,
    _extract_firmware_from_zip,
    _firmware_tar_filter,
    _is_android_firmware_zip,
    _sanitize_filename,
    _zip_contains_rootfs,
)

# ---------------------------------------------------------------------------
# _sanitize_filename
# ---------------------------------------------------------------------------

class TestSanitizeFilename:
    def test_normal_filename(self):
        assert _sanitize_filename("firmware.bin") == "firmware.bin"

    def test_strips_path_components(self):
        assert _sanitize_filename("/etc/passwd") == "passwd"

    def test_strips_traversal(self):
        assert _sanitize_filename("../../../etc/shadow") == "shadow"

    def test_replaces_special_chars(self):
        result = _sanitize_filename("firmware (v2) [test].bin")
        assert "(" not in result
        assert "[" not in result
        assert result.endswith(".bin")

    def test_strips_leading_dots(self):
        result = _sanitize_filename(".hidden_firmware")
        assert not result.startswith(".")

    def test_strips_leading_underscores(self):
        result = _sanitize_filename("___firmware.bin")
        assert result == "firmware.bin"

    def test_truncates_long_filename(self):
        result = _sanitize_filename("a" * 300 + ".bin")
        assert len(result) <= 200

    def test_empty_becomes_default(self):
        assert _sanitize_filename("") == "firmware.bin"

    def test_dots_only_becomes_default(self):
        assert _sanitize_filename("...") == "firmware.bin"

    def test_windows_path(self):
        result = _sanitize_filename("C:\\Users\\admin\\firmware.bin")
        # os.path.basename handles this correctly on Linux
        assert "firmware" in result

    def test_collapses_consecutive_underscores(self):
        result = _sanitize_filename("firm   ware.bin")
        assert "___" not in result


# ---------------------------------------------------------------------------
# _zip_contains_rootfs
# ---------------------------------------------------------------------------

class TestZipContainsRootfs:
    def test_rootfs_at_top_level(self, tmp_path: Path):
        zp = tmp_path / "rootfs.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("etc/passwd", "root:x:0:0::/root:/bin/sh")
            zf.writestr("usr/bin/foo", "")
            zf.writestr("bin/sh", "")
            zf.writestr("lib/libc.so", "")
        assert _zip_contains_rootfs(str(zp)) is True

    def test_rootfs_in_wrapper_dir(self, tmp_path: Path):
        zp = tmp_path / "rootfs.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("rootfs/etc/passwd", "root:x:0:0::/root:/bin/sh")
            zf.writestr("rootfs/usr/bin/foo", "")
            zf.writestr("rootfs/bin/sh", "")
            zf.writestr("rootfs/lib/libc.so", "")
        assert _zip_contains_rootfs(str(zp)) is True

    def test_non_rootfs_zip(self, tmp_path: Path):
        zp = tmp_path / "generic.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("readme.txt", "Hello")
            zf.writestr("data/config.json", "{}")
        assert _zip_contains_rootfs(str(zp)) is False

    def test_partial_markers_not_enough(self, tmp_path: Path):
        """Need 3+ Linux root directories to classify as rootfs."""
        zp = tmp_path / "partial.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("etc/passwd", "root")
            zf.writestr("bin/sh", "")
        assert _zip_contains_rootfs(str(zp)) is False


# ---------------------------------------------------------------------------
# _is_android_firmware_zip
# ---------------------------------------------------------------------------

class TestIsAndroidFirmwareZip:
    def test_payload_bin_detected(self, tmp_path: Path):
        zp = tmp_path / "ota.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("payload.bin", b"\x00" * 16)
        assert _is_android_firmware_zip(str(zp)) is True

    def test_meta_inf_android(self, tmp_path: Path):
        zp = tmp_path / "ota.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("META-INF/com/google/android/updater-script", "")
        assert _is_android_firmware_zip(str(zp)) is True

    def test_multiple_partitions(self, tmp_path: Path):
        zp = tmp_path / "factory.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("system.img", b"\x00" * 16)
            zf.writestr("boot.img", b"\x00" * 16)
        assert _is_android_firmware_zip(str(zp)) is True

    def test_single_partition_not_android(self, tmp_path: Path):
        zp = tmp_path / "generic.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("system.img", b"\x00" * 16)
            zf.writestr("readme.txt", "Not Android")
        assert _is_android_firmware_zip(str(zp)) is False

    def test_generic_zip_not_android(self, tmp_path: Path):
        zp = tmp_path / "generic.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("readme.txt", "Hello")
        assert _is_android_firmware_zip(str(zp)) is False


# ---------------------------------------------------------------------------
# _extract_firmware_from_zip
# ---------------------------------------------------------------------------

class TestExtractFirmwareFromZip:
    def test_extracts_largest_file(self, tmp_path: Path):
        zp = tmp_path / "firmware.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("readme.txt", "small")
            zf.writestr("firmware.bin", b"\x7fELF" + b"\x00" * 1000)
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        result = _extract_firmware_from_zip(str(zp), str(out_dir))
        assert result is not None
        assert os.path.isfile(result)
        assert os.path.basename(result) == "firmware.bin"

    def test_empty_zip_returns_none(self, tmp_path: Path):
        zp = tmp_path / "empty.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            pass  # no files
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        result = _extract_firmware_from_zip(str(zp), str(out_dir))
        assert result is None

    def test_hidden_files_skipped(self, tmp_path: Path):
        zp = tmp_path / "macos.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr(".DS_Store", "")
            zf.writestr("__MACOSX/resource", "")
            zf.writestr("firmware.bin", b"\x00" * 100)
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        result = _extract_firmware_from_zip(str(zp), str(out_dir))
        assert result is not None
        assert "firmware.bin" in result

    def test_zip_slip_prevention(self, tmp_path: Path):
        """Entries with path traversal should be skipped silently."""
        zp = tmp_path / "malicious.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            # Normal file
            zf.writestr("firmware.bin", b"\x00" * 100)
            # Malicious entry (path traversal)
            zf.writestr("../../etc/passwd", "hacked")
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        result = _extract_firmware_from_zip(str(zp), str(out_dir))
        assert result is not None
        # The traversal target should NOT exist outside output
        assert not os.path.exists(tmp_path / "etc" / "passwd")

    def test_preserves_directory_structure(self, tmp_path: Path):
        zp = tmp_path / "structured.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("subdir/firmware.bin", b"\x00" * 100)
            zf.writestr("subdir/config.txt", "test")
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        result = _extract_firmware_from_zip(str(zp), str(out_dir))
        assert result is not None
        # Both files should be extracted
        zip_contents = out_dir / "zip_contents"
        assert os.path.isfile(zip_contents / "subdir" / "config.txt")


# ---------------------------------------------------------------------------
# _firmware_tar_filter
# ---------------------------------------------------------------------------

class TestFirmwareTarFilter:
    def test_allows_regular_file(self, tmp_path: Path):
        member = tarfile.TarInfo(name="etc/passwd")
        member.type = tarfile.REGTYPE
        result = _firmware_tar_filter(member, str(tmp_path))
        assert result is not None

    def test_allows_directory(self, tmp_path: Path):
        member = tarfile.TarInfo(name="etc/")
        member.type = tarfile.DIRTYPE
        result = _firmware_tar_filter(member, str(tmp_path))
        assert result is not None

    def test_allows_symlink(self, tmp_path: Path):
        member = tarfile.TarInfo(name="bin/sh")
        member.type = tarfile.SYMTYPE
        member.linkname = "/usr/bin/bash"
        result = _firmware_tar_filter(member, str(tmp_path))
        assert result is not None

    def test_rejects_device_node(self, tmp_path: Path):
        member = tarfile.TarInfo(name="dev/sda")
        member.type = tarfile.BLKTYPE
        result = _firmware_tar_filter(member, str(tmp_path))
        assert result is None

    def test_strips_leading_slash(self, tmp_path: Path):
        member = tarfile.TarInfo(name="/etc/passwd")
        member.type = tarfile.REGTYPE
        result = _firmware_tar_filter(member, str(tmp_path))
        assert result is not None
        assert not result.name.startswith("/")

    def test_rejects_path_traversal(self, tmp_path: Path):
        member = tarfile.TarInfo(name="../../etc/shadow")
        member.type = tarfile.REGTYPE
        # The imported `_firmware_tar_filter` (from `unpack_linux`) raises
        # `tarfile.AbsolutePathError` (a `FilterError` subclass) for paths
        # that escape the destination — this replaces the prior local `ValueError`
        # behaviour as part of Phase Lint.B.2 (2026-05-10) F811 dedup.
        with pytest.raises(tarfile.AbsolutePathError):
            _firmware_tar_filter(member, str(tmp_path))


# ---------------------------------------------------------------------------
# FirmwareService DB methods (mocked)
# ---------------------------------------------------------------------------

class TestFirmwareServiceDBMethods:

    @pytest.mark.asyncio
    async def test_get_by_id_found(self):
        db = AsyncMock()
        fw = MagicMock()
        fw.id = "test-id"
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = fw
        db.execute = AsyncMock(return_value=mock_result)

        svc = FirmwareService(db)
        result = await svc.get_by_id("test-id")
        assert result is fw

    @pytest.mark.asyncio
    async def test_get_by_id_not_found(self):
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=mock_result)

        svc = FirmwareService(db)
        result = await svc.get_by_id("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_list_by_project(self):
        db = AsyncMock()
        fw_list = [MagicMock(), MagicMock()]
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = fw_list
        db.execute = AsyncMock(return_value=mock_result)

        svc = FirmwareService(db)
        result = await svc.list_by_project("project-id")
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_get_by_project_returns_first(self):
        db = AsyncMock()
        fw = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = fw
        db.execute = AsyncMock(return_value=mock_result)

        svc = FirmwareService(db)
        result = await svc.get_by_project("project-id")
        assert result is fw

    @pytest.mark.asyncio
    async def test_get_by_project_empty(self):
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=mock_result)

        svc = FirmwareService(db)
        result = await svc.get_by_project("project-id")
        assert result is None

    @staticmethod
    def _svc_with_storage_root(db, storage_root):
        """FirmwareService whose settings point at a throwaway root.

        ``delete`` is containment-checked against ``settings.storage_root``,
        so a test that writes outside it will (correctly) be refused.
        """
        settings = MagicMock()
        settings.storage_root = str(storage_root)
        svc = FirmwareService.__new__(FirmwareService)
        svc.db = db
        svc.settings = settings
        return svc

    @pytest.mark.asyncio
    async def test_delete_removes_directory(self, tmp_path: Path):
        import uuid as _uuid

        db = AsyncMock()
        db.delete = AsyncMock()
        db.flush = AsyncMock()

        project_id, firmware_id = _uuid.uuid4(), _uuid.uuid4()
        fw_dir = (
            tmp_path / "projects" / str(project_id) / "firmware" / str(firmware_id)
        )
        fw_dir.mkdir(parents=True)
        storage = fw_dir / "firmware.bin"
        storage.write_bytes(b"\x00")

        fw = MagicMock()
        fw.id = firmware_id
        fw.project_id = project_id
        fw.storage_path = str(storage)
        fw.extracted_path = None

        svc = self._svc_with_storage_root(db, tmp_path)
        await svc.delete(fw)

        db.delete.assert_awaited_once_with(fw)
        db.flush.assert_awaited_once()
        assert not fw_dir.exists()

    @pytest.mark.asyncio
    async def test_delete_removes_directory_when_storage_path_is_null(
        self, tmp_path: Path,
    ):
        """An upload aborted in ``upload_stage='detecting'`` has a directory
        on disk but no ``storage_path``. Keying cleanup off the column alone
        left those trees orphaned; the canonical path is derived from the
        row's identity instead.
        """
        import uuid as _uuid

        db = AsyncMock()
        project_id, firmware_id = _uuid.uuid4(), _uuid.uuid4()
        fw_dir = (
            tmp_path / "projects" / str(project_id) / "firmware" / str(firmware_id)
        )
        fw_dir.mkdir(parents=True)
        (fw_dir / "partial.bin").write_bytes(b"\x00" * 8)

        fw = MagicMock()
        fw.id = firmware_id
        fw.project_id = project_id
        fw.storage_path = None
        fw.extracted_path = None

        svc = self._svc_with_storage_root(db, tmp_path)
        await svc.delete(fw)

        assert not fw_dir.exists()
        db.delete.assert_awaited_once_with(fw)

    @pytest.mark.asyncio
    async def test_delete_with_extracted_path_fallback(self, tmp_path: Path):
        """Legacy rows whose extracted tree sits outside the canonical dir."""
        import uuid as _uuid

        db = AsyncMock()
        project_id, firmware_id = _uuid.uuid4(), _uuid.uuid4()
        legacy_dir = tmp_path / "projects" / str(project_id) / "legacy"
        extracted = legacy_dir / "extracted"
        (extracted / "etc").mkdir(parents=True)

        fw = MagicMock()
        fw.id = firmware_id
        fw.project_id = project_id
        fw.storage_path = None
        fw.extracted_path = str(extracted)

        svc = self._svc_with_storage_root(db, tmp_path)
        await svc.delete(fw)

        db.delete.assert_awaited_once()
        # dirname(extracted_path) is purged, the storage root is not.
        assert not legacy_dir.exists()
        assert tmp_path.exists()  # noqa: ASYNC240 — test-fixture path check; no production I/O

    @pytest.mark.asyncio
    async def test_delete_refuses_to_purge_outside_storage_root(
        self, tmp_path: Path,
    ):
        """A row pointing outside the root must not trigger a host rmtree."""
        import uuid as _uuid

        db = AsyncMock()
        storage_root = tmp_path / "storage"
        (storage_root / "projects").mkdir(parents=True)

        outside = tmp_path / "precious"
        (outside / "data").mkdir(parents=True)

        fw = MagicMock()
        fw.id = _uuid.uuid4()
        fw.project_id = _uuid.uuid4()
        fw.storage_path = str(outside / "data" / "firmware.bin")
        fw.extracted_path = None

        svc = self._svc_with_storage_root(db, storage_root)
        await svc.delete(fw)

        assert (outside / "data").exists(), (
            "delete must refuse to rmtree a path outside the storage root"
        )
        db.delete.assert_awaited_once()


# ---------------------------------------------------------------------------
# upload_bytes_only — orphan-directory cleanup on every failure path
# ---------------------------------------------------------------------------


class TestUploadBytesOnlyCleansUpOnFailure:
    """``upload_bytes_only`` mkdirs the firmware directory BEFORE the
    Firmware row exists. Every exit path between the mkdir and the commit
    must remove that directory or the bytes are orphaned with nothing in
    the DB pointing at them.

    Historically only the 409-dedup path cleaned up (and it used
    ``os.rmdir``, which silently fails on a non-empty directory). The
    413-oversize path removed the file but left the directory, and a
    client disconnect mid-stream left the full partial payload behind.
    """

    @staticmethod
    def _service(tmp_path, db=None):
        settings = MagicMock()
        settings.storage_root = str(tmp_path)
        settings.max_upload_size_mb = 1
        svc = FirmwareService.__new__(FirmwareService)
        svc.settings = settings
        svc.db = db if db is not None else AsyncMock()
        return svc

    @staticmethod
    def _upload(name, chunks):
        """Minimal UploadFile stand-in yielding ``chunks`` then b""."""
        queue = list(chunks)

        async def _read(_n):
            return queue.pop(0) if queue else b""

        f = MagicMock()
        f.filename = name
        f.size = sum(len(c) for c in chunks)
        f.read = _read
        return f

    @staticmethod
    def _project_dirs(tmp_path, project_id):
        base = Path(tmp_path) / "projects" / str(project_id) / "firmware"
        if not base.is_dir():
            return []
        return sorted(p for p in base.iterdir() if p.is_dir())

    @pytest.mark.asyncio
    async def test_oversize_upload_leaves_no_directory(self, tmp_path):
        import uuid as _uuid

        from fastapi import HTTPException

        project_id = _uuid.uuid4()
        svc = self._service(tmp_path)
        # 1 MB limit; send 2 MB.
        big = self._upload("big.bin", [b"x" * (1024 * 1024)] * 2)

        with pytest.raises(HTTPException) as exc:
            await svc.upload_bytes_only(project_id, big)
        assert exc.value.status_code == 413

        assert self._project_dirs(tmp_path, project_id) == [], (
            "413 oversize path must remove the firmware directory"
        )

    @pytest.mark.asyncio
    async def test_duplicate_upload_leaves_no_directory(self, tmp_path):
        import uuid as _uuid

        from fastapi import HTTPException

        project_id = _uuid.uuid4()
        result = MagicMock()
        result.scalar_one_or_none.return_value = _uuid.uuid4()  # existing row
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)

        svc = self._service(tmp_path, db=db)
        dup = self._upload("dup.bin", [b"same-bytes"])

        with pytest.raises(HTTPException) as exc:
            await svc.upload_bytes_only(project_id, dup)
        assert exc.value.status_code == 409

        assert self._project_dirs(tmp_path, project_id) == [], (
            "409 dedup path must remove the firmware directory "
            "(os.rmdir silently failed once the file was written)"
        )

    @pytest.mark.asyncio
    async def test_client_disconnect_leaves_no_directory(self, tmp_path):
        """CancelledError inherits BaseException — the handler must catch it."""
        import asyncio as _asyncio
        import uuid as _uuid

        project_id = _uuid.uuid4()
        svc = self._service(tmp_path)

        sent = {"n": 0}

        async def _read(_n):
            sent["n"] += 1
            if sent["n"] == 1:
                return b"partial-payload"
            raise _asyncio.CancelledError

        upload = MagicMock()
        upload.filename = "aborted.bin"
        upload.size = 16
        upload.read = _read

        with pytest.raises(_asyncio.CancelledError):
            await svc.upload_bytes_only(project_id, upload)

        assert self._project_dirs(tmp_path, project_id) == [], (
            "a client disconnect mid-stream must not orphan the partial upload"
        )

    @pytest.mark.asyncio
    async def test_successful_upload_keeps_the_directory(self, tmp_path):
        """The cleanup must not fire on the happy path."""
        import uuid as _uuid

        project_id = _uuid.uuid4()
        result = MagicMock()
        result.scalar_one_or_none.return_value = None  # no duplicate
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        db.add = MagicMock()

        svc = self._service(tmp_path, db=db)
        good = self._upload("good.bin", [b"firmware-bytes"])

        firmware = await svc.upload_bytes_only(project_id, good)

        dirs = self._project_dirs(tmp_path, project_id)
        assert len(dirs) == 1, "successful upload must keep its directory"
        assert (dirs[0] / "good.bin").read_bytes() == b"firmware-bytes"
        assert firmware.upload_stage == "detecting"
        db.commit.assert_awaited_once()
