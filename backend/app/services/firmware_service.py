import asyncio
import hashlib
import os
import re
import shutil
import tarfile
import uuid
import zipfile

import aiofiles
from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.firmware import Firmware


def _sanitize_filename(name: str) -> str:
    """Sanitize a user-supplied filename to prevent path traversal and OS issues.

    Strips directory components, replaces unsafe characters, and limits length.
    """
    # Take only the basename (strip any path components / traversal)
    name = os.path.basename(name)
    # Replace anything that isn't alphanumeric, dot, hyphen, or underscore
    name = re.sub(r"[^\w.\-]", "_", name)
    # Collapse consecutive underscores
    name = re.sub(r"__+", "_", name)
    # Strip leading dots (no hidden files / no "..") and leading underscores
    name = name.lstrip("._")
    # Limit to 200 chars to stay within filesystem limits
    name = name[:200]
    return name or "firmware.bin"


def _zip_contains_rootfs(zip_path: str) -> bool:
    """Check if a ZIP archive contains a Linux root filesystem.

    Looks for standard Linux top-level directories (etc/, usr/, bin/, lib/,
    sbin/) either at the archive root or one level deep (when the ZIP has a
    single wrapper directory).  If 3+ of these markers are found, we treat
    the ZIP as a rootfs archive.
    """
    rootfs_markers = {"etc", "usr", "bin", "lib", "sbin"}

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = [
            info.filename for info in zf.infolist()
            if not info.filename.startswith(".")
            and not info.filename.startswith("__")
        ]

        # Collect top-level directory names
        top_level_dirs: set[str] = set()
        for name in names:
            parts = name.strip("/").split("/")
            if len(parts) >= 1:
                top_level_dirs.add(parts[0])

        # Case 1: rootfs directories directly at the archive root
        if len(rootfs_markers & top_level_dirs) >= 3:
            return True

        # Case 2: single wrapper directory containing rootfs directories
        #   e.g., rootfs/etc/, rootfs/usr/, rootfs/bin/
        if len(top_level_dirs) == 1:
            wrapper = next(iter(top_level_dirs))
            second_level_dirs: set[str] = set()
            for name in names:
                parts = name.strip("/").split("/")
                if len(parts) >= 2 and parts[0] == wrapper:
                    second_level_dirs.add(parts[1])
            if len(rootfs_markers & second_level_dirs) >= 3:
                return True

    return False


def _extract_firmware_from_zip(zip_path: str, output_dir: str) -> str | None:
    """Extract the main firmware file from a ZIP archive.

    Picks the largest file in the archive (most likely the firmware image).
    Returns the path to the extracted file, or None if the archive is empty.
    """
    with zipfile.ZipFile(zip_path, "r") as zf:
        candidates = []
        for info in zf.infolist():
            if info.is_dir():
                continue
            basename = os.path.basename(info.filename)
            # Skip hidden files, macOS resource forks, etc.
            if not basename or basename.startswith(".") or basename.startswith("__"):
                continue
            candidates.append(info)

        if not candidates:
            return None

        best = max(candidates, key=lambda i: i.file_size)
        target_name = _sanitize_filename(os.path.basename(best.filename))
        target_path = os.path.join(output_dir, target_name)

        # Extract in chunks to avoid loading entire file into memory
        with zf.open(best) as src, open(target_path, "wb") as dst:
            while chunk := src.read(8192):
                dst.write(chunk)

        return target_path


def _firmware_tar_filter(member, dest_path):
    """Tar filter for firmware archives — allows absolute symlinks.

    Python 3.12's filter="data" rejects symlinks to absolute paths,
    but firmware rootfs archives legitimately use them. This filter
    allows symlinks while still preventing path traversal and
    rejecting device nodes.
    """
    name = member.name.lstrip("/")
    if name != member.name:
        member = member.replace(name=name, deep=False)
    resolved = os.path.realpath(os.path.join(dest_path, name))
    real_dest = os.path.realpath(dest_path)
    if not resolved.startswith(real_dest + os.sep) and resolved != real_dest:
        raise ValueError(f"Path traversal detected in archive: {member.name}")
    if not (member.isreg() or member.isdir() or member.issym() or member.islnk()):
        return None
    return member


def _extract_archive(archive_path: str, output_dir: str) -> None:
    """Extract a tar, tar.gz, or zip archive with path traversal prevention."""
    if tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path) as tf:
            tf.extractall(output_dir, filter=_firmware_tar_filter)
    elif zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                target = os.path.realpath(os.path.join(output_dir, info.filename))
                if not target.startswith(os.path.realpath(output_dir) + os.sep) and target != os.path.realpath(output_dir):
                    raise ValueError(f"Path traversal detected in archive: {info.filename}")
            zf.extractall(output_dir)
    else:
        raise ValueError(
            "Unsupported archive format. Please upload a .tar.gz, .tar, or .zip file."
        )


class FirmwareService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.settings = get_settings()

    async def upload(
        self,
        project_id: uuid.UUID,
        file: UploadFile,
        version_label: str | None = None,
    ) -> Firmware:
        # Generate a firmware ID upfront for per-firmware storage directory
        firmware_id = uuid.uuid4()

        # Per-firmware storage: projects/{pid}/firmware/{fid}/
        firmware_dir = os.path.join(
            self.settings.storage_root,
            "projects",
            str(project_id),
            "firmware",
            str(firmware_id),
        )
        os.makedirs(firmware_dir, exist_ok=True)

        # Stream file to disk while computing SHA256
        raw_filename = file.filename or "firmware.bin"
        filename = _sanitize_filename(raw_filename)
        storage_path = os.path.join(firmware_dir, filename)
        sha256_hash = hashlib.sha256()
        file_size = 0

        async with aiofiles.open(storage_path, "wb") as out_file:
            while chunk := await file.read(8192):
                sha256_hash.update(chunk)
                await out_file.write(chunk)
                file_size += len(chunk)

        # If the uploaded file is a ZIP (by extension), extract the firmware from inside it.
        # We check the extension rather than zipfile.is_zipfile() alone because firmware
        # binaries can contain embedded zip data that triggers false positives.
        if raw_filename.lower().endswith(".zip") and zipfile.is_zipfile(storage_path):
            if _zip_contains_rootfs(storage_path):
                # The ZIP contains a Linux root filesystem — extract the entire
                # archive directly instead of pulling a single file for binwalk.
                # This mirrors the "Upload Rootfs" path so the user doesn't need
                # to fall back to manual rootfs upload.
                from app.workers.unpack import (
                    detect_architecture,
                    detect_kernel,
                    detect_os_info,
                    find_filesystem_root,
                )

                extraction_dir = os.path.join(firmware_dir, "extracted")
                os.makedirs(extraction_dir, exist_ok=True)

                loop = asyncio.get_running_loop()
                await loop.run_in_executor(
                    None, _extract_archive, storage_path, extraction_dir
                )
                os.remove(storage_path)

                fs_root = await loop.run_in_executor(
                    None, find_filesystem_root, extraction_dir
                )
                if not fs_root:
                    raise ValueError(
                        "ZIP appears to contain a rootfs but no filesystem root "
                        "was found after extraction."
                    )

                firmware = Firmware(
                    id=firmware_id,
                    project_id=project_id,
                    original_filename=raw_filename,
                    sha256=sha256_hash.hexdigest(),
                    file_size=file_size,
                    storage_path=storage_path,
                    extracted_path=fs_root,
                    version_label=version_label,
                    unpack_log="Rootfs ZIP detected; extracted directly without binwalk.",
                )
                arch, endian = await loop.run_in_executor(
                    None, detect_architecture, fs_root
                )
                firmware.architecture = arch
                firmware.endianness = endian
                firmware.os_info = await loop.run_in_executor(
                    None, detect_os_info, fs_root
                )
                firmware.kernel_path = await loop.run_in_executor(
                    None, detect_kernel, extraction_dir, fs_root
                )
                self.db.add(firmware)
                await self.db.flush()
                return firmware

            extracted = _extract_firmware_from_zip(storage_path, firmware_dir)
            if extracted:
                os.remove(storage_path)
                storage_path = extracted
                # Recompute hash and size for the actual firmware content
                sha256_hash = hashlib.sha256()
                file_size = 0
                async with aiofiles.open(storage_path, "rb") as f:
                    while chunk := await f.read(8192):
                        sha256_hash.update(chunk)
                        file_size += len(chunk)

        firmware = Firmware(
            id=firmware_id,
            project_id=project_id,
            original_filename=raw_filename,
            sha256=sha256_hash.hexdigest(),
            file_size=file_size,
            storage_path=storage_path,
            version_label=version_label,
        )
        self.db.add(firmware)
        await self.db.flush()
        return firmware

    async def upload_rootfs(
        self,
        firmware: Firmware,
        file: UploadFile,
    ) -> Firmware:
        """Extract a user-supplied rootfs archive into the firmware's extracted dir.

        Accepts .tar.gz, .tar, or .zip archives containing the filesystem root.
        Runs architecture and OS detection on the extracted contents.
        """
        from app.workers.unpack import (
            detect_architecture,
            detect_kernel,
            detect_os_info,
            find_filesystem_root,
        )

        firmware_dir = os.path.dirname(firmware.storage_path)
        extraction_dir = os.path.join(firmware_dir, "extracted")
        os.makedirs(extraction_dir, exist_ok=True)

        # Save archive to a temp file
        raw_filename = file.filename or "rootfs.tar.gz"
        archive_path = os.path.join(firmware_dir, _sanitize_filename(raw_filename))
        async with aiofiles.open(archive_path, "wb") as out:
            while chunk := await file.read(8192):
                await out.write(chunk)

        # Extract the archive (sync I/O — run in executor to avoid blocking)
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, _extract_archive, archive_path, extraction_dir)
        finally:
            os.remove(archive_path)

        # Find the filesystem root (sync I/O — run in executor)
        fs_root = await loop.run_in_executor(None, find_filesystem_root, extraction_dir)
        if not fs_root:
            raise ValueError(
                "Could not locate a filesystem root in the archive. "
                "Ensure it contains a Linux root filesystem (with etc/, bin/ or usr/)."
            )

        firmware.extracted_path = fs_root
        arch, endian = await loop.run_in_executor(None, detect_architecture, fs_root)
        firmware.architecture = arch
        firmware.endianness = endian
        firmware.os_info = await loop.run_in_executor(None, detect_os_info, fs_root)
        firmware.kernel_path = await loop.run_in_executor(None, detect_kernel, extraction_dir, fs_root)
        firmware.unpack_log = "Filesystem provided via manual rootfs upload."

        await self.db.flush()
        return firmware

    async def get_by_project(self, project_id: uuid.UUID) -> Firmware | None:
        """Get the first firmware for a project (backward compat)."""
        result = await self.db.execute(
            select(Firmware)
            .where(Firmware.project_id == project_id)
            .order_by(Firmware.created_at)
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, firmware_id: uuid.UUID) -> Firmware | None:
        """Get a specific firmware by its ID."""
        result = await self.db.execute(
            select(Firmware).where(Firmware.id == firmware_id)
        )
        return result.scalar_one_or_none()

    async def list_by_project(self, project_id: uuid.UUID) -> list[Firmware]:
        """List all firmware for a project, ordered by creation time."""
        result = await self.db.execute(
            select(Firmware)
            .where(Firmware.project_id == project_id)
            .order_by(Firmware.created_at)
        )
        return list(result.scalars().all())

    async def delete(self, firmware: Firmware) -> None:
        """Delete a firmware record and its files on disk."""
        # Remove files from disk
        if firmware.storage_path:
            # The firmware directory is the parent of the storage_path
            firmware_dir = os.path.dirname(firmware.storage_path)
            if os.path.isdir(firmware_dir):
                shutil.rmtree(firmware_dir, ignore_errors=True)
        elif firmware.extracted_path:
            # Fallback: remove extracted path's parent
            parent = os.path.dirname(firmware.extracted_path)
            if os.path.isdir(parent):
                shutil.rmtree(parent, ignore_errors=True)

        await self.db.delete(firmware)
        await self.db.flush()
