"""Common utilities for firmware unpacking — shared by Linux and Android paths."""

import asyncio
import os
import re as _re
from dataclasses import dataclass

from elftools.elf.elffile import ELFFile


@dataclass
class UnpackResult:
    extracted_path: str | None = None
    extraction_dir: str | None = None
    architecture: str | None = None
    endianness: str | None = None
    os_info: str | None = None
    kernel_path: str | None = None
    unpack_log: str = ""
    success: bool = False
    error: str | None = None


# Map ELF machine types to friendly names
_ELF_ARCH_MAP = {
    "EM_MIPS": "mips",
    "EM_ARM": "arm",
    "EM_AARCH64": "aarch64",
    "EM_386": "x86",
    "EM_X86_64": "x86_64",
    "EM_PPC": "ppc",
    "EM_PPC64": "ppc64",
    "EM_SH": "sh",
    "EM_SPARC": "sparc",
}

# Known filesystem root directory names produced by binwalk extraction
_FS_ROOT_NAMES = frozenset({
    "ext-root", "squash-root", "squashfs-root", "ubifs-root",
    "cpio-root", "jffs2-root", "cramfs-root", "romfs-root",
})

# Filename patterns that strongly indicate a kernel image
_KERNEL_NAME_PATTERNS = ("vmlinux", "zimage", "uimage", "bzimage")

# File extensions for filesystem images — NOT kernels
_FS_IMAGE_EXTENSIONS = frozenset({
    ".ext", ".ext2", ".ext3", ".ext4",
    ".yaffs", ".yaffs2",
    ".jffs2",
    ".squashfs", ".sqfs",
    ".cramfs",
    ".ubifs", ".ubi",
    ".romfs",
    ".cpio",
})

_ROOT_DIR_RE = _re.compile(r"^[a-z0-9]+-root(-\d+)?$")

# Unblob chunk suffixes that indicate successfully processed content
_EXTRACT_DIR_SUFFIXES = ("_extract",)


def cleanup_unblob_artifacts(extraction_dir: str) -> int:
    """Remove unblob's .unknown chunk files and empty extraction dirs.

    Unblob splits firmware images into named chunks. Successfully identified
    chunks get an ``_extract`` sibling directory with their contents.
    ``.unknown`` chunks are segments unblob couldn't identify — typically
    partition table headers, bootloader padding, or raw data.  These add
    noise to the file explorer without analytical value.

    Returns the number of files removed.
    """
    removed = 0
    try:
        entries = list(os.scandir(extraction_dir))
    except OSError:
        return 0

    for entry in entries:
        if not entry.is_file(follow_symlinks=False):
            continue
        # Remove .unknown files (unidentified chunks)
        if entry.name.endswith(".unknown"):
            try:
                os.unlink(entry.path)
                removed += 1
            except OSError:
                pass
            continue
        # Remove raw chunk files that have a corresponding _extract dir
        # e.g. "53742118-282966566.squashfs_v4_le" when
        #      "53742118-282966566.squashfs_v4_le_extract/" exists
        extract_dir = entry.path + "_extract"
        if os.path.isdir(extract_dir):
            try:
                os.unlink(entry.path)
                removed += 1
            except OSError:
                pass

    return removed


def check_extraction_limits(
    extraction_dir: str, firmware_size: int, settings=None
) -> str | None:
    """Walk the extraction directory and enforce zip-bomb prevention limits.

    Returns an error message string if any limit is exceeded, or None if OK.
    """
    if settings is None:
        from app.config import get_settings
        settings = get_settings()

    max_bytes = settings.max_extraction_size_mb * 1024 * 1024
    max_files = settings.max_extraction_files
    max_ratio = settings.max_compression_ratio

    total_size = 0
    file_count = 0

    def _walk(path: str) -> str | None:
        nonlocal total_size, file_count
        try:
            entries = os.scandir(path)
        except OSError:
            return None
        for entry in entries:
            try:
                if entry.is_file(follow_symlinks=False):
                    file_count += 1
                    total_size += entry.stat(follow_symlinks=False).st_size
                elif entry.is_dir(follow_symlinks=False):
                    result = _walk(entry.path)
                    if result is not None:
                        return result
            except OSError:
                continue

            if file_count > max_files:
                return (
                    f"Extraction bomb detected: file count ({file_count}) "
                    f"exceeds limit ({max_files})"
                )
            if total_size > max_bytes:
                return (
                    f"Extraction bomb detected: total size "
                    f"({total_size // (1024*1024)}MB) exceeds limit "
                    f"({settings.max_extraction_size_mb}MB)"
                )
        return None

    error = _walk(extraction_dir)
    if error:
        return error

    # Check compression ratio
    if firmware_size > 0 and total_size > 0:
        ratio = total_size / firmware_size
        if ratio > max_ratio:
            return (
                f"Extraction bomb detected: compression ratio ({ratio:.1f}:1) "
                f"exceeds limit ({max_ratio}:1)"
            )

    return None


async def run_binwalk_extraction(firmware_path: str, output_dir: str, timeout: int = 600) -> str:
    """Run binwalk -e to extract firmware contents. Returns stdout+stderr."""
    proc = await asyncio.create_subprocess_exec(
        "binwalk", "-e", "-C", output_dir, firmware_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"binwalk extraction timed out after {timeout}s")

    return stdout.decode(errors="replace").replace("\x00", "")


async def run_unblob_extraction(firmware_path: str, output_dir: str, timeout: int = 1200) -> str:
    """Run unblob to extract firmware — handles 78+ formats.

    Unblob handles Rockchip RKFW, MediaTek, Qualcomm, and many proprietary
    container formats that binwalk cannot. Used as fallback when binwalk
    fails or times out.
    """
    from shutil import which

    if not which("unblob"):
        raise RuntimeError("unblob is not installed")

    proc = await asyncio.create_subprocess_exec(
        "unblob", "--extract-dir", output_dir, firmware_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"unblob extraction timed out after {timeout}s")

    return stdout.decode(errors="replace").replace("\x00", "")


async def run_uefi_extraction(firmware_path: str, output_dir: str, timeout: int = 300) -> str:
    """Run UEFIExtract to parse and extract UEFI/BIOS firmware.

    UEFIExtract produces a hierarchical .dump/ directory with all firmware
    volumes, DXE drivers, PEI modules, NVRAM, and other components extracted
    and decompressed. Each component gets header.bin, body.bin, and info.txt.
    """
    from shutil import which

    if not which("UEFIExtract"):
        raise RuntimeError(
            "UEFIExtract is not installed. "
            "Install from https://github.com/LongSoft/UEFITool"
        )

    import shutil

    # UEFIExtract creates output at <input>.dump/ next to the input file.
    # Copy firmware to output_dir so the .dump/ lands there.
    work_copy = os.path.join(output_dir, os.path.basename(firmware_path))
    shutil.copy2(firmware_path, work_copy)

    proc = await asyncio.create_subprocess_exec(
        "UEFIExtract", work_copy, "all",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"UEFIExtract timed out after {timeout}s")

    log = stdout.decode(errors="replace").replace("\x00", "")

    # Remove the work copy (keep only the .dump/ directory)
    try:
        os.unlink(work_copy)
    except OSError:
        pass

    return log


def _read_magic(path: str, num_bytes: int = 4) -> bytes:
    """Read the first N bytes of a file for magic number detection."""
    try:
        with open(path, "rb") as f:
            return f.read(num_bytes)
    except OSError:
        return b""


def _has_linux_markers(path: str) -> bool:
    """Check if a directory has the standard Linux or Android filesystem markers."""
    try:
        all_entries = set(os.listdir(path))
    except OSError:
        return False
    has_etc = "etc" in all_entries or "etc_ro" in all_entries
    has_usr_or_bin = "usr" in all_entries or "bin" in all_entries
    if has_etc and has_usr_or_bin:
        return True
    if "system" in all_entries:
        system_path = os.path.join(path, "system")
        if os.path.isdir(system_path):
            try:
                system_entries = set(os.listdir(system_path))
            except OSError:
                system_entries = set()
            if "build.prop" in system_entries:
                return True
        if "vendor" in all_entries or "product" in all_entries:
            return True
    return False


def _etc_entry_count(path: str) -> int:
    """Count entries in the etc/ (or etc_ro/) directory as a quality signal."""
    for name in ("etc", "etc_ro"):
        etc_path = os.path.join(path, name)
        if os.path.isdir(etc_path):
            try:
                return len(os.listdir(etc_path))
            except OSError:
                pass
        if os.path.islink(etc_path):
            target = os.readlink(etc_path)
            if target.startswith("/"):
                relative_target = os.path.join(path, target.lstrip("/"))
                if os.path.isdir(relative_target):
                    try:
                        return len(os.listdir(relative_target))
                    except OSError:
                        pass
    return 0


def find_filesystem_root(extraction_dir: str) -> str | None:
    """Find the extracted filesystem root by looking for Linux directory markers."""
    candidates: list[tuple[str, int, int, int]] = []

    for root, dirs, _files in os.walk(extraction_dir):
        if not _has_linux_markers(root):
            continue

        dirname = os.path.basename(root)
        priority = 10 if dirname in _FS_ROOT_NAMES else 0
        try:
            entries = set(os.listdir(root))
        except OSError:
            entries = set()
        if "init" in entries and "system" in entries and ("bin" in entries or "apex" in entries):
            priority = 20
        etc_count = _etc_entry_count(root)
        try:
            total_entries = len(os.listdir(root))
        except OSError:
            total_entries = 0
        candidates.append((root, priority, etc_count, total_entries))

    if candidates:
        candidates.sort(key=lambda c: (c[1], c[2], c[3]), reverse=True)
        return candidates[0][0]

    best_dir = None
    best_count = 0
    for root, dirs, files in os.walk(extraction_dir):
        count = len(dirs) + len(files)
        if count > best_count:
            best_count = count
            best_dir = root

    return best_dir


def _find_binwalk_output_dir(
    fs_root_real: str, extraction_dir_real: str
) -> str | None:
    """Walk up from the rootfs to find the binwalk output directory."""
    current = os.path.dirname(fs_root_real)
    rootfs_basename = os.path.basename(fs_root_real)
    best = None

    while current.startswith(extraction_dir_real):
        try:
            entries = os.listdir(current)
        except OSError:
            if current == extraction_dir_real:
                break
            current = os.path.dirname(current)
            continue

        has_other_root = False
        has_large_file = False
        for name in entries:
            if name == rootfs_basename:
                continue
            full = os.path.join(current, name)
            if os.path.isdir(full):
                if _ROOT_DIR_RE.match(name):
                    has_other_root = True
                    break
                try:
                    for child in os.listdir(full):
                        child_full = os.path.join(full, child)
                        if os.path.isdir(child_full) and _ROOT_DIR_RE.match(child):
                            if os.path.realpath(child_full) != fs_root_real:
                                has_other_root = True
                                break
                except OSError:
                    pass
                if has_other_root:
                    break
            elif os.path.isfile(full):
                try:
                    if os.path.getsize(full) >= 100_000:
                        has_large_file = True
                except OSError:
                    pass

        if has_other_root or has_large_file:
            best = current
            break

        if current == extraction_dir_real:
            break
        current = os.path.dirname(current)

    return best


def classify_firmware(firmware_path: str) -> str:
    """Classify firmware file type to determine the analysis pipeline."""
    import zipfile as _zipfile

    if _zipfile.is_zipfile(firmware_path):
        try:
            with _zipfile.ZipFile(firmware_path, "r") as zf:
                names = set(zf.namelist())
                android_markers = {
                    "META-INF/com/google/android/updater-script",
                    "META-INF/com/google/android/update-binary",
                    "META-INF/com/android/metadata",
                    "payload.bin", "system.img", "boot.img", "vendor.img",
                }
                if len(names & android_markers) >= 2:
                    return "android_ota"
                if "payload.bin" in names or "system.img" in names:
                    return "android_ota"
                # Check for UEFI capsule inside ZIP (e.g., Framework BIOS updates)
                uefi_zip_markers = {".cap", ".rom", ".fd", ".bin"}
                for name in names:
                    ext = os.path.splitext(name)[1].lower()
                    if ext in uefi_zip_markers:
                        # Extract and check if inner file is UEFI
                        try:
                            inner = zf.read(name)
                            if _is_uefi_content(inner):
                                return "uefi_firmware"
                        except Exception:
                            pass
        except Exception:
            pass

    magic = _read_magic(firmware_path, 16)

    # Android sparse image
    if magic[:4] == b"\x3a\xff\x26\xed":
        return "android_sparse"

    # Android boot image
    if magic[:8] == b"ANDROID!":
        return "android_boot"

    # UEFI/BIOS firmware detection (before tar/ELF checks)
    if _is_uefi_firmware(firmware_path, magic):
        return "uefi_firmware"

    if _is_partition_dump_tar(firmware_path):
        return "partition_dump_tar"

    if _is_rootfs_tar(firmware_path):
        return "linux_rootfs_tar"

    if magic[:4] == b"\x7fELF":
        return "elf_binary"

    if magic[:1] == b":" and all(c in b"0123456789ABCDEFabcdef:\r\n" for c in magic):
        return "intel_hex"

    if magic[:2] == b"MZ":
        return "pe_binary"

    return "linux_blob"


# EFI capsule GUID: BD86663B-08ED-4816-8FF0-D29BF6426720
_EFI_CAPSULE_GUID = b"\x3b\x66\x86\xbd\xed\x08\x16\x48\x8f\xf0\xd2\x9b\xf6\x42\x67\x20"
# Intel Flash Descriptor signature at offset 0x10
_IFD_SIGNATURE = b"\x5a\xa5\xf0\x0f"
# UEFI Firmware Volume magic: _FVH
_FVH_MAGIC = b"_FVH"
# AMI Aptio capsule marker
_AMI_CAPSULE = b"\xB5\x25\x67\x8D"


def _is_uefi_content(data: bytes) -> bool:
    """Check if raw bytes contain UEFI firmware signatures."""
    if len(data) < 32:
        return False
    # EFI capsule GUID at offset 0
    if data[:16] == _EFI_CAPSULE_GUID:
        return True
    # Intel Flash Descriptor at offset 0x10
    if len(data) > 0x14 and data[0x10:0x14] == _IFD_SIGNATURE:
        return True
    # Search first 4KB for _FVH (firmware volume header)
    search_region = data[:4096]
    if _FVH_MAGIC in search_region:
        return True
    return False


def _is_uefi_firmware(firmware_path: str, magic: bytes) -> bool:
    """Detect UEFI/BIOS firmware by magic bytes and structure."""
    # EFI capsule GUID at offset 0
    if len(magic) >= 16 and magic[:16] == _EFI_CAPSULE_GUID:
        return True
    # Intel Flash Descriptor at offset 0x10
    try:
        with open(firmware_path, "rb") as f:
            f.seek(0x10)
            ifd = f.read(4)
            if ifd == _IFD_SIGNATURE:
                return True
            # Search first 64KB for firmware volume header (_FVH)
            f.seek(0)
            head = f.read(65536)
            if _FVH_MAGIC in head:
                return True
    except OSError:
        pass
    # Check file extension as weak signal combined with size
    ext = os.path.splitext(firmware_path)[1].lower()
    if ext in (".rom", ".cap", ".fd", ".upd"):
        try:
            size = os.path.getsize(firmware_path)
            # UEFI firmware is typically 4MB-32MB
            if 2 * 1024 * 1024 <= size <= 64 * 1024 * 1024:
                return True
        except OSError:
            pass
    return False


def _is_partition_dump_tar(firmware_path: str) -> bool:
    """Check if the file is a tar of raw partition images (EDL/MTKClient dump).

    Qualcomm EDL dumps contain partitions like aboot.img, rpm.img, tz.img.
    MTKClient dumps contain partitions like boot.img, recovery.img, super.img, lk.img.
    Device bridge dumps also match this pattern.
    """
    import tarfile as _tarfile

    try:
        if not _tarfile.is_tarfile(firmware_path):
            return False
    except Exception:
        return False

    # Partition names that indicate a raw dump (not a rootfs)
    qualcomm_markers = {"aboot", "rpm", "tz", "hyp", "modem", "sbl1", "tz"}
    mtk_markers = {"lk", "tee", "preloader", "md1img", "spmfw", "sspm"}
    generic_markers = {"boot", "recovery", "system", "vendor", "super", "vbmeta", "dtbo"}
    all_markers = qualcomm_markers | mtk_markers | generic_markers

    try:
        with _tarfile.open(firmware_path) as tf:
            img_count = 0
            matched = 0
            for member in tf:
                name = os.path.basename(member.name)
                stem, ext = os.path.splitext(name)
                if ext.lower() == ".img":
                    img_count += 1
                    if stem.lower() in all_markers:
                        matched += 1
                if img_count >= 20:
                    break
            # At least 3 .img files with 2+ matching known partition names
            return img_count >= 3 and matched >= 2
    except Exception:
        return False


def _is_rootfs_tar(firmware_path: str) -> bool:
    """Check if the file is a tar archive containing a Linux rootfs."""
    import tarfile as _tarfile

    try:
        if not _tarfile.is_tarfile(firmware_path):
            return False
    except Exception:
        return False

    linux_dirs = {"etc", "usr", "bin", "lib", "sbin", "var", "tmp", "dev", "proc"}
    try:
        with _tarfile.open(firmware_path) as tf:
            top_names: set[str] = set()
            second_names: set[str] = set()
            count = 0
            for member in tf:
                parts = member.name.strip("/").split("/")
                if len(parts) >= 1:
                    top_names.add(parts[0])
                if len(parts) >= 2:
                    second_names.add(parts[1])
                count += 1
                if len(top_names & linux_dirs) >= 3:
                    return True
                if len(top_names) <= 3 and len(second_names & linux_dirs) >= 3:
                    return True
                if count >= 5000:
                    break
            if len(top_names & linux_dirs) >= 3:
                return True
            if len(top_names) <= 3 and len(second_names & linux_dirs) >= 3:
                return True
    except Exception:
        return False

    return False
