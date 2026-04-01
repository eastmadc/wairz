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
        except Exception:
            pass

    sparse_magic = _read_magic(firmware_path, 4)
    if sparse_magic == b"\x3a\xff\x26\xed":
        return "android_sparse"

    if _is_rootfs_tar(firmware_path):
        return "linux_rootfs_tar"

    magic = _read_magic(firmware_path, 16)

    if magic[:4] == b"\x7fELF":
        return "elf_binary"

    if magic[:1] == b":" and all(c in b"0123456789ABCDEFabcdef:\r\n" for c in magic):
        return "intel_hex"

    if magic[:2] == b"MZ":
        return "pe_binary"

    return "linux_blob"


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
