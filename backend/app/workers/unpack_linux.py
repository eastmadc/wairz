"""Linux-specific firmware detection and analysis."""

import os

from elftools.elf.elffile import ELFFile

from app.workers.unpack_common import (
    _ELF_ARCH_MAP,
    _FS_IMAGE_EXTENSIONS,
    _FS_ROOT_NAMES,
    _KERNEL_NAME_PATTERNS,
    _read_magic,
)


def detect_architecture(fs_root: str) -> tuple[str | None, str | None]:
    """Detect architecture and endianness by examining ELF binaries.

    Uses majority voting across all ELF binaries found in common directories.
    """
    from collections import Counter

    search_dirs = ["bin", "usr/bin", "sbin", "usr/sbin", "lib"]
    votes: Counter[tuple[str, str]] = Counter()
    max_scan = 50

    for search_dir in search_dirs:
        search_path = os.path.join(fs_root, search_dir)
        if not os.path.isdir(search_path):
            continue

        try:
            entries = os.listdir(search_path)
        except OSError:
            continue

        for entry in entries:
            if sum(votes.values()) >= max_scan:
                break

            full_path = os.path.join(search_path, entry)
            if not os.path.isfile(full_path):
                continue
            try:
                with open(full_path, "rb") as f:
                    magic = f.read(4)
                    if magic != b"\x7fELF":
                        continue
                    f.seek(0)
                    elf = ELFFile(f)
                    arch = _ELF_ARCH_MAP.get(elf.header.e_machine, elf.header.e_machine)
                    endianness = "little" if elf.little_endian else "big"

                    if arch == "mips" and endianness == "little":
                        arch = "mipsel"

                    votes[(arch, endianness)] += 1
            except Exception:
                continue

    if not votes:
        return None, None

    (arch, endianness), _count = votes.most_common(1)[0]
    return arch, endianness


def detect_os_info(fs_root: str) -> str | None:
    """Read OS info from standard release files."""
    release_files = [
        "etc/os-release",
        "etc/openwrt_release",
        "etc/lsb-release",
        "etc/version",
        "etc/issue",
        "system/build.prop",
        "build.prop",
    ]
    for rel_file in release_files:
        full_path = os.path.join(fs_root, rel_file)
        if os.path.isfile(full_path):
            try:
                with open(full_path) as f:
                    content = f.read(1024)
                content = content.replace("\x00", "").strip()
                if content:
                    return content
            except Exception:
                continue
    return None


def detect_architecture_from_elf(path: str) -> tuple[str | None, str | None]:
    """Detect architecture and endianness from a single ELF file."""
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            machine = elf.header.e_machine
            arch = _ELF_ARCH_MAP.get(machine)
            endian = "little" if elf.little_endian else "big"
            return arch, endian
    except Exception:
        return None, None


def detect_kernel(extraction_dir: str, fs_root: str | None) -> str | None:
    """Scan the extraction directory for a kernel image."""
    if fs_root:
        scan_dir = os.path.dirname(fs_root)
    else:
        scan_dir = extraction_dir

    if not os.path.isdir(scan_dir):
        return None

    candidates: list[tuple[str, int]] = []

    for entry in os.scandir(scan_dir):
        if not entry.is_file(follow_symlinks=False):
            continue

        name_lower = entry.name.lower()

        if name_lower in _FS_ROOT_NAMES:
            continue
        if name_lower.endswith(".json") or name_lower.endswith(".txt"):
            continue
        _, ext = os.path.splitext(name_lower)
        if ext in _FS_IMAGE_EXTENSIONS:
            continue

        try:
            file_size = entry.stat().st_size
        except OSError:
            continue

        if file_size < 500_000:
            continue

        if any(p in name_lower for p in _KERNEL_NAME_PATTERNS):
            candidates.append((entry.path, 100))
            continue

        magic = _read_magic(entry.path, 4)

        if magic == b"\x7fELF":
            try:
                with open(entry.path, "rb") as f:
                    elf = ELFFile(f)
                    if elf.header.e_type == "ET_EXEC" and file_size > 1_000_000:
                        candidates.append((entry.path, 95))
                        continue
            except Exception:
                pass

        if magic == b"\x27\x05\x19\x56":
            candidates.append((entry.path, 90))
            continue

        if file_size > 1_000_000:
            try:
                with open(entry.path, "rb") as f:
                    f.seek(0x24)
                    arm_magic = f.read(4)
                    if arm_magic == b"\x18\x28\x6f\x01":
                        candidates.append((entry.path, 92))
                        continue
            except OSError:
                pass

        if magic[:2] == b"\x1f\x8b" and file_size > 1_000_000:
            candidates.append((entry.path, 70))
            continue

        if magic[:3] == b"\x5d\x00\x00" and file_size > 1_000_000:
            candidates.append((entry.path, 70))
            continue

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[0][0]


def check_tar_bomb(
    tar_path: str, max_size_bytes: int, max_files: int, max_ratio: int
) -> str | None:
    """Inspect a tar archive for zip-bomb indicators without extracting.

    Returns an error message string if any limit is exceeded, or None if OK.
    """
    import tarfile as _tarfile

    try:
        archive_size = os.path.getsize(tar_path)
    except OSError:
        return None

    total_size = 0
    file_count = 0

    try:
        with _tarfile.open(tar_path) as tf:
            for member in tf:
                file_count += 1
                if member.isreg():
                    total_size += member.size

                if file_count > max_files:
                    return (
                        f"Tar bomb detected: file count ({file_count}) "
                        f"exceeds limit ({max_files})"
                    )
                if total_size > max_size_bytes:
                    return (
                        f"Tar bomb detected: declared size "
                        f"({total_size // (1024*1024)}MB) exceeds limit "
                        f"({max_size_bytes // (1024*1024)}MB)"
                    )
    except Exception:
        return None  # Can't inspect — let extraction proceed

    if archive_size > 0 and total_size > 0:
        ratio = total_size / archive_size
        if ratio > max_ratio:
            return (
                f"Tar bomb detected: compression ratio ({ratio:.1f}:1) "
                f"exceeds limit ({max_ratio}:1)"
            )

    return None


def _firmware_tar_filter(member, dest_path):
    """Custom tar extraction filter for firmware rootfs archives."""
    import tarfile as _tarfile

    name = member.name.lstrip("/")
    if name != member.name:
        member = member.replace(name=name, deep=False)

    resolved = os.path.realpath(os.path.join(dest_path, name))
    real_dest = os.path.realpath(dest_path)
    if not resolved.startswith(real_dest + os.sep) and resolved != real_dest:
        raise _tarfile.AbsolutePathError(member)

    if not (member.isreg() or member.isdir() or member.issym() or member.islnk()):
        return None

    return member
