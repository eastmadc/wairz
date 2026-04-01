import asyncio
import glob
import os
from dataclasses import dataclass, field

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


def _has_linux_markers(path: str) -> bool:
    """Check if a directory has the standard Linux or Android filesystem markers."""
    try:
        all_entries = set(os.listdir(path))
    except OSError:
        return False
    has_etc = "etc" in all_entries or "etc_ro" in all_entries
    has_usr_or_bin = "usr" in all_entries or "bin" in all_entries
    # Standard Linux rootfs
    if has_etc and has_usr_or_bin:
        return True
    # Android rootfs: has system/build.prop or system/ + vendor/
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
    """Count entries in the etc/ (or etc_ro/) directory as a quality signal.

    Handles Android's common pattern where etc is a symlink to an absolute
    path (/system/etc). When the symlink target doesn't resolve, falls back
    to checking system/etc within the same root (Android layout).
    """
    for name in ("etc", "etc_ro"):
        etc_path = os.path.join(path, name)
        if os.path.isdir(etc_path):  # follows symlinks
            try:
                return len(os.listdir(etc_path))
            except OSError:
                pass
        # Android fallback: etc -> /system/etc (absolute, broken symlink)
        # Try resolving relative to this root
        if os.path.islink(etc_path):
            target = os.readlink(etc_path)
            if target.startswith("/"):
                # Resolve absolute symlink relative to this root
                relative_target = os.path.join(path, target.lstrip("/"))
                if os.path.isdir(relative_target):
                    try:
                        return len(os.listdir(relative_target))
                    except OSError:
                        pass
    return 0


def find_filesystem_root(extraction_dir: str) -> str | None:
    """Find the extracted filesystem root by looking for Linux directory markers.

    Prioritises directories with well-known root names produced by binwalk
    (e.g. squashfs-root, jffs2-root) and picks the candidate whose etc/
    directory has the most entries — empty placeholder dirs from overlapping
    extractions are deprioritised automatically.
    """
    candidates: list[tuple[str, int, int, int]] = []  # (path, priority, etc_count, total_entries)

    for root, dirs, _files in os.walk(extraction_dir):
        # os.walk() only lists real directories in `dirs`, not symlinks.
        # Firmware often has standard dirs as symlinks (e.g. /etc -> /dev/null,
        # /bin -> /usr/bin for merged-usr), so use listdir to see everything.
        if not _has_linux_markers(root):
            continue

        dirname = os.path.basename(root)
        # Known binwalk root names get priority boost
        priority = 10 if dirname in _FS_ROOT_NAMES else 0
        # Android system root: has init + system/ + bin/ — this IS the real root
        try:
            entries = set(os.listdir(root))
        except OSError:
            entries = set()
        if "init" in entries and "system" in entries and ("bin" in entries or "apex" in entries):
            priority = 20  # Android system root gets highest priority
        etc_count = _etc_entry_count(root)
        try:
            total_entries = len(os.listdir(root))
        except OSError:
            total_entries = 0
        candidates.append((root, priority, etc_count, total_entries))

    if candidates:
        # Sort by: priority descending, etc count descending, total entries descending
        candidates.sort(key=lambda c: (c[1], c[2], c[3]), reverse=True)
        return candidates[0][0]

    # Fallback: find largest directory by entry count
    best_dir = None
    best_count = 0
    for root, dirs, files in os.walk(extraction_dir):
        count = len(dirs) + len(files)
        if count > best_count:
            best_count = count
            best_dir = root

    return best_dir


def detect_architecture(fs_root: str) -> tuple[str | None, str | None]:
    """Detect architecture and endianness by examining ELF binaries.

    Uses majority voting across all ELF binaries found in common directories
    to handle mixed-architecture filesystems (e.g., ARM firmware with x86-64
    systemd from a host layer).
    """
    from collections import Counter

    # Look for ELF binaries in common dirs
    search_dirs = ["bin", "usr/bin", "sbin", "usr/sbin", "lib"]
    votes: Counter[tuple[str, str]] = Counter()
    max_scan = 50  # Cap scanning to avoid slowness on huge filesystems

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

                    # For MIPS, distinguish mips vs mipsel
                    if arch == "mips" and endianness == "little":
                        arch = "mipsel"

                    votes[(arch, endianness)] += 1
            except Exception:
                continue

    if not votes:
        return None, None

    # Return the most common architecture
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
        # Android release files
        "system/build.prop",
        "build.prop",
    ]
    for rel_file in release_files:
        full_path = os.path.join(fs_root, rel_file)
        if os.path.isfile(full_path):
            try:
                with open(full_path) as f:
                    content = f.read(1024)
                # Strip null bytes — firmware may have zeroed-out placeholder files
                content = content.replace("\x00", "").strip()
                if content:
                    return content
            except Exception:
                continue
    return None


def _read_magic(path: str, num_bytes: int = 4) -> bytes:
    """Read the first N bytes of a file for magic number detection."""
    try:
        with open(path, "rb") as f:
            return f.read(num_bytes)
    except OSError:
        return b""


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


import re as _re

_ROOT_DIR_RE = _re.compile(r"^[a-z0-9]+-root(-\d+)?$")


def _find_binwalk_output_dir(
    fs_root_real: str, extraction_dir_real: str
) -> str | None:
    """Walk up from the rootfs to find the binwalk output directory.

    The binwalk output dir is the directory that contains the rootfs
    *and* possibly other extracted partitions (jffs2-root, ext-root, etc.).
    We walk up from the rootfs toward extraction_dir, and pick the deepest
    ancestor that contains at least one sibling ``*-root`` directory or
    other content worth showing at the virtual top level.

    For nested -Me extractions the rootfs can be several levels deep:
        extracted/_fw.bin.extracted/_100.squashfs.extracted/squashfs-root/
    In that case we want the ``_100.squashfs.extracted/`` directory so its
    sibling ``ext-root/`` etc. are visible.

    Returns the binwalk output dir path, or None if the virtual top-level
    would add no value (e.g. single rootfs with no siblings).
    """
    # Walk up from rootfs parent toward (and including) extraction_dir
    current = os.path.dirname(fs_root_real)
    rootfs_basename = os.path.basename(fs_root_real)
    best = None

    while current.startswith(extraction_dir_real):
        # Check if this directory has interesting siblings / children
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
                # Also look one level inside subdirectories (for nested
                # _*.extracted/ dirs that contain *-root directories)
                try:
                    for child in os.listdir(full):
                        child_full = os.path.join(full, child)
                        if os.path.isdir(child_full) and _ROOT_DIR_RE.match(child):
                            # Make sure it's not the rootfs itself
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
            break  # Use the deepest dir with siblings

        if current == extraction_dir_real:
            break
        current = os.path.dirname(current)

    return best


def detect_kernel(extraction_dir: str, fs_root: str | None) -> str | None:
    """Scan the extraction directory for a kernel image.

    Kernels extracted by binwalk appear as siblings to the filesystem root
    in the .extracted/ directory — they are NOT inside the filesystem.

    Returns the absolute path to the best kernel candidate, or None.
    """
    # The parent of the filesystem root is the binwalk extraction output dir
    # (e.g., /data/.../extracted/_firmware.img.extracted/)
    if fs_root:
        scan_dir = os.path.dirname(fs_root)
    else:
        # No filesystem root found — scan all .extracted/ subdirectories
        scan_dir = extraction_dir

    if not os.path.isdir(scan_dir):
        return None

    candidates: list[tuple[str, int]] = []  # (path, priority)

    for entry in os.scandir(scan_dir):
        if not entry.is_file(follow_symlinks=False):
            continue

        name_lower = entry.name.lower()

        # Skip filesystem images and known roots
        if name_lower in _FS_ROOT_NAMES:
            continue
        # Skip JSON sidecar files and very small files
        if name_lower.endswith(".json") or name_lower.endswith(".txt"):
            continue
        # Skip filesystem image files (ext2, yaffs, jffs2, etc.)
        _, ext = os.path.splitext(name_lower)
        if ext in _FS_IMAGE_EXTENSIONS:
            continue

        try:
            file_size = entry.stat().st_size
        except OSError:
            continue

        # Kernels are typically > 500 KB
        if file_size < 500_000:
            continue

        # 1) Check filename patterns (highest priority)
        if any(p in name_lower for p in _KERNEL_NAME_PATTERNS):
            candidates.append((entry.path, 100))
            continue

        # 2) Check magic bytes
        magic = _read_magic(entry.path, 4)

        # ELF binary — could be an uncompressed vmlinux
        if magic == b"\x7fELF":
            # Verify it's an executable (not a shared library from extraction)
            try:
                with open(entry.path, "rb") as f:
                    elf = ELFFile(f)
                    # Kernel ELFs are ET_EXEC (type 2) and very large
                    if elf.header.e_type == "ET_EXEC" and file_size > 1_000_000:
                        candidates.append((entry.path, 95))
                        continue
            except Exception:
                pass

        # U-Boot uImage header
        if magic == b"\x27\x05\x19\x56":
            candidates.append((entry.path, 90))
            continue

        # ARM Linux zImage magic at offset 0x24: 0x016f2818
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

        # gzip-compressed (possibly compressed kernel)
        if magic[:2] == b"\x1f\x8b" and file_size > 1_000_000:
            candidates.append((entry.path, 70))
            continue

        # LZMA-compressed
        if magic[:3] == b"\x5d\x00\x00" and file_size > 1_000_000:
            candidates.append((entry.path, 70))
            continue

    if not candidates:
        return None

    # Return highest-priority candidate
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[0][0]


def _is_rootfs_tar(firmware_path: str) -> bool:
    """Check if the file is a tar archive containing a Linux rootfs.

    Detects .tar, .tar.gz, .tar.bz2, .tar.xz — any format Python's
    tarfile module supports. Returns True if the archive contains
    Linux filesystem markers (etc/, usr/, bin/, etc.) at the top level
    or one level deep behind a single wrapper directory.
    """
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
                # Early exit once we've seen enough unique path prefixes
                if len(top_names & linux_dirs) >= 3:
                    return True
                if len(top_names) <= 3 and len(second_names & linux_dirs) >= 3:
                    return True
                # Safety cap — if we haven't matched after 5000 entries, it's not a rootfs
                if count >= 5000:
                    break
            # Final check after loop
            if len(top_names & linux_dirs) >= 3:
                return True
            if len(top_names) <= 3 and len(second_names & linux_dirs) >= 3:
                return True
    except Exception:
        return False

    return False


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


def classify_firmware(firmware_path: str) -> str:
    """Classify firmware file type to determine the analysis pipeline.

    Returns one of:
    - "android_ota": Android OTA update ZIP (payload.bin or partition images)
    - "android_sparse": Android sparse image (magic 0x3AFF26ED)
    - "linux_rootfs_tar": tar archive containing Linux rootfs (bypass binwalk)
    - "linux_blob": firmware blob likely containing embedded Linux filesystem
    - "elf_binary": single ELF binary (bare metal or RTOS, skip FS extraction)
    - "intel_hex": Intel HEX format (microcontroller firmware)
    - "pe_binary": Windows PE binary
    - "unknown": unrecognized format (try binwalk)
    """
    import zipfile as _zipfile

    # Android OTA detection — check before tar since OTA ZIPs are not tars
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
                # Single system.img or payload.bin also counts
                if "payload.bin" in names or "system.img" in names:
                    return "android_ota"
        except Exception:
            pass

    # Android sparse image (magic 0x3AFF26ED, little-endian)
    sparse_magic = _read_magic(firmware_path, 4)
    if sparse_magic == b"\x3a\xff\x26\xed":
        return "android_sparse"

    # Check tar rootfs first (fast path for known archives)
    if _is_rootfs_tar(firmware_path):
        return "linux_rootfs_tar"

    magic = _read_magic(firmware_path, 16)

    # ELF binary (bare metal, RTOS, or single-binary firmware)
    if magic[:4] == b"\x7fELF":
        return "elf_binary"

    # Intel HEX (starts with ':' record marker)
    if magic[:1] == b":" and all(c in b"0123456789ABCDEFabcdef:\r\n" for c in magic):
        return "intel_hex"

    # PE binary (Windows CE/IoT)
    if magic[:2] == b"MZ":
        return "pe_binary"

    # Default: assume it's a firmware blob for binwalk
    return "linux_blob"


def _firmware_tar_filter(member, dest_path):
    """Custom tar extraction filter for firmware rootfs archives.

    Python 3.12's ``filter="data"`` rejects symlinks to absolute paths,
    but firmware filesystems legitimately use them (e.g. /bin -> /usr/bin,
    /etc/fonts/conf.d/51-local.conf -> /etc/fonts/local.conf).

    This filter:
    - Allows regular files, directories, and symlinks (including absolute)
    - Strips leading slashes from member names (prevent extraction outside dest)
    - Rejects members that would escape dest_path via ``..``
    - Rejects special files (device nodes, fifos)
    """
    import tarfile as _tarfile

    # Strip leading / from member name
    name = member.name.lstrip("/")
    if name != member.name:
        member = member.replace(name=name, deep=False)

    # Reject path traversal via ..
    resolved = os.path.realpath(os.path.join(dest_path, name))
    real_dest = os.path.realpath(dest_path)
    if not resolved.startswith(real_dest + os.sep) and resolved != real_dest:
        raise _tarfile.AbsolutePathError(member)

    # Reject special files (device nodes, block devices, fifos)
    if not (member.isreg() or member.isdir() or member.issym() or member.islnk()):
        return None  # skip silently

    return member


def _identify_partition_by_content(partition_dir: str) -> str | None:
    """Identify an Android partition by its directory contents.

    Returns a human-readable name like 'system', 'vendor', 'product',
    or None if the partition cannot be identified.
    """
    if not os.path.isdir(partition_dir):
        return None
    try:
        entries = set(os.listdir(partition_dir))
    except OSError:
        return None

    # system: has init binary, or bin/app/framework dirs
    if ("init" in entries and ("bin" in entries or "system" in entries)) or \
       ("app" in entries and "framework" in entries and "priv-app" in entries):
        return "system"

    # vendor: has build.prop + (firmware/ or lib/)
    if "build.prop" in entries and ("firmware" in entries or "lib" in entries or "etc" in entries):
        # Distinguish from system which also has build.prop
        if "app" not in entries or "framework" not in entries:
            return "vendor"

    # product: has app/ or priv-app/ but no framework/
    if ("app" in entries or "priv-app" in entries) and "framework" not in entries:
        if "overlay" in entries or "media" in entries:
            return "product"

    # system_ext: has app/ + priv-app/ but distinct from system
    if "priv-app" in entries and "apex" in entries and "framework" not in entries:
        return "system_ext"

    # odm: has etc/ + lib/ but not build.prop typically
    if "etc" in entries and "lib" in entries and "build.prop" not in entries and \
       "app" not in entries and "framework" not in entries:
        if "firmware" in entries or "overlay" in entries:
            return "odm"

    return None


async def _try_extract_partition(
    raw_path: str, rootfs_dir: str, partition_name: str, log_lines: list[str]
) -> bool:
    """Try to extract a single partition image as ext4 or EROFS."""
    import shutil

    dest_dir = os.path.join(rootfs_dir, partition_name)
    os.makedirs(dest_dir, exist_ok=True)

    # Try EROFS first (more common in modern Android)
    if shutil.which("fsck.erofs"):
        proc = await asyncio.create_subprocess_exec(
            "fsck.erofs", f"--extract={dest_dir}", raw_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=300)
            if os.listdir(dest_dir):
                log_lines.append(f"Extracted {partition_name} as EROFS ({len(os.listdir(dest_dir))} top-level entries)")
                return True
        except asyncio.TimeoutError:
            proc.kill()
            log_lines.append(f"fsck.erofs timed out on {partition_name}")

    # Try ext4 via debugfs
    if shutil.which("debugfs"):
        proc = await asyncio.create_subprocess_exec(
            "debugfs", "-R", f"rdump / {dest_dir}", raw_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=300)
            if os.listdir(dest_dir):
                log_lines.append(f"Extracted {partition_name} as ext4 ({len(os.listdir(dest_dir))} top-level entries)")
                return True
        except asyncio.TimeoutError:
            proc.kill()
            log_lines.append(f"debugfs timed out on {partition_name}")

    # Clean up empty dir
    try:
        os.rmdir(dest_dir)
    except OSError:
        pass
    return False


async def _scan_super_partitions(
    raw_path: str, rootfs_dir: str, log_lines: list[str]
) -> int:
    """Scan a raw super.img for embedded EROFS/ext4 partitions and extract them.

    Android super.img contains multiple partitions (system, vendor, product, etc.)
    at different offsets. Instead of parsing LP metadata (which requires lpunpack),
    we scan for filesystem magic bytes and extract each partition found.
    """
    import mmap
    import tempfile

    EROFS_MAGIC = b"\xe2\xe1\xf5\xe0"  # At offset 1024 within partition
    EXT4_MAGIC = b"\x53\xef"  # At offset 0x438 within partition

    partitions: list[tuple[str, int]] = []  # (type, start_offset)

    try:
        with open(raw_path, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            size = mm.size()

            # Scan for EROFS superblocks (magic at offset 1024 from partition start)
            # Check at 1MB-aligned boundaries (Android partitions are MB-aligned)
            for offset in range(1024, min(size, 10 * 1024**3), 1024 * 1024):
                if mm[offset:offset + 4] == EROFS_MAGIC:
                    partitions.append(("erofs", offset - 1024))

            # Scan for ext4 superblocks (magic at offset 0x438 from partition start)
            for offset in range(0x438, min(size, 10 * 1024**3), 1024 * 1024):
                if mm[offset:offset + 2] == EXT4_MAGIC:
                    partitions.append(("ext4", offset - 0x438))

            mm.close()
    except Exception as e:
        log_lines.append(f"Error scanning super.img: {e}")
        return 0

    if not partitions:
        log_lines.append("No EROFS or ext4 partitions found in super.img")
        return 0

    # Sort by offset and deduplicate nearby entries
    partitions.sort(key=lambda x: x[1])
    log_lines.append(f"Found {len(partitions)} partition(s) in super.img")

    extracted_count = 0
    for i, (fs_type, start_offset) in enumerate(partitions):
        # Determine partition size (distance to next partition or end of image)
        if i + 1 < len(partitions):
            part_size = partitions[i + 1][1] - start_offset
        else:
            part_size = os.path.getsize(raw_path) - start_offset

        # Skip tiny partitions (< 1MB)
        if part_size < 1024 * 1024:
            continue

        partition_name = f"partition_{i}_{fs_type}"

        # Extract partition to temp file, then extract filesystem
        try:
            with tempfile.NamedTemporaryFile(suffix=f".{fs_type}", delete=False) as tmp:
                tmp_path = tmp.name
                with open(raw_path, "rb") as src:
                    src.seek(start_offset)
                    remaining = part_size
                    while remaining > 0:
                        chunk = src.read(min(remaining, 8 * 1024 * 1024))
                        if not chunk:
                            break
                        tmp.write(chunk)
                        remaining -= len(chunk)

            if await _try_extract_partition(tmp_path, rootfs_dir, partition_name, log_lines):
                # Identify partition by content and rename from generic name
                identified = _identify_partition_by_content(
                    os.path.join(rootfs_dir, partition_name)
                )
                if identified and identified != partition_name:
                    old_path = os.path.join(rootfs_dir, partition_name)
                    new_path = os.path.join(rootfs_dir, identified)
                    if not os.path.exists(new_path):
                        os.rename(old_path, new_path)
                        log_lines.append(f"Identified {partition_name} as '{identified}'")
                        partition_name = identified
                extracted_count += 1
        except Exception as e:
            log_lines.append(f"Error extracting partition at offset 0x{start_offset:x}: {e}")
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    log_lines.append(f"Extracted {extracted_count}/{len(partitions)} partitions from super.img")
    return extracted_count


async def _extract_android_ota(firmware_path: str, extraction_dir: str) -> str:
    """Extract Android OTA ZIP — handles sparse images, ext4, EROFS."""
    import zipfile as _zipfile
    import shutil

    log_lines: list[str] = []

    # Step 1: Extract the ZIP (or handle raw sparse image)
    if _zipfile.is_zipfile(firmware_path):
        with _zipfile.ZipFile(firmware_path, "r") as zf:
            names = zf.namelist()

            # Check for payload.bin (A/B OTA)
            if "payload.bin" in names:
                payload_path = os.path.join(extraction_dir, "payload.bin")
                zf.extract("payload.bin", extraction_dir)
                log_lines.append("Found payload.bin (A/B OTA)")
                # Try payload-dumper-go
                if shutil.which("payload-dumper-go"):
                    partitions_dir = os.path.join(extraction_dir, "partitions")
                    os.makedirs(partitions_dir, exist_ok=True)
                    proc = await asyncio.create_subprocess_exec(
                        "payload-dumper-go", "-o", partitions_dir, payload_path,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    try:
                        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
                        log_lines.append(stdout.decode(errors="replace")[:2000])
                    except asyncio.TimeoutError:
                        proc.kill()
                        log_lines.append("payload-dumper-go timed out")
                    os.remove(payload_path)
                else:
                    log_lines.append("payload-dumper-go not installed, skipping payload.bin")
            else:
                # Extract partition images from ZIP
                for name in names:
                    if name.endswith(".img") or name.endswith(".bin"):
                        zf.extract(name, extraction_dir)
                        log_lines.append(f"Extracted {name}")
    else:
        # Raw sparse image — copy it for processing
        import shutil
        dest = os.path.join(extraction_dir, os.path.basename(firmware_path))
        if not dest.endswith(".img"):
            dest += ".img"
        shutil.copy2(firmware_path, dest)
        log_lines.append(f"Copied raw sparse image: {os.path.basename(firmware_path)}")

    # Step 2: Process each .img file — convert sparse, handle super.img, extract filesystems
    rootfs_dir = os.path.join(extraction_dir, "rootfs")
    os.makedirs(rootfs_dir, exist_ok=True)

    search_dirs = [extraction_dir, os.path.join(extraction_dir, "partitions")]

    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        for img_name in sorted(os.listdir(search_dir)):
            if not img_name.endswith(".img"):
                continue
            img_path = os.path.join(search_dir, img_name)

            try:
                if os.path.getsize(img_path) < 1024 * 1024:
                    continue
            except OSError:
                continue

            # Convert sparse to raw if needed
            raw_path = img_path
            try:
                with open(img_path, "rb") as f:
                    img_magic = f.read(4)
                if img_magic == b"\x3a\xff\x26\xed" and shutil.which("simg2img"):
                    raw_path = img_path + ".raw"
                    proc = await asyncio.create_subprocess_exec(
                        "simg2img", img_path, raw_path,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    await asyncio.wait_for(proc.communicate(), timeout=600)
                    log_lines.append(f"Converted {img_name} sparse → raw ({os.path.getsize(raw_path) // (1024*1024)}MB)")
                    os.remove(img_path)
            except Exception as e:
                log_lines.append(f"Error converting {img_name}: {e}")
                continue

            # Check if this is a super.img (LP metadata at offset 0x1000)
            is_super = False
            try:
                with open(raw_path, "rb") as f:
                    f.seek(0x1000)
                    lp_magic = f.read(4)
                    if lp_magic == b"\x67\x44\x6c\x61":  # "gDla" = LP_METADATA_MAGIC
                        is_super = True
                        log_lines.append(f"{img_name} is a super partition — scanning for embedded filesystems")
            except Exception:
                pass

            if is_super:
                # Scan for EROFS and ext4 filesystem signatures within the super image
                partitions_found = await _scan_super_partitions(raw_path, rootfs_dir, log_lines)
                # Clean up the large raw file
                if os.path.exists(raw_path):
                    os.remove(raw_path)
                continue

            # Not a super image — try direct extraction
            partition_name = img_name.replace(".img", "").replace(".raw", "")
            extracted = await _try_extract_partition(raw_path, rootfs_dir, partition_name, log_lines)

            if raw_path != img_path and os.path.exists(raw_path):
                os.remove(raw_path)

    return "\n".join(log_lines)


async def unpack_firmware(firmware_path: str, output_base_dir: str) -> UnpackResult:
    """Orchestrate the full unpacking pipeline.

    Uses classify_firmware() to determine the analysis strategy:
    - android_ota / android_sparse: Android OTA or sparse image extraction
    - linux_rootfs_tar: extract tar directly (bypass binwalk)
    - linux_blob: run binwalk -e (default firmware path)
    - elf_binary: skip extraction, copy binary for direct Ghidra analysis
    - intel_hex / pe_binary / unknown: try binwalk as best effort
    """
    import tarfile as _tarfile

    result = UnpackResult()
    extraction_dir = os.path.join(output_base_dir, "extracted")
    os.makedirs(extraction_dir, exist_ok=True)

    fw_type = classify_firmware(firmware_path)
    result.unpack_log = f"Firmware classified as: {fw_type}\n"

    # ELF binary: no filesystem to extract — set up for direct Ghidra analysis
    if fw_type == "elf_binary":
        import shutil
        dest = os.path.join(extraction_dir, os.path.basename(firmware_path))
        shutil.copy2(firmware_path, dest)
        result.extracted_path = extraction_dir
        result.extraction_dir = extraction_dir
        result.unpack_log += "Single ELF binary — skipped filesystem extraction. Use Ghidra for analysis."
        arch, endian = detect_architecture_from_elf(firmware_path)
        result.architecture = arch
        result.endianness = endian
        result.success = True
        return result

    # Android OTA / sparse image: custom extraction pipeline
    if fw_type in ("android_ota", "android_sparse"):
        try:
            result.unpack_log += await _extract_android_ota(firmware_path, extraction_dir)
        except Exception as e:
            result.error = f"Android extraction failed: {e}"
            result.unpack_log += str(e)
            return result
        # Find rootfs in extracted partitions — Android system partition is the main rootfs
        rootfs_dir = os.path.join(extraction_dir, "rootfs")
        # Fall through to find_filesystem_root below

    # Tar rootfs: extract directly — binwalk treats them as raw
    # data and carves out embedded compressed fragments instead.
    elif fw_type == "linux_rootfs_tar":
        try:
            with _tarfile.open(firmware_path) as tf:
                tf.extractall(extraction_dir, filter=_firmware_tar_filter)
            result.unpack_log = f"Extracted tar rootfs archive: {os.path.basename(firmware_path)}"
        except Exception as e:
            result.error = f"Tar extraction failed: {e}"
            result.unpack_log = str(e)
            return result
    else:
        # Step 1: Run binwalk extraction
        try:
            result.unpack_log = await run_binwalk_extraction(firmware_path, extraction_dir)
        except TimeoutError as e:
            result.error = str(e)
            result.unpack_log = str(e)
            return result
        except Exception as e:
            result.error = f"Extraction failed: {e}"
            result.unpack_log = str(e)
            return result

    # Step 2: Find the filesystem root
    fs_root = find_filesystem_root(extraction_dir)
    if not fs_root:
        result.error = "Could not locate filesystem root in extracted contents"
        return result
    result.extracted_path = fs_root

    # Step 2b: Determine the binwalk output directory (parent of rootfs).
    # Walk up from the rootfs to find the directory that contains it and
    # possibly other extracted partitions (jffs2-root, ext-root, etc.).
    # This handles both simple layouts (rootfs one level deep) and nested
    # binwalk -Me extractions (rootfs several levels deep).
    fs_root_real = os.path.realpath(fs_root)
    extraction_dir_real = os.path.realpath(extraction_dir)
    if fs_root_real != extraction_dir_real:
        result.extraction_dir = _find_binwalk_output_dir(
            fs_root_real, extraction_dir_real
        )

    # Step 3: Detect architecture
    arch, endian = detect_architecture(fs_root)
    result.architecture = arch
    result.endianness = endian

    # Step 4: Detect OS info
    result.os_info = detect_os_info(fs_root)

    # Step 5: Detect kernel image
    result.kernel_path = detect_kernel(extraction_dir, fs_root)

    result.success = True
    return result
