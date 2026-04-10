"""Module-level constants and standalone helpers for emulation services.

Extracted from emulation_service.py to reduce file size and improve reuse.
"""

import os
import platform
import re

# Map canonical architecture -> QEMU user-mode binary
QEMU_USER_BIN_MAP: dict[str, str] = {
    "arm": "qemu-arm-static",
    "aarch64": "qemu-aarch64-static",
    "mips": "qemu-mips-static",
    "mipsel": "qemu-mipsel-static",
    "x86": "qemu-i386-static",
    "x86_64": "qemu-x86_64-static",
}

# Architecture aliases -> canonical names used by QEMU
ARCH_ALIASES: dict[str, str] = {
    "arm": "arm",
    "armhf": "arm",
    "armel": "arm",
    "ARM": "arm",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "mips": "mips",
    "MIPS": "mips",
    "mipsbe": "mips",
    "mipsel": "mipsel",
    "MIPS-LE": "mipsel",
    "mipsle": "mipsel",
    "x86": "x86",
    "i386": "x86",
    "i686": "x86",
    "x86_64": "x86_64",
    "amd64": "x86_64",
}

# binfmt_misc registration entries for each architecture.
# Format: ":name:type:offset:magic:mask:interpreter:flags"
# Flags: F = fix binary (kernel caches interpreter fd -- works in chroots/containers)
#        P = preserve argv[0]
#        C = use caller's credentials
# The \x sequences are interpreted by the kernel's binfmt_misc parser, not the shell.
# Mask \xfe on e_type byte matches both ET_EXEC (2) and ET_DYN (3) for PIE support.
BINFMT_ENTRIES: dict[str, tuple[str, str]] = {
    "arm": (
        "qemu-arm",
        r":qemu-arm:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        r"\x02\x00\x28\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff"
        r"\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-arm-static:FPC",
    ),
    "aarch64": (
        "qemu-aarch64",
        r":qemu-aarch64:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00"
        r"\x00\x02\x00\xb7\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff"
        r"\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-aarch64-static:FPC",
    ),
    "mips": (
        "qemu-mips",
        r":qemu-mips:M::\x7fELF\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        r"\x00\x02\x00\x08:\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00"
        r"\x00\x00\x00\xff\xfe\xff\xff:/usr/bin/qemu-mips-static:FPC",
    ),
    "mipsel": (
        "qemu-mipsel",
        r":qemu-mipsel:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00"
        r"\x00\x02\x00\x08\x00:\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00"
        r"\x00\x00\x00\x00\xfe\xff\xff\xff:/usr/bin/qemu-mipsel-static:FPC",
    ),
    "x86": (
        "qemu-i386",
        r":qemu-i386:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        r"\x02\x00\x03\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff"
        r"\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-i386-static:FPC",
    ),
    "x86_64": (
        "qemu-x86_64",
        r":qemu-x86_64:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00"
        r"\x00\x02\x00\x3e\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff"
        r"\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-x86_64-static:FPC",
    ),
}

# Detect host architecture so we can skip binfmt_misc for native binaries
_HOST_ARCH = ARCH_ALIASES.get(platform.machine())

# Regex to strip ANSI escape sequences, OSC sequences, and carriage returns
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r")

# Regex to strip residual serial-exec markers that may leak through
_MARKER_RE = re.compile(r"WAIRZ_(?:START|END)_WZE\w+")


def _validate_kernel_file(path: str) -> tuple[bool, str]:
    """Check whether a file looks like a valid kernel image by inspecting magic bytes.

    Returns (is_valid, reason) where reason describes what was detected or
    why the file was rejected.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return False, "file not found or unreadable"

    if size < 500_000:
        return False, f"too small ({size} bytes) — kernels are typically >500KB"

    try:
        with open(path, "rb") as f:
            header = f.read(64)
    except OSError:
        return False, "unable to read file"

    if len(header) < 4:
        return False, "file too short to identify"

    # ELF — must be ET_EXEC (vmlinux), not ET_DYN (shared lib)
    if header[:4] == b"\x7fELF":
        # e_type is at offset 16 (2 bytes). ET_EXEC = 2
        if len(header) >= 18:
            # Check both endiannesses (EI_DATA at offset 5: 1=LE, 2=BE)
            ei_data = header[5]
            if ei_data == 1:  # little-endian
                e_type = int.from_bytes(header[16:18], "little")
            else:
                e_type = int.from_bytes(header[16:18], "big")
            if e_type == 2:
                return True, "ELF executable (vmlinux)"
            return False, f"ELF file but type={e_type} (not ET_EXEC=2) — likely a shared library or firmware image"
        return False, "ELF header too short"

    # U-Boot uImage
    if header[:4] == b"\x27\x05\x19\x56":
        return True, "U-Boot uImage"

    # ARM zImage — magic at offset 0x24: 0x016f2818 (little-endian)
    if len(header) >= 0x28:
        arm_magic = header[0x24:0x28]
        if arm_magic == b"\x18\x28\x6f\x01":
            return True, "ARM zImage"

    # gzip-compressed (common for compressed kernels)
    if header[:2] == b"\x1f\x8b" and size > 500_000:
        return True, "gzip-compressed (possibly vmlinuz)"

    # LZMA-compressed
    if header[:3] == b"\x5d\x00\x00" and size > 500_000:
        return True, "LZMA-compressed (possibly vmlinuz)"

    return False, "unrecognized format — not ELF/uImage/zImage/gzip/LZMA"
