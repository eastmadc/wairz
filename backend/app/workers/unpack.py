"""Firmware unpacking orchestrator.

Delegates to specialized modules:
- unpack_common: classification, filesystem detection, shared utilities
- unpack_linux: architecture detection, kernel detection, tar handling
- unpack_android: OTA extraction, sparse images, super.img partitions
"""

import os

# Re-export public API for backward compatibility
from app.workers.unpack_common import (  # noqa: F401
    UnpackResult,
    classify_firmware,
    find_filesystem_root,
    run_binwalk_extraction,
    _find_binwalk_output_dir,
)
from app.workers.unpack_linux import (  # noqa: F401
    detect_architecture,
    detect_architecture_from_elf,
    detect_kernel,
    detect_os_info,
    _firmware_tar_filter,
)
from app.workers.unpack_android import _extract_android_ota  # noqa: F401


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

    # Tar rootfs: extract directly — binwalk treats them as raw data
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
        # Run binwalk extraction
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

    # Find the filesystem root
    fs_root = find_filesystem_root(extraction_dir)
    if not fs_root:
        result.error = "Could not locate filesystem root in extracted contents"
        return result
    result.extracted_path = fs_root

    # Determine the binwalk output directory
    fs_root_real = os.path.realpath(fs_root)
    extraction_dir_real = os.path.realpath(extraction_dir)
    if fs_root_real != extraction_dir_real:
        result.extraction_dir = _find_binwalk_output_dir(
            fs_root_real, extraction_dir_real
        )

    # Detect architecture, OS info, and kernel
    arch, endian = detect_architecture(fs_root)
    result.architecture = arch
    result.endianness = endian
    result.os_info = detect_os_info(fs_root)
    result.kernel_path = detect_kernel(extraction_dir, fs_root)

    result.success = True
    return result
