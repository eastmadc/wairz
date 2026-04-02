"""Firmware unpacking orchestrator with adaptive fallback chain.

Strategy: try format-specific fast paths first, then fall back through
generic extractors (binwalk → unblob) until one succeeds.

Delegates to specialized modules:
- unpack_common: classification, filesystem detection, shared utilities
- unpack_linux: architecture detection, kernel detection, tar handling
- unpack_android: OTA extraction, sparse images, super.img partitions
"""

import logging
import os

# Re-export public API for backward compatibility
from app.workers.unpack_common import (  # noqa: F401
    UnpackResult,
    classify_firmware,
    find_filesystem_root,
    run_binwalk_extraction,
    run_unblob_extraction,
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

logger = logging.getLogger(__name__)


def _analyze_filesystem(result: UnpackResult, extraction_dir: str) -> None:
    """Post-extraction analysis: find root, detect arch/OS/kernel."""
    fs_root = find_filesystem_root(extraction_dir)
    if not fs_root:
        result.error = "Could not locate filesystem root in extracted contents"
        return

    result.extracted_path = fs_root

    fs_root_real = os.path.realpath(fs_root)
    extraction_dir_real = os.path.realpath(extraction_dir)
    if fs_root_real != extraction_dir_real:
        result.extraction_dir = _find_binwalk_output_dir(
            fs_root_real, extraction_dir_real
        )

    arch, endian = detect_architecture(fs_root)
    result.architecture = arch
    result.endianness = endian
    result.os_info = detect_os_info(fs_root)
    result.kernel_path = detect_kernel(extraction_dir, fs_root)
    result.success = True


async def unpack_firmware(firmware_path: str, output_base_dir: str) -> UnpackResult:
    """Orchestrate the full unpacking pipeline with adaptive fallback.

    Pipeline:
    1. Classify firmware type
    2. Try format-specific fast path (Android, tar, ELF)
    3. If fast path fails or format is unknown, run fallback chain:
       binwalk (600s) → unblob (1200s)
    4. Post-extraction: find filesystem root, detect architecture/OS/kernel
    """
    import tarfile as _tarfile

    result = UnpackResult()
    extraction_dir = os.path.join(output_base_dir, "extracted")
    os.makedirs(extraction_dir, exist_ok=True)

    fw_type = classify_firmware(firmware_path)
    result.unpack_log = f"Firmware classified as: {fw_type}\n"

    # === STAGE 1: Format-Specific Fast Paths ===

    if fw_type == "elf_binary":
        import shutil
        dest = os.path.join(extraction_dir, os.path.basename(firmware_path))
        shutil.copy2(firmware_path, dest)
        result.extracted_path = extraction_dir
        result.extraction_dir = extraction_dir
        result.unpack_log += "Single ELF binary — skipped filesystem extraction."
        arch, endian = detect_architecture_from_elf(firmware_path)
        result.architecture = arch
        result.endianness = endian
        result.success = True
        return result

    if fw_type in ("android_ota", "android_sparse"):
        try:
            result.unpack_log += await _extract_android_ota(firmware_path, extraction_dir)
            _analyze_filesystem(result, extraction_dir)
            if result.success:
                return result
            result.unpack_log += "\nAndroid extraction produced no filesystem root.\n"
        except Exception as e:
            result.unpack_log += f"\nAndroid extraction failed: {e}\n"
            logger.warning("Android fast path failed, falling through to generic extractors", exc_info=True)

    elif fw_type == "linux_rootfs_tar":
        try:
            with _tarfile.open(firmware_path) as tf:
                tf.extractall(extraction_dir, filter=_firmware_tar_filter)
            result.unpack_log += f"Extracted tar rootfs: {os.path.basename(firmware_path)}\n"
            _analyze_filesystem(result, extraction_dir)
            if result.success:
                return result
            result.unpack_log += "\nTar extraction produced no filesystem root.\n"
        except Exception as e:
            result.unpack_log += f"\nTar extraction failed: {e}\n"
            logger.warning("Tar fast path failed, falling through to generic extractors", exc_info=True)

    # === STAGE 2: Generic Fallback Chain ===

    fallback_extractors = [
        ("binwalk", run_binwalk_extraction, 600),
        ("unblob", run_unblob_extraction, 1200),
    ]

    for name, func, timeout in fallback_extractors:
        try:
            result.unpack_log += f"\nTrying {name} (timeout {timeout}s)...\n"
            log = await func(firmware_path, extraction_dir, timeout=timeout)
            result.unpack_log += log

            # Check if this extractor produced a usable filesystem
            _analyze_filesystem(result, extraction_dir)
            if result.success:
                result.unpack_log += f"\n{name} extraction succeeded.\n"
                return result

            result.unpack_log += f"\n{name} ran but no filesystem root found. Trying next...\n"
            result.error = None  # Clear for next attempt
        except TimeoutError:
            result.unpack_log += f"\n{name} timed out after {timeout}s.\n"
            logger.info("%s timed out on %s", name, os.path.basename(firmware_path))
        except Exception as e:
            result.unpack_log += f"\n{name} failed: {e}\n"
            logger.info("%s failed on %s: %s", name, os.path.basename(firmware_path), e)

    # All extractors exhausted
    if not result.success:
        result.error = "All extraction methods failed or produced no filesystem root"
        result.unpack_log += "\nAll extraction methods exhausted.\n"

    return result
