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
    check_extraction_limits,
    classify_firmware,
    cleanup_unblob_artifacts,
    find_filesystem_root,
    run_binwalk_extraction,
    run_unblob_extraction,
    _find_binwalk_output_dir,
)
from app.workers.unpack_linux import (  # noqa: F401
    check_tar_bomb,
    detect_architecture,
    detect_architecture_from_elf,
    detect_kernel,
    detect_os_info,
    _firmware_tar_filter,
)
from app.workers.unpack_android import _extract_android_ota, _extract_boot_img  # noqa: F401

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
        binwalk_dir = _find_binwalk_output_dir(
            fs_root_real, extraction_dir_real
        )
        # Only set extraction_dir if the binwalk output dir contains
        # meaningful sibling content (other roots, large files).
        # For deep unblob extractions where the rootfs is nested many
        # levels down, showing raw intermediary files is confusing.
        if binwalk_dir:
            result.extraction_dir = binwalk_dir

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
    import shutil
    import tarfile as _tarfile

    result = UnpackResult()
    extraction_dir = os.path.join(output_base_dir, "extracted")

    # Clean leftover data from previous failed attempts so retries work cleanly
    if os.path.exists(extraction_dir):
        shutil.rmtree(extraction_dir, ignore_errors=True)
    os.makedirs(extraction_dir, exist_ok=True)

    # Check disk space: need at least 2x firmware size for extraction headroom
    try:
        fw_size = os.path.getsize(firmware_path)
        free_space = shutil.disk_usage(extraction_dir).free
        if free_space < fw_size * 2:
            result.error = (
                f"Insufficient disk space: {free_space // (1024*1024)}MB free, "
                f"need ~{fw_size * 2 // (1024*1024)}MB for extraction"
            )
            result.unpack_log = result.error
            return result
    except OSError:
        pass  # Can't check — proceed anyway

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

    if fw_type in ("android_ota", "android_sparse", "android_boot"):
        try:
            if fw_type == "android_boot":
                boot_dir = os.path.join(extraction_dir, "boot")
                boot_log: list[str] = []
                await _extract_boot_img(firmware_path, boot_dir, boot_log)
                result.unpack_log += "\n".join(boot_log)
                # Use ramdisk as rootfs if it was extracted
                ramdisk_dir = os.path.join(boot_dir, "ramdisk")
                if os.path.isdir(ramdisk_dir) and os.listdir(ramdisk_dir):
                    result.extracted_path = ramdisk_dir
                else:
                    result.extracted_path = boot_dir
                result.extraction_dir = extraction_dir
                result.success = True
                return result
            result.unpack_log += await _extract_android_ota(firmware_path, extraction_dir)
            bomb_error = check_extraction_limits(extraction_dir, fw_size)
            if bomb_error:
                result.error = bomb_error
                result.unpack_log += f"\n{bomb_error}\n"
                shutil.rmtree(extraction_dir, ignore_errors=True)
                return result
            _analyze_filesystem(result, extraction_dir)
            if result.success:
                return result
            result.unpack_log += "\nAndroid extraction produced no filesystem root.\n"
        except Exception as e:
            result.unpack_log += f"\nAndroid extraction failed: {e}\n"
            logger.warning("Android fast path failed, falling through to generic extractors", exc_info=True)

    elif fw_type == "partition_dump_tar":
        # Raw partition image dump (EDL, MTKClient, or device bridge)
        try:
            from app.config import get_settings as _get_settings
            _settings = _get_settings()
            tar_bomb_error = check_tar_bomb(
                firmware_path,
                _settings.max_extraction_size_mb * 1024 * 1024,
                _settings.max_extraction_files,
                _settings.max_compression_ratio,
            )
            if tar_bomb_error:
                result.error = tar_bomb_error
                result.unpack_log += f"\n{tar_bomb_error}\n"
                return result
            with _tarfile.open(firmware_path) as tf:
                tf.extractall(extraction_dir, filter=_firmware_tar_filter)
            result.unpack_log += f"Extracted partition dump tar: {os.path.basename(firmware_path)}\n"
            bomb_error = check_extraction_limits(extraction_dir, fw_size)
            if bomb_error:
                result.error = bomb_error
                result.unpack_log += f"\n{bomb_error}\n"
                shutil.rmtree(extraction_dir, ignore_errors=True)
                return result
            # Process extracted .img files through Android pipeline
            result.unpack_log += await _extract_android_ota(extraction_dir, extraction_dir)
            _analyze_filesystem(result, extraction_dir)
            if result.success:
                return result
            result.unpack_log += "\nPartition dump extraction produced no filesystem root.\n"
        except Exception as e:
            result.unpack_log += f"\nPartition dump extraction failed: {e}\n"
            logger.warning("Partition dump fast path failed, falling through", exc_info=True)

    elif fw_type == "linux_rootfs_tar":
        try:
            from app.config import get_settings as _get_settings
            _settings = _get_settings()
            tar_bomb_error = check_tar_bomb(
                firmware_path,
                _settings.max_extraction_size_mb * 1024 * 1024,
                _settings.max_extraction_files,
                _settings.max_compression_ratio,
            )
            if tar_bomb_error:
                result.error = tar_bomb_error
                result.unpack_log += f"\n{tar_bomb_error}\n"
                return result
            with _tarfile.open(firmware_path) as tf:
                tf.extractall(extraction_dir, filter=_firmware_tar_filter)
            result.unpack_log += f"Extracted tar rootfs: {os.path.basename(firmware_path)}\n"
            bomb_error = check_extraction_limits(extraction_dir, fw_size)
            if bomb_error:
                result.error = bomb_error
                result.unpack_log += f"\n{bomb_error}\n"
                shutil.rmtree(extraction_dir, ignore_errors=True)
                return result
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
            bomb_error = check_extraction_limits(extraction_dir, fw_size)
            if bomb_error:
                result.error = bomb_error
                result.unpack_log += f"\n{bomb_error}\n"
                shutil.rmtree(extraction_dir, ignore_errors=True)
                return result
            # Clean up unblob/binwalk artifacts (.unknown chunks, raw images
            # that have been extracted) to reduce file explorer noise
            removed = cleanup_unblob_artifacts(extraction_dir)
            # Also clean nested extraction dirs (unblob nests under img_extract/)
            for entry in os.scandir(extraction_dir):
                if entry.is_dir(follow_symlinks=False) and entry.name.endswith("_extract"):
                    removed += cleanup_unblob_artifacts(entry.path)
            if removed:
                result.unpack_log += f"Cleaned up {removed} intermediate artifact(s).\n"
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
