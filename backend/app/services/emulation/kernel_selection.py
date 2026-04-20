"""Kernel resolution helpers for system-mode emulation.

Extracted from ``emulation_service.py`` as step 3/7 of the Phase 5 split.

This module provides the *selection* logic — given a firmware architecture
and optional hints (user-specified kernel name, firmware-extracted kernel
path), it returns a backend-local path to a kernel file suitable for
``qemu-system-<arch>``. It does NOT handle kernel download/sync; that
lives in ``app.services.kernel_service`` (``KernelService``).

Public surface:

- ``find_kernel`` — arch → kernel path, with fallback priority
  (user-specified → firmware-extracted → pre-built pool).
- ``find_initrd`` — locate the initramfs companion for a kernel (by
  sidecar metadata or filename convention).
"""

import logging
import os

from app.config import Settings
from app.services.emulation_constants import _validate_kernel_file
from app.services.kernel_service import KernelService

logger = logging.getLogger(__name__)


def find_kernel(
    settings: Settings,
    arch: str | None,
    kernel_name: str | None = None,
    firmware_kernel_path: str | None = None,
) -> str:
    """Find a kernel for system-mode emulation.

    Priority order:

    1. Explicit ``kernel_name`` (user-specified from kernel management).
    2. Kernel extracted from the firmware during unpacking (validated via
       :func:`app.services.emulation_constants._validate_kernel_file`).
    3. Pre-built kernels in ``settings.emulation_kernel_dir`` (matching
       architecture, via :class:`KernelService`).

    Raises ``ValueError`` if no kernel is found or a user-specified
    ``kernel_name`` is missing / contains path traversal characters.
    """
    kernel_dir = settings.emulation_kernel_dir

    # 1) User-specified kernel from the kernel management system
    if kernel_name:
        if "/" in kernel_name or "\\" in kernel_name or ".." in kernel_name:
            raise ValueError(f"Invalid kernel name: {kernel_name}")
        kernel_path = os.path.join(kernel_dir, kernel_name)
        if not os.path.isfile(kernel_path):
            raise ValueError(
                f"Kernel '{kernel_name}' not found in {kernel_dir}. "
                "Upload a kernel via the kernel management API."
            )
        return kernel_path

    # 2) Kernel extracted from the firmware itself — validate before using
    if firmware_kernel_path and os.path.isfile(firmware_kernel_path):
        is_valid, reason = _validate_kernel_file(firmware_kernel_path)
        if is_valid:
            logger.info(
                "Using kernel extracted from firmware: %s (%s)",
                firmware_kernel_path, reason,
            )
            return firmware_kernel_path
        else:
            logger.warning(
                "Firmware kernel candidate rejected: %s — %s. "
                "Falling through to pre-built kernels.",
                firmware_kernel_path, reason,
            )

    # 3) Pre-built kernel from the kernel management directory
    svc = KernelService()
    match = svc.find_kernel_for_arch(arch or "arm")
    if match:
        return os.path.join(kernel_dir, match["name"])

    raise ValueError(
        f"No kernel available for architecture '{arch or 'arm'}'. "
        "System-mode emulation requires a pre-built Linux kernel. "
        "A kernel was not found in the firmware image. "
        "Upload one via the kernel management page or API "
        "(GET/POST /api/v1/kernels)."
    )


def find_initrd(
    kernel_path: str | None,
    kernel_name: str | None = None,
) -> str | None:
    """Find the initrd/initramfs companion for a kernel.

    Checks the kernel service sidecar metadata and convention-based
    naming (``<kernel>.initrd``). Returns None if no companion is found.
    """
    if not kernel_path:
        return None

    svc = KernelService()

    # If kernel_name was specified, check sidecar directly
    if kernel_name:
        initrd = svc._initrd_path(kernel_name)
        if initrd:
            return initrd

    # Try convention: look for <kernel_basename>.initrd in the kernel dir
    kernel_basename = os.path.basename(kernel_path)
    initrd = svc._initrd_path(kernel_basename)
    if initrd:
        return initrd

    return None
