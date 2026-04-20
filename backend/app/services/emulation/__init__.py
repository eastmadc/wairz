"""Emulation service — split into a subpackage for maintainability.

This subpackage replaces the monolithic ``emulation_service.py`` (1664 LOC)
with per-topic modules:

- ``service`` — :class:`EmulationService` public API (orchestrator).
- ``docker_ops`` — Docker container lifecycle helpers (tar streaming,
  symlink repair, stub injection, log retrieval, host-path resolution).
- ``kernel_selection`` — arch-to-kernel matching + initrd discovery.
- ``sysroot_mount`` — wairz init-wrapper generation + injection into
  the firmware rootfs (system-mode only).
- ``user_mode`` — user-mode QEMU setup (binfmt_misc registration +
  interactive shell command builder).
- ``system_mode`` — system-mode QEMU setup (kernel/initrd copy, QEMU
  launch, startup health probe).

Callers should import :class:`EmulationService` directly from
``app.services.emulation``. The legacy ``app.services.emulation_service``
module has been deleted; no shim is kept (4 callers updated in-place).
"""

from app.services.emulation.service import EmulationService

__all__ = ["EmulationService"]
