"""Canonical on-disk storage-path math + containment-checked purge.

Every firmware byte wairz stores lives under::

    {storage_root}/projects/{project_id}/firmware/{firmware_id}/

Two call sites own deletion of that tree: ``FirmwareService.delete`` (a
single firmware) and the projects router's ``delete_project`` (a whole
project). Before this module existed only the former removed files —
deleting a project dropped the child rows through the ORM
``cascade="all, delete-orphan"`` on ``Project.firmware`` and never
reached ``FirmwareService.delete``, so the entire byte tree stayed on
the volume with no DB row pointing at it.

That is a CLAUDE.md Rule #47 instance: the ORM cascade is a CONSUMER
HOOK of the delete state change, and it bypassed the only file-removing
code path. The fix is to make project deletion purge the project's
storage directory explicitly rather than relying on a per-firmware hook
the cascade never invokes.

``purge_dir_within_root`` is the single sanctioned deletion primitive.
It realpaths BOTH sides before comparing (CLAUDE.md Security #1 — the
same discipline the download endpoints use) and refuses to remove
anything that does not resolve strictly inside ``storage_root``. A
symlinked or traversal-crafted ``project_id`` therefore cannot turn a
project delete into an arbitrary host rmtree.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import uuid

logger = logging.getLogger(__name__)

__all__ = [
    "firmware_storage_dir",
    "project_storage_dir",
    "purge_dir_within_root",
    "purge_dir_within_root_sync",
]


def project_storage_dir(storage_root: str, project_id: uuid.UUID | str) -> str:
    """Absolute path of a project's storage directory (may not exist)."""
    return os.path.join(storage_root, "projects", str(project_id))


def firmware_storage_dir(
    storage_root: str,
    project_id: uuid.UUID | str,
    firmware_id: uuid.UUID | str,
) -> str:
    """Absolute path of one firmware's storage directory (may not exist)."""
    return os.path.join(
        storage_root, "projects", str(project_id), "firmware", str(firmware_id)
    )


def _is_within(root_real: str, target_real: str) -> bool:
    """True when ``target_real`` is strictly inside ``root_real``.

    Strictly: equality returns False, so the storage root itself can
    never be purged.
    """
    return target_real.startswith(root_real.rstrip(os.sep) + os.sep)


def purge_dir_within_root_sync(storage_root: str, target: str) -> bool:
    """Remove ``target`` if it resolves strictly inside ``storage_root``.

    Combines realpath + isdir + rmtree so a single executor hop covers
    all three blocking calls (Rule #5 minimum-hop discipline).

    Returns True when a directory was removed, False when there was
    nothing to remove.

    Raises ValueError when ``target`` escapes the root — that is a
    programming error or an attack, never a no-op.

    Raises OSError when the tree could not be fully removed. This
    matters more than it looks: firmware extractions routinely contain
    files the API process cannot unlink (root-owned worker output,
    archive members restored with awkward modes). ``rmtree`` with
    ``ignore_errors=True`` swallows every one of those and returns
    normally, so a delete that actually left gigabytes behind reports
    success and the residue is invisible until something goes looking
    for it. Observed live: deleting one 11 GB firmware left a 6 GB /
    416-file subtree with the caller none the wiser. Surface it instead
    — every caller already logs OSError, and the reconcile script
    reports the directory as still-present on its next run.
    """
    root_real = os.path.realpath(storage_root)
    target_real = os.path.realpath(target)

    if not _is_within(root_real, target_real):
        raise ValueError(
            f"refusing to purge {target!r}: resolves to {target_real!r}, "
            f"which is outside storage root {root_real!r}"
        )

    if not os.path.isdir(target_real):
        return False

    failures: list[tuple[str, BaseException]] = []

    # onexc= (3.12+, and the project floor is 3.12) rather than the
    # onerror= callback, which was removed in 3.14.
    shutil.rmtree(target_real, onexc=lambda _f, path, exc: failures.append((path, exc)))

    if failures or os.path.exists(target_real):
        sample = ", ".join(f"{p} ({e.__class__.__name__})" for p, e in failures[:3])
        raise OSError(
            f"incomplete purge of {target_real!r}: {len(failures)} path(s) "
            f"could not be removed{': ' + sample if sample else ''}"
        )
    return True


async def purge_dir_within_root(storage_root: str, target: str) -> bool:
    """Async wrapper around :func:`purge_dir_within_root_sync`."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, purge_dir_within_root_sync, storage_root, target
    )
