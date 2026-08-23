#!/usr/bin/env python3
"""Reconcile the firmware storage volume against the database.

Reports — and optionally removes — two classes of orphan:

``orphan-project``
    ``{storage_root}/projects/{uuid}/`` with no row in ``projects``.
    Historically produced by ``DELETE /api/v1/projects/{id}``, which
    dropped the rows through the ORM cascade and never touched disk.

``orphan-firmware``
    ``.../projects/{live_uuid}/firmware/{uuid}/`` with no row in
    ``firmware``. Produced by upload paths that created the directory
    before the row and did not clean up on the way out (413 oversize,
    409 dedup, client disconnect mid-stream).

Both leaks are fixed in the application code; this script exists to
clear what already accumulated, and to run periodically as a drift
check afterwards.

DEFAULT IS DRY RUN. Nothing is removed unless ``--apply`` is passed.

Usage::

    # inside the backend/worker container
    python scripts/reconcile_firmware_storage.py
    python scripts/reconcile_firmware_storage.py --json
    python scripts/reconcile_firmware_storage.py --apply

Exit codes: 0 = no orphans (or --apply succeeded), 1 = orphans found in
dry-run mode (so it can be used as a cron drift alarm), 2 = error.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid

from sqlalchemy import select

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import get_settings  # noqa: E402
from app.database import async_session_factory  # noqa: E402
from app.models.firmware import Firmware  # noqa: E402
from app.models.project import Project  # noqa: E402
from app.services.storage_paths import purge_dir_within_root_sync  # noqa: E402


def _looks_like_uuid(name: str) -> bool:
    try:
        uuid.UUID(name)
    except (ValueError, AttributeError):
        return False
    return True


def _dir_size_bytes(path: str) -> int:
    total = 0
    for root, _dirs, files in os.walk(path, onerror=lambda _e: None):
        for fname in files:
            try:
                total += os.lstat(os.path.join(root, fname)).st_size
            except OSError:
                pass
    return total


def _human(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


async def _load_db_ids() -> tuple[set[str], set[str]]:
    async with async_session_factory() as db:
        projects = {
            str(pid) for pid in (await db.execute(select(Project.id))).scalars()
        }
        firmware = {
            str(fid) for fid in (await db.execute(select(Firmware.id))).scalars()
        }
    return projects, firmware


def _scan(storage_root: str, db_projects: set[str], db_firmware: set[str]) -> list[dict]:
    projects_root = os.path.join(storage_root, "projects")
    orphans: list[dict] = []
    if not os.path.isdir(projects_root):
        return orphans

    for project_name in sorted(os.listdir(projects_root)):
        project_path = os.path.join(projects_root, project_name)
        if not os.path.isdir(project_path) or not _looks_like_uuid(project_name):
            continue

        if project_name not in db_projects:
            orphans.append(
                {
                    "kind": "orphan-project",
                    "project_id": project_name,
                    "firmware_id": None,
                    "path": project_path,
                    "bytes": _dir_size_bytes(project_path),
                }
            )
            # Whole tree goes; do not also enumerate its children.
            continue

        firmware_root = os.path.join(project_path, "firmware")
        if not os.path.isdir(firmware_root):
            continue
        for fw_name in sorted(os.listdir(firmware_root)):
            fw_path = os.path.join(firmware_root, fw_name)
            if not os.path.isdir(fw_path) or not _looks_like_uuid(fw_name):
                continue
            if fw_name in db_firmware:
                continue
            orphans.append(
                {
                    "kind": "orphan-firmware",
                    "project_id": project_name,
                    "firmware_id": fw_name,
                    "path": fw_path,
                    "bytes": _dir_size_bytes(fw_path),
                }
            )
    return orphans


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="actually remove the orphans (default is dry run)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()

    settings = get_settings()
    storage_root = settings.storage_root

    db_projects, db_firmware = await _load_db_ids()
    orphans = _scan(storage_root, db_projects, db_firmware)
    orphans.sort(key=lambda o: o["bytes"], reverse=True)
    total = sum(o["bytes"] for o in orphans)

    if args.apply:
        for orphan in orphans:
            try:
                purge_dir_within_root_sync(storage_root, orphan["path"])
                orphan["removed"] = True
            except (OSError, ValueError) as exc:
                orphan["removed"] = False
                orphan["error"] = str(exc)

    if args.json:
        print(
            json.dumps(
                {
                    "storage_root": storage_root,
                    "db_projects": len(db_projects),
                    "db_firmware": len(db_firmware),
                    "orphan_count": len(orphans),
                    "orphan_bytes": total,
                    "applied": args.apply,
                    "orphans": orphans,
                },
                indent=2,
            )
        )
    else:
        mode = "REMOVING" if args.apply else "DRY RUN — nothing removed"
        print(f"storage_root : {storage_root}")
        print(f"db projects  : {len(db_projects)}   db firmware: {len(db_firmware)}")
        print(f"mode         : {mode}")
        print()
        if not orphans:
            print("No orphans found.")
        else:
            for orphan in orphans:
                flag = ""
                if args.apply:
                    flag = " [removed]" if orphan.get("removed") else " [FAILED]"
                label = orphan["firmware_id"] or orphan["project_id"]
                print(
                    f"  {_human(orphan['bytes']):>10}  {orphan['kind']:<16} "
                    f"{label}{flag}"
                )
            print()
            print(f"TOTAL: {len(orphans)} orphans, {_human(total)}")

    if orphans and not args.apply:
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        raise SystemExit(2) from None
