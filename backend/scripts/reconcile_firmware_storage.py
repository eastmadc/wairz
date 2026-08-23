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

**"No database row" is not sufficient evidence that a tree is dead.**
A device's row can be deleted while its tree stays load-bearing for
scripts and profiles. This has already cost real data: a firmware tree
that every DB-based check cleared was the live tablet for an ongoing
assessment, with its path hardcoded in a recovery script. The DB is the
wrong oracle on its own.

So before removing anything, this script greps the repositories for
each orphan UUID and REFUSES any tree whose id appears in a source file
(``.py``/``.sh``/``.js``/``.ts``). A hit in prose (a postmortem, a
planning note) is reported but not blocking; a hit in code is decisive.
Override with ``--force-referenced`` only when you have read the hit
and know it is inert.

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


def _default_repo_roots() -> list[str]:
    """The wairz checkout this script lives in, if it is on disk.

    Inside the container only /app exists; on the host the script runs
    from the checkout. Both are searched when present.
    """
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    roots = [os.path.dirname(here), "/app"]
    return [r for r in dict.fromkeys(roots) if os.path.isdir(r)]


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


CODE_SUFFIXES = (".py", ".sh", ".js", ".ts", ".tsx", ".yml", ".yaml", ".json")
SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".worktrees", "output"}


def _scan_repo_refs(roots: list[str], ids: set[str]) -> dict[str, dict[str, list[str]]]:
    """Map each id -> {"code": [files], "prose": [files]}.

    Walks the trees once, reading each candidate file a single time and
    testing every id against it. Grepping per (id x file) is what made
    the naive version of this check too slow to actually run — and a
    check too slow to run is a check that does not happen.
    """
    hits: dict[str, dict[str, list[str]]] = {i: {"code": [], "prose": []} for i in ids}
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(path) > 8 * 1024 * 1024:
                        continue
                    with open(path, encoding="utf-8", errors="ignore") as fh:
                        blob = fh.read()
                except OSError:
                    continue
                for i in ids:
                    if i in blob:
                        kind = "code" if name.endswith(CODE_SUFFIXES) else "prose"
                        hits[i][kind].append(path)
    return hits


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
    parser.add_argument(
        "--repo",
        action="append",
        default=None,
        help="repository root to grep for orphan ids (repeatable). "
        "Defaults to the wairz checkout containing this script.",
    )
    parser.add_argument(
        "--force-referenced",
        action="store_true",
        help="remove even trees whose id appears in a source file. "
        "Read the hits first — this is how live data gets destroyed.",
    )
    args = parser.parse_args()

    settings = get_settings()
    storage_root = settings.storage_root

    db_projects, db_firmware = await _load_db_ids()
    orphans = _scan(storage_root, db_projects, db_firmware)
    orphans.sort(key=lambda o: o["bytes"], reverse=True)
    total = sum(o["bytes"] for o in orphans)

    # The id whose directory would actually be removed.
    for o in orphans:
        o["target_id"] = o["firmware_id"] or o["project_id"]

    repo_roots = args.repo or _default_repo_roots()
    refs = _scan_repo_refs(repo_roots, {o["target_id"] for o in orphans})
    for o in orphans:
        r = refs.get(o["target_id"], {"code": [], "prose": []})
        o["code_refs"] = r["code"]
        o["prose_refs"] = r["prose"]
        o["blocked"] = bool(r["code"]) and not args.force_referenced

    if args.apply:
        for orphan in orphans:
            if orphan["blocked"]:
                orphan["removed"] = False
                orphan["error"] = "blocked: referenced by source code"
                continue
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
                if orphan["blocked"]:
                    flag = "  << BLOCKED: referenced in code"
                elif orphan["code_refs"]:
                    flag = "  << code refs OVERRIDDEN"
                elif orphan["prose_refs"]:
                    flag = f"  (prose refs: {len(orphan['prose_refs'])})"
                if args.apply and not orphan["blocked"]:
                    flag += " [removed]" if orphan.get("removed") else " [FAILED]"
                print(
                    f"  {_human(orphan['bytes']):>10}  {orphan['kind']:<16} "
                    f"{orphan['target_id']}{flag}"
                )
                for p in orphan["code_refs"][:3]:
                    print(f"                  code: {p}")
            print()
            blocked = [o for o in orphans if o["blocked"]]
            print(f"TOTAL: {len(orphans)} orphans, {_human(total)}")
            if blocked:
                print(
                    f"BLOCKED: {len(blocked)} tree(s), "
                    f"{_human(sum(o['bytes'] for o in blocked))} — "
                    "read the code refs above before using --force-referenced."
                )

    if orphans and not args.apply:
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        raise SystemExit(2) from None
