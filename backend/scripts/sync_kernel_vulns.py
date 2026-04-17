#!/usr/bin/env python3
"""Manually sync kernel.org vulns.git into the Redis subsystem index.

The arq worker runs this daily at 03:00 UTC.  Use this CLI entry point for
first-boot population, debugging, or a forced resync::

    docker compose exec backend /app/.venv/bin/python scripts/sync_kernel_vulns.py

The script prints the :func:`sync` return dict (``status``, ``cve_count``,
``subsystem_count``, ``duration_seconds``) and exits 0 on ``status=="ok"``,
1 otherwise — safe to drop into an Ops cron or a smoke test.
"""
from __future__ import annotations

import asyncio
import json
import sys


async def _main() -> int:
    # Late import so importing this file (e.g. for linters) doesn't eagerly
    # pull SQLAlchemy, Redis, etc.
    from app.services.hardware_firmware import kernel_vulns_index as kvi

    result = await kvi.sync()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "ok" else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
