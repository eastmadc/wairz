"""ARQ worker configuration for background jobs.

Start the worker with:
    uv run arq app.workers.arq_worker.WorkerSettings

Or from docker compose:
    docker compose exec backend uv run arq app.workers.arq_worker.WorkerSettings
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from arq.connections import RedisSettings

from app.config import get_settings

logger = logging.getLogger(__name__)


def get_redis_settings() -> RedisSettings:
    """Parse redis_url from app settings into ARQ RedisSettings."""
    settings = get_settings()
    url = settings.redis_url
    parsed = urlparse(url)
    return RedisSettings(
        host=parsed.hostname or "localhost",
        port=parsed.port or 6379,
        database=int(parsed.path.lstrip("/") or "0"),
    )


# Import task functions so ARQ can discover them
from app.workers.unpack_job import run_unpack_job  # noqa: E402


class WorkerSettings:
    """ARQ worker settings — passed to ``arq`` CLI."""

    functions = [run_unpack_job]
    redis_settings = get_redis_settings()
    max_jobs = 3
    job_timeout = 600  # 10 minutes per job
