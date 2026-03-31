"""Async Redis client utility.

Provides a connection factory and context manager for Redis access.
All operations are designed to fail silently — Redis is used as a cache
layer and must never block the critical path.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

import redis.asyncio as aioredis

from app.config import get_settings

logger = logging.getLogger(__name__)

# Module-level client singleton (lazily initialized)
_redis_client: aioredis.Redis | None = None


def _create_redis_client() -> aioredis.Redis:
    """Create an async Redis client from settings."""
    settings = get_settings()
    return aioredis.from_url(
        settings.redis_url,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
    )


def get_redis_client() -> aioredis.Redis:
    """Get or create the module-level Redis client singleton."""
    global _redis_client
    if _redis_client is None:
        _redis_client = _create_redis_client()
    return _redis_client


@asynccontextmanager
async def get_redis() -> AsyncIterator[aioredis.Redis]:
    """Async context manager that yields a Redis client.

    Usage:
        async with get_redis() as r:
            await r.get("key")

    If Redis is unavailable, yields None so callers can guard with:
        async with get_redis() as r:
            if r is not None:
                ...
    """
    try:
        client = get_redis_client()
        yield client
    except Exception:
        logger.debug("Redis unavailable, yielding None")
        yield None  # type: ignore[arg-type]
