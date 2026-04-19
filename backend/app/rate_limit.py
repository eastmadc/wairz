"""Shared rate-limiter instance (B.1.b).

Import the `limiter` object from here in routers that need per-endpoint limits.
The FastAPI app in ``main.py`` attaches this limiter to ``app.state`` and
registers the 429 exception handler so all responses are consistent.

Usage in a router::

    from app.rate_limit import limiter
    from starlette.requests import Request

    @router.post("")
    @limiter.limit("5/minute")
    async def my_endpoint(request: Request, ...):
        ...

The ``request: Request`` parameter is **required** by slowapi — it must be the
first positional parameter of the endpoint function (or present by name).
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# In-memory storage is fine for single-instance deployments.
# To enable distributed rate limiting across multiple replicas, pass:
#   storage_uri="redis://redis:6379/1"
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
