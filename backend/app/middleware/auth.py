"""
API key authentication middleware.

If ``settings.api_key`` is empty the middleware is a no-op (auth disabled).
Otherwise every request must carry a valid key via the ``X-API-Key`` header
or the ``api_key`` query parameter.
"""

import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import get_settings

# Paths that never require authentication.
_EXEMPT_PATHS: set[str] = {"/", "/health", "/api/v1/health"}


class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        settings = get_settings()

        # Auth disabled — let everything through.
        if not settings.api_key:
            return await call_next(request)

        # CORS preflight must always pass.
        if request.method == "OPTIONS":
            return await call_next(request)

        # Exempt well-known paths.
        if request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        # Extract key from header or query parameter.
        provided_key = (
            request.headers.get("X-API-Key")
            or request.query_params.get("api_key")
        )

        if not provided_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing API key"},
            )

        if not secrets.compare_digest(provided_key, settings.api_key):
            return JSONResponse(
                status_code=403,
                content={"detail": "Invalid API key"},
            )

        return await call_next(request)
