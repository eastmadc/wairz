"""Pure-ASGI API-key authentication middleware.

Covers both ``http`` and ``websocket`` scopes. The prior
:class:`starlette.middleware.base.BaseHTTPMiddleware`-based
implementation only intercepted HTTP scope, leaving WebSocket
endpoints (``/ws`` terminal shell, ``/{session_id}/terminal``
emulation TCP proxy) reachable without any credential when the
backend listened on a non-loopback address.

Key sources (checked in order):
    1. ``X-API-Key`` request header  (preferred; used by axios + CLI)
    2. ``api_key`` query-string parameter  (fallback for browser
       WebSockets — ``Sec-WebSocket-*`` headers are kernel-controlled,
       so query-param is the only browser path).

Auth is disabled entirely when ``settings.api_key`` is falsy, so
fresh dev checkouts without an API_KEY env var keep working.

On failure:
    - HTTP scope → ``401 {"detail": "Missing or invalid API key"}``
    - WebSocket scope → handshake is accepted so a clean WebSocket
      close frame can be sent with ``code=4401`` reason
      ``"unauthenticated"``. Browsers surface this on
      ``onclose.code``, which the frontend uses to distinguish auth
      failure from other rejection reasons (project-not-found uses
      4004, etc.). Rejecting before ``accept()`` would collapse to
      HTTP 403 and lose the code distinction in the browser.
"""

import secrets
from urllib.parse import parse_qs

from starlette.types import ASGIApp, Receive, Scope, Send

from app.config import get_settings

# Paths that must remain reachable without a key — liveness probes,
# container healthchecks, reverse-proxy checks.
_EXEMPT_HTTP_PATHS: frozenset[str] = frozenset({
    "/health",
    "/health/deep",
    "/api/v1/health",
})


class APIKeyASGIMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        settings = get_settings()
        expected = settings.api_key

        # Auth disabled — pass every request through untouched. Preserves
        # the historical "API_KEY unset → open backend" dev ergonomic;
        # the require-api-key gate is the separate B.1.a follow-on.
        if not expected:
            await self.app(scope, receive, send)
            return

        scope_type = scope.get("type")

        if scope_type == "http":
            # CORS preflight — browsers never include custom headers on
            # preflight, so gating OPTIONS would break all cross-origin
            # calls even with a valid key on the real request.
            if scope.get("method") == "OPTIONS":
                await self.app(scope, receive, send)
                return
            if scope.get("path") in _EXEMPT_HTTP_PATHS:
                await self.app(scope, receive, send)
                return
            if not _check_key(scope, expected):
                await _http_401(send)
                return
            await self.app(scope, receive, send)
            return

        if scope_type == "websocket":
            if not _check_key(scope, expected):
                await _ws_close_4401(send)
                return
            await self.app(scope, receive, send)
            return

        # lifespan and any unknown future scope types — pass through.
        await self.app(scope, receive, send)


def _check_key(scope: Scope, expected: str) -> bool:
    """Return True when the request carries a matching API key."""
    provided: str | None = None

    # Header path. Starlette ASGI scope["headers"] is list[tuple[bytes, bytes]];
    # keys are already lowercased by the server.
    for name, value in scope.get("headers") or []:
        if name == b"x-api-key":
            provided = value.decode("latin-1")
            break

    if not provided:
        qs = scope.get("query_string", b"") or b""
        if qs:
            params = parse_qs(qs.decode("latin-1"))
            candidates = params.get("api_key")
            if candidates:
                provided = candidates[0]

    if not provided:
        return False
    return secrets.compare_digest(provided, expected)


async def _http_401(send: Send) -> None:
    await send({
        "type": "http.response.start",
        "status": 401,
        "headers": [(b"content-type", b"application/json")],
    })
    await send({
        "type": "http.response.body",
        "body": b'{"detail":"Missing or invalid API key"}',
    })


async def _ws_close_4401(send: Send) -> None:
    # Accept the handshake so the subsequent close frame carries our
    # 4xxx code to the client (browsers surface CloseEvent.code only on
    # a completed handshake; a pre-accept rejection collapses to HTTP
    # 403 with CloseEvent.code=1006).
    # 4xxx codes are application-defined per RFC 6455 §7.4.2; 4401
    # mirrors HTTP 401 for easy mental mapping.
    await send({"type": "websocket.accept"})
    await send({
        "type": "websocket.close",
        "code": 4401,
        "reason": "unauthenticated",
    })
