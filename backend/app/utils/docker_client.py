"""Docker client factory — routes all Docker SDK calls through the socket proxy.

All services and routers that need a Docker client should use ``get_docker_client()``
instead of ``docker.from_env()``.  This factory reads ``settings.docker_host``
(backed by the ``DOCKER_HOST`` env var), which in production points to the
``docker-proxy`` sidecar (``tcp://docker-proxy:2375``) rather than the raw
host socket.  This narrows blast radius: a backend RCE cannot escape to the
host via privileged-container creation because the proxy enforces a per-endpoint
allowlist (CONTAINERS, IMAGES, NETWORKS, EVENTS, EXEC, POST; VOLUMES=0).

For development outside Docker (no proxy sidecar) set ``DOCKER_HOST=''`` or
``DOCKER_HOST=unix:///var/run/docker.sock`` in your environment to fall back
to the default socket.
"""

import docker

from app.config import get_settings


def get_docker_client() -> docker.DockerClient:
    """Return a Docker client configured to use the socket proxy.

    The client is created fresh on each call (not cached) — same pattern as
    the previous ``docker.from_env()`` calls — so callers manage lifetime.
    """
    host = get_settings().docker_host
    if host:
        return docker.DockerClient(base_url=host)
    # Fallback: let the SDK discover the socket via DOCKER_HOST env / default path
    return docker.from_env()
