#!/bin/sh
set -e

# Fix Docker socket group at runtime so emulation/fuzzing work regardless
# of the host's docker GID. Runs as root, then drops to wairz.
if [ -S /var/run/docker.sock ]; then
    SOCK_GID=$(stat -c %g /var/run/docker.sock)
    CUR_GID=$(getent group docker 2>/dev/null | cut -d: -f3)
    if [ -n "$SOCK_GID" ] && [ "$SOCK_GID" != "${CUR_GID:-}" ]; then
        groupmod -g "$SOCK_GID" docker 2>/dev/null || groupadd -g "$SOCK_GID" docker 2>/dev/null || true
        usermod -aG docker wairz 2>/dev/null || true
    fi
fi

# Use the pre-built venv directly instead of `uv run` which recreates the
# venv and wipes manually-installed packages (Qiling, keystone-engine).
exec su -s /bin/sh wairz -c '.venv/bin/python -m alembic upgrade head && .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000'
