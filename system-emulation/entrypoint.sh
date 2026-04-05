#!/bin/bash
# =============================================================================
# FirmAE System Emulation Container — Entrypoint
#
# 1. Ensure /dev/net/tun exists (required for QEMU TAP networking)
# 2. Start internal PostgreSQL (FirmAE's state database)
# 3. Initialize FirmAE database schema
# 4. Start Flask API shim via gunicorn
# =============================================================================
set -e

FIRMAE_DIR="${FIRMAE_DIR:-/opt/FirmAE}"
PGDATA="${PGDATA:-/var/lib/postgresql/15/firmae}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-postgres}"
FIRMAE_DB="firmware"

# ---------------------------------------------------------------------------
# 1. Ensure /dev/net/tun exists
# ---------------------------------------------------------------------------
if [ ! -c /dev/net/tun ]; then
    echo "[entrypoint] Creating /dev/net/tun..."
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 666 /dev/net/tun
fi

# ---------------------------------------------------------------------------
# 2. Start PostgreSQL
# ---------------------------------------------------------------------------
echo "[entrypoint] Starting PostgreSQL..."
mkdir -p /run/postgresql
chown postgres:postgres /run/postgresql

# Start PostgreSQL as the postgres user
su - postgres -c "/usr/lib/postgresql/15/bin/pg_ctl -D ${PGDATA} -l /data/logs/postgresql.log -o '-p ${PGPORT}' start"

# Wait for PostgreSQL to be ready
echo "[entrypoint] Waiting for PostgreSQL..."
for i in $(seq 1 30); do
    if su - postgres -c "pg_isready -p ${PGPORT}" >/dev/null 2>&1; then
        echo "[entrypoint] PostgreSQL is ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "[entrypoint] ERROR: PostgreSQL failed to start within 30s" >&2
        cat /data/logs/postgresql.log >&2
        exit 1
    fi
    sleep 1
done

# ---------------------------------------------------------------------------
# 3. Initialize FirmAE database
# ---------------------------------------------------------------------------
echo "[entrypoint] Initializing FirmAE database..."

# Create the firmware database if it doesn't exist
su - postgres -c "psql -p ${PGPORT} -tc \"SELECT 1 FROM pg_database WHERE datname='${FIRMAE_DB}'\"" | grep -q 1 || \
    su - postgres -c "createdb -p ${PGPORT} ${FIRMAE_DB}"

# Apply FirmAE schema if the schema file exists
if [ -f "${FIRMAE_DIR}/database/schema" ]; then
    su - postgres -c "psql -p ${PGPORT} -d ${FIRMAE_DB} -f ${FIRMAE_DIR}/database/schema" 2>/dev/null || true
elif [ -f "${FIRMAE_DIR}/database/schema.sql" ]; then
    su - postgres -c "psql -p ${PGPORT} -d ${FIRMAE_DB} -f ${FIRMAE_DIR}/database/schema.sql" 2>/dev/null || true
fi

# Set FirmAE's DB password if needed
su - postgres -c "psql -p ${PGPORT} -c \"ALTER USER postgres PASSWORD '${POSTGRES_PASSWORD:-firmae}'\"" 2>/dev/null || true

echo "[entrypoint] Database initialized."

# ---------------------------------------------------------------------------
# 4. Start Flask API shim
# ---------------------------------------------------------------------------
echo "[entrypoint] Starting Flask API shim on :5000..."

export FIRMAE_DIR
export PGHOST=localhost
export PGPORT
export PGUSER
export PGPASSWORD="${POSTGRES_PASSWORD:-firmae}"
export PGDATABASE="${FIRMAE_DB}"

exec gunicorn \
    --bind 0.0.0.0:5000 \
    --workers 1 \
    --threads 4 \
    --timeout 300 \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    "app:create_app()" \
    --chdir /opt/shim
