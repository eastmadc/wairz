# =============================================================================
# FirmAE System Emulation Container for Wairz
#
# Wraps FirmAE (https://github.com/pr0v3rbs/FirmAE) in a Docker container
# with a Flask API shim for automated full-system firmware emulation.
#
# Includes:
#   - FirmAE with all dependencies (binwalk, QEMU system, PostgreSQL)
#   - Internal ephemeral PostgreSQL 15 instance (FirmAE's state DB)
#   - Flask API shim on port 5000
#   - nmap for service discovery, socat for serial console proxying
#
# Requires: --privileged (or NET_ADMIN + SYS_ADMIN + MKNOD caps + /dev/net/tun)
# =============================================================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV FIRMAE_DIR=/opt/FirmAE
ENV PGDATA=/var/lib/postgresql/15/firmae
ENV PGUSER=postgres
ENV FLASK_APP=/opt/shim/app.py

# ---------------------------------------------------------------------------
# 1. System dependencies
# ---------------------------------------------------------------------------

# Add PostgreSQL apt repo (postgresql-15 not in default jammy repos)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gnupg2 lsb-release curl ca-certificates \
    && echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
       > /etc/apt/sources.list.d/pgdg.list \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
       | gpg --dearmor -o /etc/apt/trusted.gpg.d/postgresql.gpg \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    # PostgreSQL 15
    postgresql-15 postgresql-client-15 \
    # QEMU system emulators
    qemu-system-arm qemu-system-mips qemu-system-x86 \
    qemu-utils \
    # Networking tools
    nmap socat iproute2 iptables bridge-utils net-tools iputils-ping tcpdump \
    busybox-static \
    # FirmAE dependencies
    binwalk \
    python3 python3-pip python3-venv python3-psycopg2 \
    git wget curl \
    unzip p7zip-full \
    mtd-utils gzip bzip2 arj lhasa \
    squashfs-tools \
    e2fsprogs \
    kpartx \
    uml-utilities \
    sudo bc file cpio fdisk bash-static \
    lsof procps \
    # Build tools (for FirmAE's libnvram etc.)
    build-essential gcc-mipsel-linux-gnu gcc-mips-linux-gnu \
    gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu \
    liblzma-dev liblzo2-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 2. Clone FirmAE
# ---------------------------------------------------------------------------
RUN git clone --depth 1 https://github.com/pr0v3rbs/FirmAE.git ${FIRMAE_DIR}

WORKDIR ${FIRMAE_DIR}

# ---------------------------------------------------------------------------
# 3. Build FirmAE's native components (libnvram, console, etc.)
# ---------------------------------------------------------------------------
# FirmAE's install.sh tries to install system packages and start postgres;
# we've already handled those above. Build just the native binaries.
RUN cd ${FIRMAE_DIR}/firmae-kernel-v4.1 2>/dev/null || true && \
    # Build libnvram for each architecture if the source exists
    if [ -d "${FIRMAE_DIR}/src/libnvram" ]; then \
        cd ${FIRMAE_DIR}/src/libnvram && \
        make clean 2>/dev/null; \
        CC=mipsel-linux-gnu-gcc make 2>/dev/null && \
            cp libnvram.so ${FIRMAE_DIR}/binaries/libnvram.so.mipsel 2>/dev/null; \
        make clean 2>/dev/null; \
        CC=mips-linux-gnu-gcc make 2>/dev/null && \
            cp libnvram.so ${FIRMAE_DIR}/binaries/libnvram.so.mips 2>/dev/null; \
        make clean 2>/dev/null; \
        CC=arm-linux-gnueabi-gcc make 2>/dev/null && \
            cp libnvram.so ${FIRMAE_DIR}/binaries/libnvram.so.armel 2>/dev/null; \
        make clean 2>/dev/null; \
    fi && \
    # Build console helper if it exists
    if [ -d "${FIRMAE_DIR}/src/console" ]; then \
        cd ${FIRMAE_DIR}/src/console && make 2>/dev/null || true; \
    fi

# ---------------------------------------------------------------------------
# 3b. Patch FirmAE for Docker compatibility (no kpartx/loop partitions)
# ---------------------------------------------------------------------------
COPY patches/ /tmp/patches/
RUN chmod +x /tmp/patches/*.sh && \
    /tmp/patches/docker-compat.sh ${FIRMAE_DIR} && \
    rm -rf /tmp/patches

# ---------------------------------------------------------------------------
# 4. Download pre-built FirmAE kernels
# ---------------------------------------------------------------------------
RUN mkdir -p ${FIRMAE_DIR}/binaries && \
    cd ${FIRMAE_DIR} && \
    # FirmAE stores kernels in its binaries/ directory
    # Download kernel images if the download script exists
    if [ -f "${FIRMAE_DIR}/download.sh" ]; then \
        bash ${FIRMAE_DIR}/download.sh 2>/dev/null || true; \
    fi

# ---------------------------------------------------------------------------
# 5. Initialize PostgreSQL data directory
# ---------------------------------------------------------------------------
RUN mkdir -p ${PGDATA} /run/postgresql && \
    chown -R postgres:postgres /var/lib/postgresql /run/postgresql && \
    su - postgres -c "/usr/lib/postgresql/15/bin/initdb -D ${PGDATA}"

# ---------------------------------------------------------------------------
# 6. Install Flask API shim dependencies
# ---------------------------------------------------------------------------
RUN pip3 install --no-cache-dir \
    flask \
    gunicorn \
    psycopg2-binary \
    python-magic

# ---------------------------------------------------------------------------
# 7. Copy shim application and entrypoint
# ---------------------------------------------------------------------------
COPY shim/ /opt/shim/
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh /opt/shim/*.py 2>/dev/null || true

# ---------------------------------------------------------------------------
# 8. Create working directories and set permissions
# ---------------------------------------------------------------------------
RUN mkdir -p /firmwares /data/logs /data/scratch && \
    # FirmAE needs write access to its own directories
    chmod -R 777 ${FIRMAE_DIR}/scratch 2>/dev/null || mkdir -p ${FIRMAE_DIR}/scratch && chmod 777 ${FIRMAE_DIR}/scratch && \
    chmod -R 777 ${FIRMAE_DIR}/images 2>/dev/null || mkdir -p ${FIRMAE_DIR}/images && chmod 777 ${FIRMAE_DIR}/images

# Expose Flask shim API
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

ENTRYPOINT ["/opt/entrypoint.sh"]
