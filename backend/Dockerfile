FROM python:3.12-slim AS base

# Install system dependencies for firmware analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk \
    sleuthkit \
    squashfs-tools \
    cramfsswap \
    util-linux-extra \
    mtd-utils \
    e2fsprogs \
    cpio \
    p7zip-full \
    cabextract \
    lzop \
    srecord \
    file \
    libmagic1 \
    build-essential \
    git \
    zlib1g-dev \
    liblzma-dev \
    liblzo2-dev \
    wget \
    curl \
    unzip \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/* \
    && printf '#!/bin/sh\n# Wrapper: translates cramfsck -x <dir> <file> to fsck.cramfs --extract=<dir> <file>\nif [ "$1" = "-x" ]; then shift; dir="$1"; shift; exec fsck.cramfs --extract="$dir" "$@"; fi\nexec fsck.cramfs "$@"\n' > /usr/local/bin/cramfsck \
    && chmod +x /usr/local/bin/cramfsck

# Install Python-based firmware extraction tools used by binwalk
RUN pip3 install --no-cache-dir --break-system-packages \
    jefferson \
    ubi_reader \
    && pip3 install --no-cache-dir --break-system-packages \
       git+https://github.com/devttys0/yaffshiv.git 2>/dev/null \
    || echo "WARN: yaffshiv install failed — YAFFS extraction won't work"

# Install sasquatch for non-standard SquashFS (vendor-modified)
# Try the devttys0 fork first; patch out -Werror to handle newer compiler warnings
RUN git clone https://github.com/devttys0/sasquatch.git /tmp/sasquatch \
    && cd /tmp/sasquatch \
    && sed -i 's/-Werror//g' squashfs-tools/Makefile patches/*.patch 2>/dev/null \
    && sed -i 's/-Wall -Werror/-Wall/g' squashfs-tools/Makefile 2>/dev/null; \
    cd /tmp/sasquatch && ./build.sh 2>/dev/null \
    && cp /usr/local/bin/sasquatch /usr/local/bin/sasquatch 2>/dev/null; \
    rm -rf /tmp/sasquatch; \
    which sasquatch || echo "WARN: sasquatch build failed — non-standard SquashFS won't extract"

# Install OpenJDK 21 for Ghidra (JDK 17 not available in Trixie)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra
ARG GHIDRA_VERSION=11.3.1
ARG GHIDRA_DATE=20250219
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
        -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm /tmp/ghidra.zip

# On ARM64: build native decompiler from Ghidra source (official release
# only ships linux_x86_64 natives — no linux_arm_64). The decompiler is a
# C++ binary invoked by the Java frontend for decompilation.
# On x86_64: skip (pre-built binaries are included in the release ZIP).
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        echo "ARM64 detected — building Ghidra native decompiler from source..." && \
        apt-get update && apt-get install -y --no-install-recommends bison flex binutils-dev && \
        git clone --depth 1 --branch Ghidra_${GHIDRA_VERSION}_build \
            https://github.com/NationalSecurityAgency/ghidra /tmp/ghidra-src && \
        cd /tmp/ghidra-src/Ghidra/Features/Decompiler/src/decompile/cpp && \
        sed -i 's/-m32//g' Makefile && \
        make decomp_opt -j$(nproc) ARCH_FLAGS= && \
        mkdir -p /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64 && \
        cp decomp_opt /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/decompile && \
        chmod +x /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/decompile && \
        cd /tmp/ghidra-src/Ghidra/Features/Decompiler/src/decompile/cpp && \
        make sleigh_opt -j$(nproc) ARCH_FLAGS= && \
        cp sleigh_opt /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/sleighc && \
        chmod +x /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/sleighc && \
        rm -rf /tmp/ghidra-src && \
        apt-get purge -y bison flex && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* && \
        echo "Ghidra ARM64 natives built successfully"; \
    else \
        echo "x86_64 detected — using pre-built Ghidra natives"; \
    fi

# Install Grype for local vulnerability scanning (multi-arch)
ARG GRYPE_VERSION=0.87.0
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then GOARCH=amd64; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then GOARCH=arm64; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    curl -sSfL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${GOARCH}.tar.gz" \
        | tar xz -C /usr/local/bin grype && \
    chmod +x /usr/local/bin/grype

# Install Syft for SBOM generation (multi-arch)
ARG SYFT_VERSION=1.41.2
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then GOARCH=amd64; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then GOARCH=arm64; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    curl -sSfL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${GOARCH}.tar.gz" \
        | tar xz -C /usr/local/bin syft && \
    chmod +x /usr/local/bin/syft

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Create non-root user and add to docker group for emulation container management.
# The docker socket GID from the host is passed via build arg (default 999).
ARG DOCKER_GID=999
RUN groupadd -g ${DOCKER_GID} docker || true \
    && useradd -m -s /bin/bash wairz \
    && usermod -aG docker wairz

# Set up working directory
WORKDIR /app

# Copy dependency files first for caching
COPY pyproject.toml uv.lock* ./

# Install dependencies
RUN uv sync --no-dev --no-editable 2>/dev/null || uv sync --no-editable

# Copy application code
COPY . .

# Bake in default emulation kernels so they're available out of the box.
# The docker-compose bind mount (./emulation/kernels:/opt/kernels) overlays
# on top at runtime, allowing users to add custom kernels.
COPY --from=kernels . /opt/kernels/

# Create data and Ghidra project directories
RUN mkdir -p /data/firmware /tmp/ghidra_projects \
    && chown -R wairz:wairz /data /app /tmp/ghidra_projects /opt/ghidra /opt/kernels

USER wairz

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

EXPOSE 8000

CMD ["sh", "-c", "uv run alembic upgrade head && uv run uvicorn app.main:app --host 0.0.0.0 --port 8000"]
