#!/bin/sh
# Download YARA Forge core community rules.
# Safe to re-run — overwrites previous download.
# Called from Dockerfile entrypoint or manually.

set -e

YARA_FORGE_DIR="${YARA_FORGE_DIR:-/data/yara-forge}"
YARA_FORGE_URL="https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.yar"

mkdir -p "$YARA_FORGE_DIR"

echo "Downloading YARA Forge core rules..."
if curl -fsSL --max-time 30 -o "$YARA_FORGE_DIR/yara-forge-rules-core.yar" "$YARA_FORGE_URL"; then
    RULE_COUNT=$(grep -c "^rule " "$YARA_FORGE_DIR/yara-forge-rules-core.yar" 2>/dev/null || echo "?")
    echo "YARA Forge: downloaded $RULE_COUNT rules to $YARA_FORGE_DIR"
else
    echo "WARN: YARA Forge download failed (network unavailable?) — continuing without community rules"
fi
