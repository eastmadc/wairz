r"""add firmware.vuln_scan_provenance (Rule #37 truthfulness surface)

Revision ID: a3f7c21e9b40
Revises: b8c9d0e1f2a3
Create Date: 2026-07-25 12:00:00.000000

The vuln-scan 202+polling state machine (revision ``c1d2e3f4a5b6``) deliberately
carries NO JSONB result column: the ``sbom_vulnerabilities`` rows ARE the result
and the per-severity breakdown is cheap to recompute.

One fact is NOT recoverable from those rows — WHICH CVE source enriched the scan.
A scan run while the pinned NVD cache (Rule #37) was unavailable or
half-populated persists ``vuln_scan_status='completed'`` with zero vulnerability
rows, byte-identical to a genuinely clean firmware; only the backend log knew the
difference. This column persists the scan-level provenance the
``VulnerabilityService`` already computes:

    {schema_version, engine, manifest_sha, populated_at, cve_count,
     modes: {cache_hit|cache_miss|cache_degraded|cache_unavailable|live_fallback: n},
     lookups, degraded, degraded_reasons[], candidates_total, resolved_total,
     skipped_total, worst_mode, enrichment_status, warning}

so the REST polling endpoint + the MCP tool can tell "scanned against pinned
cache sha X" from "cache unavailable — no enrichment ran".

Nullable with no server_default: NULL means "no completed scan has recorded
provenance yet" (every pre-existing row), which the Rule #35c normaliser
``_normalize_firmware_vuln_scan_provenance`` maps to ``None`` — read as UNKNOWN
provenance, never as a healthy pinned-cache scan.

Per CLAUDE.md Rule #19 evidence-first: revision id ``a3f7c21e9b40`` verified FREE (``c9d0e1f2a3b4`` was already taken —
caught by the pre-authoring grep)
before authoring; chains from the current single head ``b8c9d0e1f2a3``.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a3f7c21e9b40"
down_revision: str | None = "b8c9d0e1f2a3"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "vuln_scan_provenance",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("firmware", "vuln_scan_provenance")
