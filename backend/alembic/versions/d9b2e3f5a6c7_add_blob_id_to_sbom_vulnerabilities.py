"""add blob_id FK to sbom_vulnerabilities for hardware firmware CVE matches

Revision ID: d9b2e3f5a6c7
Revises: c8a1f4e2d5b6
Create Date: 2026-04-17 02:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "d9b2e3f5a6c7"
down_revision: Union[str, None] = "c8a1f4e2d5b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add blob_id column (nullable — hw firmware CVEs only)
    op.add_column(
        "sbom_vulnerabilities",
        sa.Column(
            "blob_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.create_foreign_key(
        "fk_sbom_vulns_blob_id",
        "sbom_vulnerabilities",
        "hardware_firmware_blobs",
        ["blob_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(
        "idx_sbom_vulns_blob",
        "sbom_vulnerabilities",
        ["blob_id"],
    )
    # Make component_id nullable so hw-firmware-only rows are legal
    op.alter_column(
        "sbom_vulnerabilities",
        "component_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=True,
    )
    # Ensure each row has at least one of component_id / blob_id
    op.create_check_constraint(
        "ck_sbom_vulns_component_or_blob",
        "sbom_vulnerabilities",
        "component_id IS NOT NULL OR blob_id IS NOT NULL",
    )
    # New columns: match_confidence and match_tier (help UI triage 3-tier noise)
    op.add_column(
        "sbom_vulnerabilities",
        sa.Column("match_confidence", sa.String(16), nullable=True),
        # values: high | medium | low
    )
    op.add_column(
        "sbom_vulnerabilities",
        sa.Column("match_tier", sa.String(32), nullable=True),
        # values: chipset_cpe | nvd_freetext | curated_yaml
    )


def downgrade() -> None:
    op.drop_column("sbom_vulnerabilities", "match_tier")
    op.drop_column("sbom_vulnerabilities", "match_confidence")
    op.drop_constraint(
        "ck_sbom_vulns_component_or_blob",
        "sbom_vulnerabilities",
        type_="check",
    )
    op.alter_column(
        "sbom_vulnerabilities",
        "component_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=False,
    )
    op.drop_index("idx_sbom_vulns_blob", table_name="sbom_vulnerabilities")
    op.drop_constraint(
        "fk_sbom_vulns_blob_id",
        "sbom_vulnerabilities",
        type_="foreignkey",
    )
    op.drop_column("sbom_vulnerabilities", "blob_id")
