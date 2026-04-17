"""add hardware_firmware_blobs table

Revision ID: c8a1f4e2d5b6
Revises: b7d3f1a2c4e5
Create Date: 2026-04-17 01:35:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "c8a1f4e2d5b6"
down_revision: Union[str, None] = "b7d3f1a2c4e5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "hardware_firmware_blobs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("firmware_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("blob_path", sa.String(1024), nullable=False),
        sa.Column("partition", sa.String(64), nullable=True),
        sa.Column("blob_sha256", sa.String(64), nullable=False),
        sa.Column("file_size", sa.BigInteger(), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("vendor", sa.String(64), nullable=True),
        sa.Column("format", sa.String(32), nullable=False),
        sa.Column("version", sa.String(128), nullable=True),
        sa.Column(
            "signed",
            sa.String(16),
            server_default="unknown",
            nullable=False,
        ),
        sa.Column("signature_algorithm", sa.String(64), nullable=True),
        sa.Column("cert_subject", sa.Text(), nullable=True),
        sa.Column("chipset_target", sa.String(64), nullable=True),
        sa.Column("driver_references", postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column("sbom_component_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column("detection_source", sa.String(64), nullable=False),
        sa.Column(
            "detection_confidence",
            sa.String(16),
            server_default="medium",
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["firmware_id"], ["firmware.id"], ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["sbom_component_id"], ["sbom_components.id"], ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "firmware_id", "blob_sha256", name="uq_hwfw_firmware_sha256",
        ),
    )
    op.create_index(
        "ix_hwfw_firmware_category",
        "hardware_firmware_blobs",
        ["firmware_id", "category"],
    )
    op.create_index(
        "ix_hwfw_vendor",
        "hardware_firmware_blobs",
        ["vendor"],
    )
    op.create_index(
        "ix_hwfw_sha256",
        "hardware_firmware_blobs",
        ["blob_sha256"],
    )
    # Index on firmware_id for FK lookups (also covered by ix_hwfw_firmware_category
    # as leading column, but explicit for ORM index=True parity).
    op.create_index(
        "ix_hardware_firmware_blobs_firmware_id",
        "hardware_firmware_blobs",
        ["firmware_id"],
    )
    op.create_index(
        "ix_hardware_firmware_blobs_blob_sha256",
        "hardware_firmware_blobs",
        ["blob_sha256"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_hardware_firmware_blobs_blob_sha256",
        table_name="hardware_firmware_blobs",
    )
    op.drop_index(
        "ix_hardware_firmware_blobs_firmware_id",
        table_name="hardware_firmware_blobs",
    )
    op.drop_index("ix_hwfw_sha256", table_name="hardware_firmware_blobs")
    op.drop_index("ix_hwfw_vendor", table_name="hardware_firmware_blobs")
    op.drop_index(
        "ix_hwfw_firmware_category", table_name="hardware_firmware_blobs",
    )
    op.drop_table("hardware_firmware_blobs")
