"""add firmware_id to findings

Revision ID: 81f49fd099f5
Revises: a3b4c5d6e7f8
Create Date: 2026-04-03 05:48:28.364416

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "81f49fd099f5"
down_revision: Union[str, None] = "a3b4c5d6e7f8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("firmware_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        "fk_findings_firmware_id",
        "findings",
        "firmware",
        ["firmware_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_findings_firmware_id", "findings", ["firmware_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_firmware_id", table_name="findings")
    op.drop_constraint("fk_findings_firmware_id", "findings", type_="foreignkey")
    op.drop_column("findings", "firmware_id")
