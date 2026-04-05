"""add system emulation columns to emulation_sessions

Revision ID: b5c6d7e8f9a0
Revises: a4b5c6d7e8f9
Create Date: 2026-04-05 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision: str = "b5c6d7e8f9a0"
down_revision: Union[str, None] = "a4b5c6d7e8f9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "emulation_sessions",
        sa.Column("discovered_services", JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "emulation_sessions",
        sa.Column("system_emulation_stage", sa.String(length=50), nullable=True),
    )
    op.add_column(
        "emulation_sessions",
        sa.Column("kernel_used", sa.String(length=200), nullable=True),
    )
    op.add_column(
        "emulation_sessions",
        sa.Column("firmware_ip", sa.String(length=50), nullable=True),
    )
    op.add_column(
        "emulation_sessions",
        sa.Column("nvram_state", JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "emulation_sessions",
        sa.Column("idle_since", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("emulation_sessions", "idle_since")
    op.drop_column("emulation_sessions", "nvram_state")
    op.drop_column("emulation_sessions", "firmware_ip")
    op.drop_column("emulation_sessions", "kernel_used")
    op.drop_column("emulation_sessions", "system_emulation_stage")
    op.drop_column("emulation_sessions", "discovered_services")
