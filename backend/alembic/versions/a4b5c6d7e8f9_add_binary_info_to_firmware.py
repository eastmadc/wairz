"""add binary_info JSONB column to firmware

Revision ID: a4b5c6d7e8f9
Revises: 8da8627326d4
Create Date: 2026-04-04 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision: str = "a4b5c6d7e8f9"
down_revision: Union[str, None] = "8da8627326d4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column("binary_info", JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("firmware", "binary_info")
