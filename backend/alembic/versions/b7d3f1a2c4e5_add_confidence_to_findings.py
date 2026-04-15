"""add confidence to findings

Revision ID: b7d3f1a2c4e5
Revises: e0c33cf2204e
Create Date: 2026-04-14 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'b7d3f1a2c4e5'
down_revision: Union[str, None] = 'e0c33cf2204e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('findings', sa.Column('confidence', sa.String(20), nullable=True))


def downgrade() -> None:
    op.drop_column('findings', 'confidence')
