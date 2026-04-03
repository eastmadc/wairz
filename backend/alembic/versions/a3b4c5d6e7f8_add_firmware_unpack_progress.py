"""add firmware unpack progress fields

Revision ID: a3b4c5d6e7f8
Revises: c20efe937646
Create Date: 2026-04-03

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'a3b4c5d6e7f8'
down_revision: Union[str, None] = 'c20efe937646'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('firmware', sa.Column('unpack_stage', sa.String(100), nullable=True))
    op.add_column('firmware', sa.Column('unpack_progress', sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column('firmware', 'unpack_progress')
    op.drop_column('firmware', 'unpack_stage')
