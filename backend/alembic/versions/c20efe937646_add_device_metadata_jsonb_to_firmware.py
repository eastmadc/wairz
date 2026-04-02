"""add device_metadata JSONB to firmware

Revision ID: c20efe937646
Revises: c4d5e6f7a8b9
Create Date: 2026-04-02 18:18:35.163746

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'c20efe937646'
down_revision: Union[str, None] = 'c4d5e6f7a8b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('firmware', sa.Column('device_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    op.drop_column('firmware', 'device_metadata')
