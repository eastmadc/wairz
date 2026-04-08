"""add pcap_path to emulation_sessions

Revision ID: aeb9bcbc594a
Revises: b5c6d7e8f9a0
Create Date: 2026-04-07 18:47:43.754483

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'aeb9bcbc594a'
down_revision: Union[str, None] = 'b5c6d7e8f9a0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('emulation_sessions', sa.Column('pcap_path', sa.String(length=512), nullable=True))


def downgrade() -> None:
    op.drop_column('emulation_sessions', 'pcap_path')
