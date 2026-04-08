"""add attack_surface_entries table

Revision ID: 49211e346ae0
Revises: aeb9bcbc594a
Create Date: 2026-04-08 16:53:53.125720

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '49211e346ae0'
down_revision: Union[str, None] = 'aeb9bcbc594a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('attack_surface_entries',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('project_id', sa.Uuid(), nullable=False),
    sa.Column('firmware_id', sa.Uuid(), nullable=False),
    sa.Column('binary_path', sa.Text(), nullable=False),
    sa.Column('binary_name', sa.Text(), nullable=False),
    sa.Column('architecture', sa.Text(), nullable=True),
    sa.Column('file_size', sa.Integer(), nullable=True),
    sa.Column('attack_surface_score', sa.Integer(), server_default='0', nullable=False),
    sa.Column('score_breakdown', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
    sa.Column('is_setuid', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('is_network_listener', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('is_cgi_handler', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('has_dangerous_imports', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('dangerous_imports', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=True),
    sa.Column('input_categories', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=True),
    sa.Column('auto_findings_generated', sa.Boolean(), server_default='false', nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['firmware_id'], ['firmware.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_attack_surface_project_firmware_score', 'attack_surface_entries', ['project_id', 'firmware_id', sa.text('attack_surface_score DESC')], unique=False)


def downgrade() -> None:
    op.drop_index('ix_attack_surface_project_firmware_score', table_name='attack_surface_entries')
    op.drop_table('attack_surface_entries')
