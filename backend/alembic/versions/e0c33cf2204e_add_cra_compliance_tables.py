"""add CRA compliance tables

Revision ID: e0c33cf2204e
Revises: 49211e346ae0
Create Date: 2026-04-09 01:15:20.381708

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'e0c33cf2204e'
down_revision: Union[str, None] = '49211e346ae0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'cra_assessments',
        sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('project_id', sa.Uuid(), nullable=False),
        sa.Column('firmware_id', sa.Uuid(), nullable=True),
        sa.Column('assessor_name', sa.String(length=255), nullable=True),
        sa.Column('product_name', sa.String(length=255), nullable=True),
        sa.Column('product_version', sa.String(length=100), nullable=True),
        sa.Column('overall_status', sa.String(length=20), server_default='in_progress', nullable=False),
        sa.Column('auto_pass_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('auto_fail_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('manual_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('not_tested_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['firmware_id'], ['firmware.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_cra_assessments_project_id'), 'cra_assessments', ['project_id'], unique=False)
    op.create_index(op.f('ix_cra_assessments_firmware_id'), 'cra_assessments', ['firmware_id'], unique=False)

    op.create_table(
        'cra_requirement_results',
        sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('assessment_id', sa.Uuid(), nullable=False),
        sa.Column('requirement_id', sa.String(length=50), nullable=False),
        sa.Column('requirement_title', sa.String(length=255), nullable=False),
        sa.Column('annex_part', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=20), server_default='not_tested', nullable=False),
        sa.Column('auto_populated', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('evidence_summary', sa.Text(), nullable=True),
        sa.Column('finding_ids', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('tool_sources', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('manual_notes', sa.Text(), nullable=True),
        sa.Column('manual_evidence', sa.Text(), nullable=True),
        sa.Column('related_cwes', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('related_cves', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('assessed_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['assessment_id'], ['cra_assessments.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_cra_requirement_results_assessment_id'), 'cra_requirement_results', ['assessment_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_cra_requirement_results_assessment_id'), table_name='cra_requirement_results')
    op.drop_table('cra_requirement_results')
    op.drop_index(op.f('ix_cra_assessments_firmware_id'), table_name='cra_assessments')
    op.drop_index(op.f('ix_cra_assessments_project_id'), table_name='cra_assessments')
    op.drop_table('cra_assessments')
