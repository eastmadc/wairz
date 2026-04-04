"""add missing indexes to foreign keys and query columns

Revision ID: 8da8627326d4
Revises: 81f49fd099f5
Create Date: 2026-04-04 12:37:28.091531

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '8da8627326d4'
down_revision: Union[str, None] = '81f49fd099f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Foreign key indexes
    op.create_index('ix_firmware_project_id', 'firmware', ['project_id'])
    op.create_index('ix_emulation_sessions_firmware_id', 'emulation_sessions', ['firmware_id'])
    op.create_index('ix_findings_conversation_id', 'findings', ['conversation_id'])
    op.create_index('ix_findings_component_id', 'findings', ['component_id'])
    op.create_index('ix_sbom_vulnerabilities_component_id', 'sbom_vulnerabilities', ['component_id'])
    op.create_index('ix_sbom_vulnerabilities_firmware_id', 'sbom_vulnerabilities', ['firmware_id'])
    op.create_index('ix_sbom_vulnerabilities_finding_id', 'sbom_vulnerabilities', ['finding_id'])
    op.create_index('ix_analysis_cache_firmware_id', 'analysis_cache', ['firmware_id'])
    op.create_index('ix_review_agents_conversation_id', 'review_agents', ['conversation_id'])
    op.create_index('ix_fuzzing_campaigns_firmware_id', 'fuzzing_campaigns', ['firmware_id'])
    op.create_index('ix_fuzzing_crashes_finding_id', 'fuzzing_crashes', ['finding_id'])
    op.create_index('ix_conversations_project_id', 'conversations', ['project_id'])

    # Query column indexes
    op.create_index('ix_firmware_sha256', 'firmware', ['sha256'])
    op.create_index('ix_documents_sha256', 'documents', ['sha256'])
    op.create_index('ix_analysis_cache_binary_sha256', 'analysis_cache', ['binary_sha256'])


def downgrade() -> None:
    op.drop_index('ix_analysis_cache_binary_sha256', 'analysis_cache')
    op.drop_index('ix_documents_sha256', 'documents')
    op.drop_index('ix_firmware_sha256', 'firmware')
    op.drop_index('ix_conversations_project_id', 'conversations')
    op.drop_index('ix_fuzzing_crashes_finding_id', 'fuzzing_crashes')
    op.drop_index('ix_fuzzing_campaigns_firmware_id', 'fuzzing_campaigns')
    op.drop_index('ix_review_agents_conversation_id', 'review_agents')
    op.drop_index('ix_analysis_cache_firmware_id', 'analysis_cache')
    op.drop_index('ix_sbom_vulnerabilities_finding_id', 'sbom_vulnerabilities')
    op.drop_index('ix_sbom_vulnerabilities_firmware_id', 'sbom_vulnerabilities')
    op.drop_index('ix_sbom_vulnerabilities_component_id', 'sbom_vulnerabilities')
    op.drop_index('ix_findings_component_id', 'findings')
    op.drop_index('ix_findings_conversation_id', 'findings')
    op.drop_index('ix_emulation_sessions_firmware_id', 'emulation_sessions')
    op.drop_index('ix_firmware_project_id', 'firmware')
