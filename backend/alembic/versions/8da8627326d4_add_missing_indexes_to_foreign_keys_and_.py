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
    op.create_index('ix_firmware_project_id', 'firmware', ['project_id'], if_not_exists=True)
    op.create_index('ix_emulation_sessions_firmware_id', 'emulation_sessions', ['firmware_id'], if_not_exists=True)
    op.create_index('ix_findings_conversation_id', 'findings', ['conversation_id'], if_not_exists=True)
    op.create_index('ix_findings_component_id', 'findings', ['component_id'], if_not_exists=True)
    op.create_index('ix_sbom_vulnerabilities_component_id', 'sbom_vulnerabilities', ['component_id'], if_not_exists=True)
    op.create_index('ix_sbom_vulnerabilities_firmware_id', 'sbom_vulnerabilities', ['firmware_id'], if_not_exists=True)
    op.create_index('ix_sbom_vulnerabilities_finding_id', 'sbom_vulnerabilities', ['finding_id'], if_not_exists=True)
    op.create_index('ix_analysis_cache_firmware_id', 'analysis_cache', ['firmware_id'], if_not_exists=True)
    op.create_index('ix_review_agents_conversation_id', 'review_agents', ['conversation_id'], if_not_exists=True)
    op.create_index('ix_fuzzing_campaigns_firmware_id', 'fuzzing_campaigns', ['firmware_id'], if_not_exists=True)
    op.create_index('ix_fuzzing_crashes_finding_id', 'fuzzing_crashes', ['finding_id'], if_not_exists=True)
    op.create_index('ix_conversations_project_id', 'conversations', ['project_id'], if_not_exists=True)

    # Query column indexes
    op.create_index('ix_firmware_sha256', 'firmware', ['sha256'], if_not_exists=True)
    op.create_index('ix_documents_sha256', 'documents', ['sha256'], if_not_exists=True)
    op.create_index('ix_analysis_cache_binary_sha256', 'analysis_cache', ['binary_sha256'], if_not_exists=True)


def downgrade() -> None:
    op.drop_index('ix_analysis_cache_binary_sha256', 'analysis_cache', if_exists=True)
    op.drop_index('ix_documents_sha256', 'documents', if_exists=True)
    op.drop_index('ix_firmware_sha256', 'firmware', if_exists=True)
    op.drop_index('ix_conversations_project_id', 'conversations', if_exists=True)
    op.drop_index('ix_fuzzing_crashes_finding_id', 'fuzzing_crashes', if_exists=True)
    op.drop_index('ix_fuzzing_campaigns_firmware_id', 'fuzzing_campaigns', if_exists=True)
    op.drop_index('ix_review_agents_conversation_id', 'review_agents', if_exists=True)
    op.drop_index('ix_analysis_cache_firmware_id', 'analysis_cache', if_exists=True)
    op.drop_index('ix_sbom_vulnerabilities_finding_id', 'sbom_vulnerabilities', if_exists=True)
    op.drop_index('ix_sbom_vulnerabilities_firmware_id', 'sbom_vulnerabilities', if_exists=True)
    op.drop_index('ix_sbom_vulnerabilities_component_id', 'sbom_vulnerabilities', if_exists=True)
    op.drop_index('ix_findings_component_id', 'findings', if_exists=True)
    op.drop_index('ix_findings_conversation_id', 'findings', if_exists=True)
    op.drop_index('ix_emulation_sessions_firmware_id', 'emulation_sessions', if_exists=True)
    op.drop_index('ix_firmware_project_id', 'firmware', if_exists=True)
